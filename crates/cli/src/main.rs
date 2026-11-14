//! `rollcall`: from a folder of stolen files to a list of the people affected.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rollcall_case::{
    Case, HashingWriter, IngestOptions, ResolveSummary, StoredPerson, Values, export_people_csv,
    export_records_csv, ingest, mask, summarise, summarise_person,
};
use rollcall_model::ElementKind;
use rollcall_model::date::{civil_from_days, today};

#[derive(Parser)]
#[command(
    name = "rollcall",
    version,
    about = "Breach-response data mining: who was affected, and which of their data was exposed.",
    long_about = "Reads a folder of exfiltrated files into a case and produces a notification \
                  list. Everything runs locally. Use only on data you are authorized to inspect."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read an evidence folder into a case. Safe to repeat: unchanged files are not read again
    Ingest {
        /// Folder holding the exfiltrated files
        evidence: PathBuf,
        /// Case file to create or update; keep it outside the evidence folder
        #[arg(long)]
        case: PathBuf,
        /// Files larger than this many MiB are hashed and reported, but not read
        #[arg(long, default_value_t = 512, value_parser = clap::value_parser!(u64).range(1..=4096))]
        max_file_mib: u64,
    },
    /// List the affected people, with sensitive identifiers masked
    People {
        #[arg(long)]
        case: PathBuf,
        /// Most rows to print
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one person: what is exposed, where it was found, and why records were merged
    Person {
        /// Person identifier, as shown by `people`
        id: i64,
        #[arg(long)]
        case: PathBuf,
    },
    /// List evidence that was not, or not fully, turned into person records
    Gaps {
        #[arg(long)]
        case: PathBuf,
    },
    /// Count the people in a case by what was exposed, where they live and how to reach them
    Summary {
        #[arg(long)]
        case: PathBuf,
    },
    /// Answer the questions the tool could not settle: are these two records one person?
    Review {
        #[command(subcommand)]
        action: Review,
    },
    /// Show the case history, or check that it has not been altered
    Audit {
        #[arg(long)]
        case: PathBuf,
        /// Re-compute the hash chain instead of listing entries
        #[arg(long)]
        verify: bool,
    },
    /// Write the notification list as CSV
    Export {
        #[arg(long)]
        case: PathBuf,
        /// File to create; an existing file is never overwritten
        #[arg(long)]
        out: PathBuf,
        /// One row per person, or one row per source record (the evidence behind the list)
        #[arg(long, value_enum, default_value_t = Level::People)]
        level: Level,
        /// Whether sensitive identifiers are masked to their last four characters
        #[arg(long, value_enum, default_value_t = ValueMode::Masked)]
        values: ValueMode,
    },
}

#[derive(Subcommand)]
enum Review {
    /// List open questions, most likely matches first
    List {
        #[arg(long)]
        case: PathBuf,
        /// Most questions to print
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Rule that the two records of a suggestion are the same person
    Accept {
        /// Suggestion number, as shown by `review list`
        suggestion: i64,
        #[command(flatten)]
        ruling: Ruling,
    },
    /// Rule that the two records of a suggestion are different people
    Reject {
        /// Suggestion number, as shown by `review list`
        suggestion: i64,
        #[command(flatten)]
        ruling: Ruling,
    },
    /// Rule that any two records are the same person
    Merge {
        record_a: i64,
        record_b: i64,
        #[command(flatten)]
        ruling: Ruling,
    },
    /// Rule that two records are different people, separating them if they were merged
    Split {
        record_a: i64,
        record_b: i64,
        #[command(flatten)]
        ruling: Ruling,
    },
    /// List the rulings made so far
    Rulings {
        #[arg(long)]
        case: PathBuf,
    },
    /// Withdraw a ruling
    Undo {
        /// Ruling number, as shown by `review rulings`
        ruling_id: i64,
        #[command(flatten)]
        ruling: Ruling,
    },
}

#[derive(Args)]
struct Ruling {
    #[arg(long)]
    case: PathBuf,
    /// Who is making the ruling; defaults to the logged-in user name
    #[arg(long)]
    reviewer: Option<String>,
    /// Why, for the audit log
    #[arg(long, default_value = "")]
    note: String,
}

impl Ruling {
    fn reviewer(&self) -> String {
        self.reviewer
            .clone()
            .or_else(|| std::env::var("USER").ok())
            .or_else(|| std::env::var("USERNAME").ok())
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_owned())
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ValueMode {
    Masked,
    Full,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Level {
    People,
    Records,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(text) => {
            // A closed pipe (`rollcall people | head`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(printable(&text).as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {}", printable(&format!("{error:#}")));
            ExitCode::FAILURE
        }
    }
}

/// Text for a terminal. Values found in evidence can hold control characters that would
/// move the cursor, recolour the screen or hide what came before; every one except the
/// line breaks this program writes is shown as a visible escape instead.
fn printable(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() && character != '\n' {
            shown.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
        } else {
            shown.push(character);
        }
    }
    shown
}

fn run(command: Command) -> Result<String> {
    match command {
        Command::Ingest {
            evidence,
            case,
            max_file_mib,
        } => ingest_command(&evidence, &case, max_file_mib),
        Command::People { case, limit } => people_command(&case, limit),
        Command::Person { id, case } => person_command(&case, id),
        Command::Gaps { case } => gaps_command(&case),
        Command::Summary { case } => summary_command(&case),
        Command::Review { action } => review_command(action),
        Command::Audit { case, verify } => audit_command(&case, verify),
        Command::Export {
            case,
            out,
            level,
            values,
        } => {
            let values = match values {
                ValueMode::Masked => Values::Masked,
                ValueMode::Full => Values::Full,
            };
            export_command(&case, &out, level, values)
        }
    }
}

/// `2026-11-13 14:05:09 UTC` for a count of seconds since 1970.
fn timestamp(seconds: i64) -> String {
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let time = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        time / 3_600,
        time / 60 % 60,
        time % 60
    )
}

fn ingest_command(evidence: &Path, case_path: &Path, max_file_mib: u64) -> Result<String> {
    let mut case = Case::create_or_open(case_path)?;
    let options = IngestOptions {
        max_file_bytes: max_file_mib * 1024 * 1024,
        ..IngestOptions::default()
    };
    let summary = ingest(&mut case, evidence, &options)?;
    let mut text = String::new();
    writeln!(text, "Files found:      {}", summary.discovered)?;
    writeln!(text, "  read this run:  {}", summary.read)?;
    writeln!(text, "  unchanged:      {}", summary.reused)?;
    writeln!(text, "  not read:       {}", summary.not_read)?;
    if summary.missing > 0 {
        writeln!(text, "Files no longer in the folder: {}", summary.missing)?;
    }
    writeln!(
        text,
        "Source records:   {} ({} new)",
        summary.total_records, summary.new_records
    )?;
    writeln!(text, "People:           {}", summary.persons)?;
    writeln!(text, "Open questions:   {}", summary.suggestions)?;
    writeln!(text, "Coverage gaps:    {}", summary.total_gaps)?;
    let case_shown = case_path.display();
    if summary.suggestions > 0 {
        writeln!(
            text,
            "\nSome records may belong to the same person. Settle them with:\n  rollcall review list --case {case_shown}"
        )?;
    }
    if summary.total_gaps > 0 {
        writeln!(
            text,
            "\nSome evidence did not become person records. Review it with:\n  rollcall gaps --case {case_shown}"
        )?;
    }
    Ok(text)
}

fn table(text: &mut String, rows: &[Vec<String>]) -> Result<()> {
    let columns = rows.first().map_or(0, Vec::len);
    let widths: Vec<usize> = (0..columns.saturating_sub(1))
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
                .min(44)
        })
        .collect();
    for row in rows {
        for (cell, width) in row.iter().zip(&widths) {
            let shown: String = cell.chars().take(*width).collect();
            write!(text, "{shown:<width$}  ")?;
        }
        writeln!(text, "{}", row.last().map_or("", String::as_str))?;
    }
    Ok(())
}

fn kinds(kinds: &[ElementKind]) -> String {
    kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn people_command(case_path: &Path, limit: usize) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let questioned: std::collections::HashSet<i64> = case
        .suggestions()?
        .into_iter()
        .flat_map(|suggestion| [suggestion.person_a, suggestion.person_b])
        .collect();
    let header = ["ID", "NAME", "RECORDS", "EXPOSED"];
    let mut rows = vec![
        header
            .iter()
            .map(|cell| (*cell).to_owned())
            .collect::<Vec<_>>(),
    ];
    let mut total = 0_usize;
    case.for_each_person(|person| {
        total += 1;
        if total > limit {
            return Ok(());
        }
        let summary = summarise_person(&person.records);
        let mut name = if summary.name().is_empty() {
            "(no name)".to_owned()
        } else {
            summary.name().to_owned()
        };
        if questioned.contains(&person.id) {
            name.push_str(" (?)");
        }
        if !summary.needs_review.is_empty() {
            name.push_str(" (!)");
        }
        rows.push(vec![
            person.id.to_string(),
            name,
            person.records.len().to_string(),
            kinds(&summary.exposed()),
        ]);
        Ok(())
    })?;

    let mut text = String::new();
    table(&mut text, &rows)?;
    writeln!(text, "\n{total} people; showing {}.", total.min(limit))?;
    writeln!(
        text,
        "(?) may be the same person as another entry: see `rollcall review list`."
    )?;
    writeln!(
        text,
        "(!) has a value that failed validation: see `rollcall person <ID>`."
    )?;
    Ok(text)
}

fn describe_person(text: &mut String, person: &StoredPerson, indent: &str) -> Result<()> {
    let summary = summarise_person(&person.records);
    for (kind, values) in &summary.values {
        let shown: Vec<String> = values
            .iter()
            .map(|value| mask(*kind, value, Values::Masked))
            .collect();
        writeln!(text, "{indent}{:<22} {}", kind.as_str(), shown.join(" | "))?;
    }
    if !summary.needs_review.is_empty() {
        writeln!(
            text,
            "{indent}failed validation:     {}",
            kinds(&summary.needs_review)
        )?;
    }
    Ok(())
}

fn person_command(case_path: &Path, id: i64) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let person = case
        .person(id)?
        .with_context(|| format!("there is no person {id}; list them with `rollcall people`"))?;
    let mut text = String::new();
    writeln!(text, "Person {id}")?;
    describe_person(&mut text, &person, "  ")?;

    writeln!(text, "\nSource records ({}):", person.records.len())?;
    for record in &person.records {
        let relation = record
            .relation
            .as_deref()
            .map(|relation| format!(" as {relation}"))
            .unwrap_or_default();
        writeln!(
            text,
            "  record {:<6} {}{relation}: {}",
            record.id,
            record.source(),
            kinds(&summarise(record).exposed())
        )?;
    }
    let links = case.links_of(id)?;
    if !links.is_empty() {
        writeln!(text, "\nWhy these records are one person:")?;
        for link in links {
            writeln!(
                text,
                "  records {} and {}: {}",
                link.record_a, link.record_b, link.reason
            )?;
        }
    }
    let open: Vec<_> = case
        .suggestions()?
        .into_iter()
        .filter(|suggestion| suggestion.person_a == id || suggestion.person_b == id)
        .collect();
    if !open.is_empty() {
        writeln!(text, "\nOpen questions:")?;
        for suggestion in open {
            let other = if suggestion.person_a == id {
                suggestion.person_b
            } else {
                suggestion.person_a
            };
            writeln!(
                text,
                "  #{}: may be the same as person {other}. {} (score {})",
                suggestion.id, suggestion.reason, suggestion.score
            )?;
        }
    }
    Ok(text)
}

fn gaps_command(case_path: &Path) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let gaps = case.gaps()?;
    let mut text = String::new();
    for gap in &gaps {
        let sheet = gap
            .scope
            .as_deref()
            .map(|scope| format!(" [{scope}]"))
            .unwrap_or_default();
        writeln!(
            text,
            "{:<12} {}{sheet}\n             {}",
            gap.kind.as_str(),
            gap.path,
            gap.detail
        )?;
    }
    if gaps.is_empty() {
        writeln!(
            text,
            "No coverage gaps: every file found was read into person records."
        )?;
    } else {
        writeln!(
            text,
            "\nCoverage gaps: {}. Each one is evidence that still needs a person to look at it.",
            gaps.len()
        )?;
    }
    Ok(text)
}

fn summary_command(case_path: &Path) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let (year, month, day) = today();
    let summary = case.summary((year, month, day))?;
    let mut text = String::new();
    writeln!(text, "People:           {}", summary.people)?;
    writeln!(
        text,
        "Source records:   {} in {} files",
        summary.source_records, summary.files
    )?;
    if summary.open_questions > 0 {
        writeln!(
            text,
            "Open questions:   {}  (until they are settled, some people are counted more than once)",
            summary.open_questions
        )?;
    }
    if summary.coverage_gaps > 0 {
        writeln!(
            text,
            "Coverage gaps:    {}  (the counts below cover only the evidence that was read)",
            summary.coverage_gaps
        )?;
    }

    writeln!(text, "\nPeople by kind of data exposed")?;
    for (category, people) in &summary.by_category {
        writeln!(text, "  {:<48} {people:>8}", category.label())?;
    }
    writeln!(
        text,
        "  {:<48} {:>8}",
        "Nothing beyond a name and contact details", summary.contact_only
    )?;

    writeln!(text, "\nPeople by element exposed")?;
    for (kind, people) in &summary.by_element {
        writeln!(text, "  {:<48} {people:>8}", kind.as_str())?;
    }

    writeln!(
        text,
        "\nPeople by state or province (someone with addresses in two is counted in both)"
    )?;
    for (region, people) in &summary.by_region {
        writeln!(text, "  {region:<48} {people:>8}")?;
    }
    writeln!(text, "  {:<48} {:>8}", "(none on file)", summary.no_region)?;

    writeln!(text, "\nHow people can be reached")?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        "Postal address on file", summary.reach.by_post
    )?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        "Email address only", summary.reach.by_email_only
    )?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        "Phone number only", summary.reach.by_phone_only
    )?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        "No contact details", summary.reach.no_contact
    )?;

    writeln!(text, "\nOther")?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        format!("Under 18 on {year:04}-{month:02}-{day:02}"),
        summary.minors
    )?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        "No date of birth on file", summary.no_birth_date
    )?;
    writeln!(text, "  {:<48} {:>8}", "No name on file", summary.unnamed)?;
    writeln!(
        text,
        "  {:<48} {:>8}",
        "With a value that failed validation", summary.needs_review
    )?;
    writeln!(
        text,
        "\nThese are counts of what was found. Who must be notified is a legal judgement."
    )?;
    Ok(text)
}

fn after_ruling(summary: ResolveSummary, what: &str) -> String {
    format!(
        "{what}\nThe case now has {} people and {} open questions.\n",
        summary.persons, summary.suggestions
    )
}

fn review_command(action: Review) -> Result<String> {
    match action {
        Review::List { case, limit } => review_list(&case, limit),
        Review::Accept { suggestion, ruling } => {
            let mut case = Case::open_existing(&ruling.case)?;
            let summary =
                case.decide_suggestion(suggestion, true, &ruling.reviewer(), &ruling.note)?;
            Ok(after_ruling(summary, "Recorded: the same person."))
        }
        Review::Reject { suggestion, ruling } => {
            let mut case = Case::open_existing(&ruling.case)?;
            let summary =
                case.decide_suggestion(suggestion, false, &ruling.reviewer(), &ruling.note)?;
            Ok(after_ruling(summary, "Recorded: different people."))
        }
        Review::Merge {
            record_a,
            record_b,
            ruling,
        } => {
            let mut case = Case::open_existing(&ruling.case)?;
            let summary =
                case.decide(record_a, record_b, true, &ruling.reviewer(), &ruling.note)?;
            Ok(after_ruling(summary, "Recorded: the same person."))
        }
        Review::Split {
            record_a,
            record_b,
            ruling,
        } => {
            let mut case = Case::open_existing(&ruling.case)?;
            let summary =
                case.decide(record_a, record_b, false, &ruling.reviewer(), &ruling.note)?;
            Ok(after_ruling(summary, "Recorded: different people."))
        }
        Review::Rulings { case } => {
            let case = Case::open_existing(&case)?;
            let rulings = case.decisions()?;
            let mut text = String::new();
            for ruling in &rulings {
                let records = ruling.records.map_or_else(
                    || "records no longer in the case (inactive)".to_owned(),
                    |(a, b)| format!("records {a} and {b}"),
                );
                let verdict = if ruling.same {
                    "same person"
                } else {
                    "different people"
                };
                let note = if ruling.note.is_empty() {
                    String::new()
                } else {
                    format!(" Note: {}", ruling.note)
                };
                writeln!(
                    text,
                    "#{:<4} {}  {records}: {verdict}, by {}.{note}",
                    ruling.id,
                    timestamp(ruling.decided_at),
                    ruling.reviewer
                )?;
            }
            writeln!(text, "{} rulings.", rulings.len())?;
            Ok(text)
        }
        Review::Undo { ruling_id, ruling } => {
            let mut case = Case::open_existing(&ruling.case)?;
            let summary = case.undo_decision(ruling_id, &ruling.reviewer())?;
            Ok(after_ruling(summary, "Ruling withdrawn."))
        }
    }
}

fn review_list(case_path: &Path, limit: usize) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let suggestions = case.suggestions()?;
    let mut text = String::new();
    for suggestion in suggestions.iter().take(limit) {
        writeln!(
            text,
            "#{}  score {}  {}",
            suggestion.id, suggestion.score, suggestion.reason
        )?;
        for (person, record) in [
            (suggestion.person_a, suggestion.record_a),
            (suggestion.person_b, suggestion.record_b),
        ] {
            if let Some(found) = case.person(person)? {
                let source = found
                    .records
                    .iter()
                    .find(|candidate| candidate.id == record)
                    .map(|candidate| candidate.source())
                    .unwrap_or_default();
                writeln!(text, "  person {person} (record {record}, {source})")?;
                describe_person(&mut text, &found, "      ")?;
            }
        }
        writeln!(text)?;
    }
    writeln!(
        text,
        "{} open questions; showing {}.",
        suggestions.len(),
        suggestions.len().min(limit)
    )?;
    if !suggestions.is_empty() {
        writeln!(
            text,
            "Answer with `rollcall review accept <#>` (same person) or `rollcall review reject <#>`."
        )?;
    }
    Ok(text)
}

fn audit_command(case_path: &Path, verify: bool) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let mut text = String::new();
    if !verify {
        for entry in case.audit_log()? {
            writeln!(
                text,
                "{:<4} {}  {:<13} {}",
                entry.id,
                timestamp(entry.at),
                entry.kind,
                entry.detail
            )?;
        }
    }
    let check = case.verify_audit()?;
    if let Some(entry) = check.broken_at {
        bail!(
            "the audit log has been altered: entry {entry} does not follow from the entry before it \
             ({} entries in all)",
            check.entries
        );
    }
    writeln!(
        text,
        "Audit log intact: {} entries. Head hash: {}",
        check.entries, check.head
    )?;
    writeln!(
        text,
        "An intact chain shows no entry was changed or removed from the middle. Record the head hash \
         outside the case to detect later removal from the end."
    )?;
    Ok(text)
}

fn export_command(case_path: &Path, out: &Path, level: Level, values: Values) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The list holds personal data: readable by its owner only.
        options.mode(0o600);
    }
    let file = options.open(out).with_context(|| {
        format!(
            "could not create {} (existing files are not overwritten)",
            out.display()
        )
    })?;
    let mut writer = HashingWriter::new(BufWriter::new(file));
    let (rows, unit) = match level {
        Level::People => (export_people_csv(&case, &mut writer, values)?, "people"),
        Level::Records => (
            export_records_csv(&case, &mut writer, values)?,
            "source records",
        ),
    };
    let hash = writer.finish()?;
    let counts = case.counts()?;
    let shown = if values == Values::Full {
        "full"
    } else {
        "masked"
    };
    case.record_export(&format!(
        "List of {rows} {unit} written with {shown} identifiers, while {} questions and {} coverage \
         gaps were open. SHA-256 of the file: {hash}.",
        counts.suggestions, counts.gaps
    ))?;

    let mut text = format!(
        "Wrote {rows} {unit} to {}.\nSHA-256: {hash}\n",
        out.display()
    );
    if values == Values::Full {
        text.push_str("Identifiers are written in full: store and share this file accordingly.\n");
    }
    if counts.suggestions > 0 {
        writeln!(
            text,
            "Open questions: {}. Some people may be listed more than once until they are settled.",
            counts.suggestions
        )?;
    }
    if counts.gaps > 0 {
        writeln!(
            text,
            "Coverage gaps: {}. The list is not complete until they are reviewed.",
            counts.gaps
        )?;
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_output_cannot_carry_control_sequences() {
        assert_eq!(
            printable("ID  NAME\n1   Jane Doe\n"),
            "ID  NAME\n1   Jane Doe\n"
        );
        assert_eq!(
            printable("Jane\u{1b}[2J\u{1b}[HDoe\r\u{7}"),
            "Jane\\u{1b}[2J\\u{1b}[HDoe\\u{d}\\u{7}"
        );
        assert_eq!(printable("tab\there \u{9b}31m"), "tab\\u{9}here \\u{9b}31m");
    }

    #[test]
    fn timestamps_are_written_in_utc() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(timestamp(1_794_632_709), "2026-11-14 05:05:09 UTC");
    }
}
