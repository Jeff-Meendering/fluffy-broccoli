//! Parsing personal names and judging whether two names could be the same person's.

use crate::nicknames;
use crate::text::{fold, jaro_winkler};

/// A personal name split into folded parts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PersonName {
    pub first: String,
    pub middle: Vec<String>,
    /// Empty when the name is a single word.
    pub last: String,
    /// Generational suffix in canonical form: `jr`, `sr`, `ii`, `iii` or `iv`.
    pub suffix: Option<&'static str>,
}

/// How closely two names agree, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameMatch {
    /// Same first and last name; middle names agree or are absent.
    Exact,
    /// Same last name; first names are forms of one name (`Bob`, `Robert`).
    Equivalent,
    /// Same last name; one first name is only an initial that fits the other.
    Initial,
    /// Close but not the same: a likely typing error, swapped order, a second middle
    /// name, or a double surname that contains the other surname.
    Similar,
    /// Same first name, different last name: possibly a name change.
    GivenOnly,
    Different,
    /// At least one side has no name at all.
    Missing,
}

const HONORIFICS: [&str; 9] = ["mr", "mrs", "ms", "miss", "dr", "prof", "mx", "sir", "rev"];
const CREDENTIALS: [&str; 9] = ["md", "phd", "esq", "cpa", "rn", "dds", "jd", "dvm", "mba"];
/// Words that belong to the surname that follows them: `de la Cruz`, `van der Berg`.
const PARTICLES: [&str; 19] = [
    "de", "del", "della", "la", "las", "los", "le", "van", "von", "der", "den", "ter", "da", "di",
    "dos", "das", "du", "bin", "st",
];

fn suffix_of(word: &str) -> Option<&'static str> {
    Some(match word {
        "jr" | "junior" => "jr",
        "sr" | "senior" => "sr",
        "ii" | "2nd" => "ii",
        "iii" | "3rd" => "iii",
        "iv" | "4th" => "iv",
        _ => return None,
    })
}

impl PersonName {
    /// Parses a name written given-name first, as the detector normalises names.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let folded = fold(text);
        let mut words: Vec<&str> = folded.split(' ').filter(|word| !word.is_empty()).collect();
        while words.len() > 1 && HONORIFICS.contains(&words[0]) {
            words.remove(0);
        }
        let mut suffix = None;
        while words.len() > 1 {
            let last = words[words.len() - 1];
            if CREDENTIALS.contains(&last) {
                words.pop();
            } else if let Some(found) = suffix_of(last) {
                suffix = Some(found);
                words.pop();
            } else {
                break;
            }
        }
        let (&first, rest) = words.split_first()?;
        if rest.is_empty() {
            return Some(Self {
                first: first.to_owned(),
                middle: Vec::new(),
                last: String::new(),
                suffix,
            });
        }
        // The surname is the last word plus any particles directly before it.
        let mut start = rest.len() - 1;
        while start > 0 && PARTICLES.contains(&rest[start - 1]) {
            start -= 1;
        }
        Some(Self {
            first: first.to_owned(),
            middle: rest[..start]
                .iter()
                .map(|word| (*word).to_owned())
                .collect(),
            last: rest[start..].concat(),
            suffix,
        })
    }

    /// First and last name with the first name in its formal form, for grouping names
    /// that may be the same person's.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{} {}", nicknames::formal(&self.first), self.last)
    }
}

enum Given {
    Equal,
    Nickname,
    Initial,
    Close,
    Different,
}

fn compare_given(left: &str, right: &str) -> Given {
    let is_initial = |name: &str| name.chars().count() == 1;
    if is_initial(left) || is_initial(right) {
        return if left.chars().next() == right.chars().next() {
            Given::Initial
        } else {
            Given::Different
        };
    }
    if left == right {
        Given::Equal
    } else if nicknames::equivalent(left, right) {
        Given::Nickname
    } else if left.len() >= 4 && right.len() >= 4 && jaro_winkler(left, right) >= 0.92 {
        Given::Close
    } else {
        Given::Different
    }
}

fn middles_agree(left: &PersonName, right: &PersonName) -> bool {
    match (left.middle.first(), right.middle.first()) {
        (Some(left), Some(right)) => !matches!(compare_given(left, right), Given::Different),
        _ => true,
    }
}

/// Judges two parsed names. Suffixes are not considered here; a clash between `Jr` and
/// `Sr` is treated as a conflict by the resolver.
#[must_use]
pub fn compare(left: &PersonName, right: &PersonName) -> NameMatch {
    if left.last.is_empty() || right.last.is_empty() {
        let same_single =
            left.last.is_empty() && right.last.is_empty() && left.first == right.first;
        return if same_single {
            NameMatch::Similar
        } else {
            NameMatch::Different
        };
    }
    let given = compare_given(&left.first, &right.first);
    if left.last == right.last {
        return match given {
            Given::Equal if middles_agree(left, right) => NameMatch::Exact,
            Given::Equal | Given::Close => NameMatch::Similar,
            Given::Nickname => NameMatch::Equivalent,
            Given::Initial => NameMatch::Initial,
            Given::Different => NameMatch::Different,
        };
    }
    if left.first == right.last && left.last == right.first {
        return NameMatch::Similar;
    }
    if matches!(given, Given::Equal | Given::Nickname) {
        let surname_typo = left.last.len() >= 5
            && right.last.len() >= 5
            && jaro_winkler(&left.last, &right.last) >= 0.92;
        // "Mary Smith Jones" beside "Mary Smith" or "Mary Jones".
        let double_surname = left
            .middle
            .last()
            .is_some_and(|middle| *middle == right.last)
            || right
                .middle
                .last()
                .is_some_and(|middle| *middle == left.last);
        return if surname_typo || double_surname {
            NameMatch::Similar
        } else {
            NameMatch::GivenOnly
        };
    }
    NameMatch::Different
}

/// The strongest match between any name on one side and any on the other.
#[must_use]
pub fn best_match(left: &[PersonName], right: &[PersonName]) -> NameMatch {
    left.iter()
        .flat_map(|left| right.iter().map(move |right| compare(left, right)))
        .min()
        .unwrap_or(NameMatch::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> PersonName {
        PersonName::parse(text).unwrap()
    }

    fn judge(left: &str, right: &str) -> NameMatch {
        let forward = compare(&name(left), &name(right));
        assert_eq!(
            forward,
            compare(&name(right), &name(left)),
            "{left} / {right}"
        );
        forward
    }

    #[test]
    fn parses_titles_particles_suffixes_and_credentials() {
        let parsed = name("Dr. María de la Cruz-López Jr., MD");
        assert_eq!(parsed.first, "maria");
        assert_eq!(parsed.middle, ["de", "la", "cruz"]);
        assert_eq!((parsed.last.as_str(), parsed.suffix), ("lopez", Some("jr")));

        let dutch = name("Jan van der Berg");
        assert_eq!(
            (dutch.first.as_str(), dutch.last.as_str()),
            ("jan", "vanderberg")
        );
        assert!(dutch.middle.is_empty());

        let single = name("Madonna");
        assert_eq!(
            (single.first.as_str(), single.last.as_str()),
            ("madonna", "")
        );
        assert_eq!(name("John Q Public III").suffix, Some("iii"));
        assert_eq!(PersonName::parse(" - "), None);
    }

    #[test]
    fn grades_name_agreement() {
        use NameMatch::{Different, Equivalent, Exact, GivenOnly, Initial, Similar};
        let expected = [
            ("Jane Doe", "JANE  DOE", Exact),
            ("Jane Q Doe", "Jane Doe", Exact),
            ("Jane Q Doe", "Jane Quinn Doe", Exact),
            ("José Núñez", "Jose Nunez", Exact),
            ("Jane Ann Doe", "Jane Beth Doe", Similar),
            ("Bob Smith", "Robert Smith", Equivalent),
            ("Liz O'Hara", "Elizabeth OHara", Equivalent),
            ("J Smith", "John Smith", Initial),
            ("J. Smith", "J Smith", Initial),
            ("Jonh Smith", "John Smith", Similar),
            ("Smith John", "John Smith", Similar),
            ("Maria Hernandes", "Maria Hernandez", Similar),
            ("Mary Smith Jones", "Mary Smith", Similar),
            ("Mary Smith", "Mary Jones", GivenOnly),
            ("Bob Smith", "Robert Jones", GivenOnly),
            ("John Smith", "Jane Smith", Different),
            ("J Smith", "K Smith", Different),
            ("Ann Lee", "Bo Chen", Different),
            ("Madonna", "Madonna", Similar),
            ("Madonna", "Madonna Ciccone", Different),
        ];
        for (left, right, grade) in expected {
            assert_eq!(judge(left, right), grade, "{left} / {right}");
        }
    }

    #[test]
    fn the_best_of_several_names_counts() {
        let primary = [name("Robert Smith"), name("Bob Smith")];
        assert_eq!(best_match(&primary, &[name("Bob Smith")]), NameMatch::Exact);
        assert_eq!(best_match(&primary, &[]), NameMatch::Missing);
    }

    #[test]
    fn keys_group_short_forms_with_formal_names() {
        assert_eq!(name("Bob Smith").key(), name("Robert A. Smith").key());
        assert_ne!(name("Alex Smith").key(), name("Alexander Smith").key());
    }
}
