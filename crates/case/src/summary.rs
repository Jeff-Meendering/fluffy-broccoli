//! Counts that describe a case as a whole: the figures a breach report starts from.

use std::collections::BTreeMap;

use anyhow::Result;
use rollcall_model::date::age_on;
use rollcall_model::{Category, ElementKind};

use crate::export::summarise_person;
use crate::store::Case;

/// How a person could be told about the breach, best means first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reach {
    /// A street address is on file.
    pub by_post: u64,
    /// No street address, but an email address.
    pub by_email_only: u64,
    /// Neither, but a phone number.
    pub by_phone_only: u64,
    /// No way to contact the person is on file.
    pub no_contact: u64,
}

/// What a case holds, counted by person.
///
/// These are counts of what was found, not a statement of who must be notified: that
/// depends on law and on facts outside the data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseSummary {
    pub people: u64,
    pub source_records: u64,
    pub files: u64,
    /// Pairs of records that may be one person. Until they are settled, some people
    /// are counted more than once.
    pub open_questions: u64,
    /// Evidence that did not become person records. The counts cover only what was read.
    pub coverage_gaps: u64,
    /// People with each element exposed.
    pub by_element: BTreeMap<ElementKind, u64>,
    /// People with each broad kind of data exposed.
    pub by_category: BTreeMap<Category, u64>,
    /// People with nothing but a name and contact details exposed.
    pub contact_only: u64,
    /// People per state or province. Someone with addresses in two is counted in both.
    pub by_region: BTreeMap<String, u64>,
    pub no_region: u64,
    pub reach: Reach,
    /// People under 18 on the day of the summary, by their latest recorded birth date.
    pub minors: u64,
    pub no_birth_date: u64,
    pub unnamed: u64,
    /// People with at least one value that failed validation.
    pub needs_review: u64,
}

impl Case {
    /// Counts the case's people as of `today`, given as `(year, month, day)`.
    pub fn summary(&self, today: (i32, u32, u32)) -> Result<CaseSummary> {
        let counts = self.counts()?;
        let mut summary = CaseSummary {
            people: counts.persons,
            source_records: counts.records,
            files: counts.documents,
            open_questions: counts.suggestions,
            coverage_gaps: counts.gaps,
            ..CaseSummary::default()
        };
        self.for_each_person(|person| {
            let found = summarise_person(&person.records);
            let has = |kind: ElementKind| found.values.contains_key(&kind);
            let mut categories: Vec<Category> = Vec::new();
            for kind in found.values.keys() {
                *summary.by_element.entry(*kind).or_default() += 1;
                if !categories.contains(&kind.category()) {
                    categories.push(kind.category());
                }
            }
            for category in &categories {
                *summary.by_category.entry(*category).or_default() += 1;
            }
            let beyond_contact = categories
                .iter()
                .any(|category| !matches!(category, Category::Name | Category::Contact));
            summary.contact_only += u64::from(!beyond_contact);

            match found.values.get(&ElementKind::State) {
                Some(regions) => {
                    for region in regions {
                        *summary.by_region.entry(region.clone()).or_default() += 1;
                    }
                }
                None => summary.no_region += 1,
            }

            let reach = &mut summary.reach;
            *(if has(ElementKind::Address) {
                &mut reach.by_post
            } else if has(ElementKind::Email) {
                &mut reach.by_email_only
            } else if has(ElementKind::Phone) {
                &mut reach.by_phone_only
            } else {
                &mut reach.no_contact
            }) += 1;

            // Dates of birth are stored as YYYY-MM-DD; the latest gives the youngest age.
            let youngest = found
                .values
                .get(&ElementKind::DateOfBirth)
                .and_then(|births| births.iter().filter_map(|birth| parse_iso(birth)).max());
            match youngest {
                Some(birth) => {
                    summary.minors += u64::from(age_on(birth, today).is_some_and(|age| age < 18))
                }
                None => summary.no_birth_date += 1,
            }
            summary.unnamed += u64::from(!has(ElementKind::Name));
            summary.needs_review += u64::from(!found.needs_review.is_empty());
            Ok(())
        })?;
        Ok(summary)
    }
}

fn parse_iso(date: &str) -> Option<(i32, u32, u32)> {
    let mut parts = date.splitn(3, '-');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}
