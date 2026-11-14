//! Decides which person records describe the same person.
//!
//! Records are merged automatically only on evidence that is hard to explain any other
//! way; weaker evidence becomes a suggestion for a reviewer. Wrongly merging two
//! people hides one of them from notification, so every rule errs towards keeping
//! records apart. The full policy is the [`decide`] function.

mod address;
mod name;
mod nicknames;
mod text;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rollcall_model::ElementKind;

pub use address::{Address, street_key};
pub use name::{NameMatch, PersonName, best_match, compare};
pub use text::{fold, jaro_winkler};

/// Everything about one person record that bears on whose it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// The record's identifier in the case.
    pub id: i64,
    pub names: Vec<PersonName>,
    pub ssns: Vec<String>,
    pub births: Vec<String>,
    /// Identifying values other than SSN: email, cards, accounts, licence and so on.
    pub identifiers: Vec<(ElementKind, String)>,
    pub phones: Vec<String>,
    pub addresses: Vec<Address>,
}

impl Profile {
    /// Builds a profile from a record's valid, normalised element values.
    #[must_use]
    pub fn new<'a>(id: i64, values: impl IntoIterator<Item = (ElementKind, &'a str)>) -> Self {
        let mut profile = Self {
            id,
            ..Self::default()
        };
        let (mut streets, mut postal, mut city, mut state) = (Vec::new(), None, None, None);
        for (kind, value) in values {
            match kind {
                ElementKind::Name => profile.names.extend(PersonName::parse(value)),
                ElementKind::Ssn => profile.ssns.push(value.to_owned()),
                ElementKind::DateOfBirth => profile.births.push(value.to_owned()),
                ElementKind::Phone => profile.phones.push(value.to_owned()),
                ElementKind::Address => streets.extend(street_key(value)),
                ElementKind::PostalCode => postal = postal.or_else(|| Some(value.to_owned())),
                ElementKind::City => city = city.or_else(|| Some(fold(value))),
                ElementKind::State => state = state.or_else(|| Some(value.to_owned())),
                ElementKind::Country | ElementKind::RoutingNumber => {}
                ElementKind::Email
                | ElementKind::PaymentCard
                | ElementKind::BankAccount
                | ElementKind::DriversLicence
                | ElementKind::Passport
                | ElementKind::MedicalRecordNumber
                | ElementKind::HealthInsuranceId => {
                    profile.identifiers.push((kind, value.to_owned()));
                }
            }
        }
        profile.addresses = streets
            .into_iter()
            .map(|street| Address {
                street,
                postal: postal.clone(),
                city: city.clone(),
                state: state.clone(),
            })
            .collect();
        profile
    }

    fn suffixes(&self) -> impl Iterator<Item = &'static str> {
        self.names.iter().filter_map(|name| name.suffix)
    }
}

/// What two records have in common.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Evidence {
    /// A reviewer said so.
    Reviewer,
    /// The same value of an identifying element.
    Identifier(ElementKind),
    BirthDate,
    Phone,
    Address,
    /// Nothing but the name.
    NameOnly,
}

/// A single-valued fact on which two groups of records disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Conflict {
    Ssn,
    BirthDate,
    Suffix,
}

/// Why two records were merged, or are suggested for merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reason {
    pub evidence: Evidence,
    pub name: NameMatch,
    pub conflict: Option<Conflict>,
}

impl Reason {
    /// A sentence a reviewer can act on.
    #[must_use]
    pub fn describe(&self) -> String {
        let shared = match self.evidence {
            Evidence::Reviewer => return "Confirmed by a reviewer".to_owned(),
            Evidence::Identifier(kind) => format!("Same {}", kind.label()),
            Evidence::BirthDate => "Same date of birth".to_owned(),
            Evidence::Phone => "Same phone number".to_owned(),
            Evidence::Address => "Same address".to_owned(),
            Evidence::NameOnly => "Same name and nothing else in common".to_owned(),
        };
        let names = match (self.evidence, self.name) {
            (Evidence::NameOnly, NameMatch::Exact) => "",
            (_, NameMatch::Exact) => "; names match",
            (_, NameMatch::Equivalent) => "; first names are forms of the same name",
            (_, NameMatch::Initial) => "; one first name is only an initial",
            (_, NameMatch::Similar) => "; names are close but not identical",
            (_, NameMatch::GivenOnly) => "; same first name, different last name",
            (_, NameMatch::Different) => "; names are different",
            (_, NameMatch::Missing) => "; one record has no name",
        };
        let conflict = match self.conflict {
            None => "",
            Some(Conflict::Ssn) => ", but the records carry different SSNs",
            Some(Conflict::BirthDate) => ", but the records carry different dates of birth",
            Some(Conflict::Suffix) => ", but the names carry different suffixes (Jr, Sr, ...)",
        };
        format!("{shared}{names}{conflict}")
    }
}

/// What the resolver does with a pair of records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Merge without asking.
    Merge,
    /// Ask a reviewer; the number ranks suggestions from 0 to 100.
    Suggest(u8),
    /// A record without a name: decided once the named records are settled.
    Defer,
    /// Not evidence that the records are one person.
    Ignore,
}

/// The merge policy: what shared evidence and name agreement together justify.
///
/// Identifiers issued to one person (SSN, licence, passport, medical record number)
/// merge unless the names plainly differ. Values that families and colleagues share
/// (email, cards, accounts, insurance, phone, address) merge only with a matching name.
#[must_use]
pub fn decide(evidence: Evidence, name: NameMatch) -> Action {
    use NameMatch::{Different, Equivalent, Exact, GivenOnly, Initial, Missing, Similar};
    match evidence {
        Evidence::Reviewer => Action::Merge,
        Evidence::Identifier(
            ElementKind::Ssn
            | ElementKind::DriversLicence
            | ElementKind::Passport
            | ElementKind::MedicalRecordNumber,
        ) => match name {
            Different => Action::Suggest(70),
            _ => Action::Merge,
        },
        Evidence::Identifier(_) => match name {
            Exact | Equivalent => Action::Merge,
            Initial | Similar => Action::Suggest(80),
            GivenOnly => Action::Suggest(55),
            Missing => Action::Defer,
            Different => Action::Ignore,
        },
        Evidence::BirthDate => match name {
            Exact | Equivalent => Action::Merge,
            Initial | Similar => Action::Suggest(80),
            GivenOnly | Different | Missing => Action::Ignore,
        },
        Evidence::Phone => match name {
            Exact | Equivalent => Action::Merge,
            Initial | Similar => Action::Suggest(75),
            GivenOnly => Action::Suggest(50),
            Missing => Action::Defer,
            Different => Action::Ignore,
        },
        Evidence::Address => match name {
            Exact => Action::Merge,
            // A father and son often share an address and a first name.
            Equivalent => Action::Suggest(85),
            Initial => Action::Suggest(70),
            Similar => Action::Suggest(60),
            GivenOnly => Action::Suggest(50),
            Different | Missing => Action::Ignore,
        },
        Evidence::NameOnly => match name {
            Exact => Action::Suggest(40),
            Equivalent => Action::Suggest(30),
            _ => Action::Ignore,
        },
    }
}

/// A reviewer's ruling on two records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraint {
    pub a: i64,
    pub b: i64,
    /// True when the records are the same person, false when they are not.
    pub same: bool,
}

/// Two records joined into one person, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub a: i64,
    pub b: i64,
    pub reason: Reason,
}

/// Two records that may be one person: a question for a reviewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suggestion {
    pub a: i64,
    pub b: i64,
    pub reason: Reason,
    pub score: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    /// Record identifiers grouped by person; each group and the list are sorted.
    pub persons: Vec<Vec<i64>>,
    /// One link for every merge that joined two groups.
    pub links: Vec<Link>,
    /// Open questions, strongest first.
    pub suggestions: Vec<Suggestion>,
}

/// Groups larger than this are too common a value to compare every pair in.
const DENSE_GROUP: usize = 50;
/// A name shared by more groups than this is too common to suggest on by itself.
/// One person spread over four files, plus a namesake in as many, must still fit.
const COMMON_NAME_GROUPS: usize = 8;
/// Suggestions weaker than this are not worth a reviewer's time.
const WEAKEST_SUGGESTION: u8 = 30;

/// Groups records into persons.
#[must_use]
pub fn resolve(profiles: &[Profile], constraints: &[Constraint]) -> Resolution {
    let index: HashMap<i64, usize> = profiles
        .iter()
        .enumerate()
        .map(|(position, profile)| (profile.id, position))
        .collect();
    let mut clusters = Clusters::new(profiles);
    let mut links = Vec::new();
    let mut proposals: Vec<Proposal> = Vec::new();

    // A reviewer's rulings come first and are never second-guessed.
    for constraint in constraints {
        let (Some(&a), Some(&b)) = (index.get(&constraint.a), index.get(&constraint.b)) else {
            continue;
        };
        if !constraint.same {
            clusters.forbid(a, b);
        }
    }
    let reviewer = Reason {
        evidence: Evidence::Reviewer,
        name: NameMatch::Missing,
        conflict: None,
    };
    for constraint in constraints.iter().filter(|constraint| constraint.same) {
        if let (Some(&a), Some(&b)) = (index.get(&constraint.a), index.get(&constraint.b))
            && clusters.union(a, b, true) == Outcome::Merged
        {
            links.push(Link {
                a: profiles[a].id,
                b: profiles[b].id,
                reason: reviewer,
            });
        }
    }

    let blocks = Blocks::new(profiles);
    let mut candidates = blocks.candidates(profiles);
    // Strongest evidence first; record identifiers break ties so the outcome does not
    // depend on the order records were supplied in.
    let ids = |a: usize, b: usize| {
        let (a, b) = (profiles[a].id, profiles[b].id);
        (a.min(b), a.max(b))
    };
    candidates.sort_unstable_by_key(|candidate| {
        (
            candidate.evidence,
            candidate.name,
            ids(candidate.a, candidate.b),
        )
    });
    for candidate in candidates {
        let reason = Reason {
            evidence: candidate.evidence,
            name: candidate.name,
            conflict: None,
        };
        match decide(candidate.evidence, candidate.name) {
            Action::Merge => match clusters.union(candidate.a, candidate.b, false) {
                Outcome::Merged => links.push(Link {
                    a: profiles[candidate.a].id,
                    b: profiles[candidate.b].id,
                    reason,
                }),
                // Strong evidence against a single-valued fact: worth a human look.
                Outcome::Conflict(conflict) => proposals.push(Proposal {
                    a: candidate.a,
                    b: candidate.b,
                    reason: Reason {
                        conflict: Some(conflict),
                        ..reason
                    },
                    score: 60,
                }),
                Outcome::Already | Outcome::Forbidden => {}
            },
            Action::Suggest(score) => proposals.push(Proposal {
                a: candidate.a,
                b: candidate.b,
                reason,
                score,
            }),
            // Deferred pairs are settled by `settle_shared_values` once named records are grouped.
            Action::Defer | Action::Ignore => {}
        }
    }

    settle_shared_values(&blocks, profiles, &mut clusters, &mut links, &mut proposals);
    suggest_on_names(&blocks, &mut clusters, &mut proposals);

    let mut resolution = Resolution {
        links,
        ..Resolution::default()
    };
    let mut best: BTreeMap<(usize, usize), Proposal> = BTreeMap::new();
    for mut proposal in proposals {
        let (a, b) = (clusters.find(proposal.a), clusters.find(proposal.b));
        if a == b || clusters.forbidden(a, b) {
            continue;
        }
        if proposal.reason.conflict.is_none()
            && let Some(conflict) = clusters.conflict(a, b)
        {
            proposal.reason.conflict = Some(conflict);
            proposal.score = proposal.score.saturating_sub(30);
        }
        if proposal.score < WEAKEST_SUGGESTION {
            continue;
        }
        let rank = |proposal: &Proposal| {
            (
                proposal.score,
                std::cmp::Reverse((proposal.reason, ids(proposal.a, proposal.b))),
            )
        };
        let slot = best.entry((a.min(b), a.max(b))).or_insert(proposal);
        if rank(&proposal) > rank(slot) {
            *slot = proposal;
        }
    }
    resolution.suggestions = best
        .into_values()
        .map(|proposal| {
            let (a, b) = (profiles[proposal.a].id, profiles[proposal.b].id);
            Suggestion {
                a: a.min(b),
                b: a.max(b),
                reason: proposal.reason,
                score: proposal.score,
            }
        })
        .collect();
    resolution.suggestions.sort_by_key(|suggestion| {
        (
            std::cmp::Reverse(suggestion.score),
            suggestion.a,
            suggestion.b,
        )
    });

    let mut persons: BTreeMap<usize, Vec<i64>> = BTreeMap::new();
    for (position, profile) in profiles.iter().enumerate() {
        persons
            .entry(clusters.find(position))
            .or_default()
            .push(profile.id);
    }
    resolution.persons = persons
        .into_values()
        .map(|mut records| {
            records.sort_unstable();
            records
        })
        .collect();
    resolution.persons.sort();
    resolution
}

/// Settles what record-by-record comparison could not, for values people may share.
///
/// First, groups that share a value are compared again using every name each group
/// has gathered through merging: a record that was nameless, or had only one spelling,
/// may now belong to a group whose names match. Then records in groups that still
/// have no name join the one named group that shares their email, card, account or
/// insurance number. When several named groups share it, the record could belong to
/// any of them, so each is suggested instead.
fn settle_shared_values(
    blocks: &Blocks,
    profiles: &[Profile],
    clusters: &mut Clusters,
    links: &mut Vec<Link>,
    proposals: &mut Vec<Proposal>,
) {
    for (key, members) in &blocks.groups {
        let evidence = key.0;
        let personal = match evidence {
            Evidence::Identifier(_) => true,
            Evidence::Phone => false,
            _ => continue,
        };
        if members.len() > DENSE_GROUP {
            continue;
        }
        let mut merge = |clusters: &mut Clusters,
                         proposals: &mut Vec<Proposal>,
                         a: usize,
                         b: usize,
                         reason: Reason| {
            match clusters.union(a, b, false) {
                Outcome::Merged => links.push(Link {
                    a: profiles[a].id,
                    b: profiles[b].id,
                    reason,
                }),
                Outcome::Conflict(conflict) => proposals.push(Proposal {
                    a,
                    b,
                    reason: Reason {
                        conflict: Some(conflict),
                        ..reason
                    },
                    score: 60,
                }),
                Outcome::Already | Outcome::Forbidden => {}
            }
        };

        let named: Vec<usize> = representatives(members, clusters)
            .into_iter()
            .filter(|member| clusters.is_named(*member))
            .collect();
        for (position, &a) in named.iter().enumerate() {
            for &b in &named[position + 1..] {
                let name = clusters.name_match(a, b);
                let reason = Reason {
                    evidence,
                    name,
                    conflict: None,
                };
                match decide(evidence, name) {
                    Action::Merge => merge(clusters, proposals, a, b, reason),
                    Action::Suggest(score) => proposals.push(Proposal {
                        a,
                        b,
                        reason,
                        score,
                    }),
                    Action::Defer | Action::Ignore => {}
                }
            }
        }

        let (named, nameless): (Vec<usize>, Vec<usize>) = representatives(members, clusters)
            .into_iter()
            .partition(|member| clusters.is_named(*member));
        let reason = Reason {
            evidence,
            name: NameMatch::Missing,
            conflict: None,
        };
        match (personal, named.as_slice()) {
            (true, []) => {
                for pair in nameless.windows(2) {
                    merge(clusters, proposals, pair[0], pair[1], reason);
                }
            }
            (true, [owner]) => {
                for &record in &nameless {
                    merge(clusters, proposals, record, *owner, reason);
                }
            }
            (true, owners) => {
                for &record in &nameless {
                    for &owner in owners.iter().take(COMMON_NAME_GROUPS) {
                        proposals.push(Proposal {
                            a: record,
                            b: owner,
                            reason,
                            score: 50,
                        });
                    }
                }
            }
            // A phone number is shared by a household or an office: never automatic.
            (false, []) => {
                for pair in nameless.windows(2) {
                    proposals.push(Proposal {
                        a: pair[0],
                        b: pair[1],
                        reason,
                        score: 45,
                    });
                }
            }
            (false, [owner]) => {
                for &record in &nameless {
                    proposals.push(Proposal {
                        a: record,
                        b: *owner,
                        reason,
                        score: 45,
                    });
                }
            }
            (false, _) => {}
        }
    }
}

/// Records that share a name and nothing else are suggested, unless the name is common.
fn suggest_on_names(blocks: &Blocks, clusters: &mut Clusters, proposals: &mut Vec<Proposal>) {
    for (key, members) in &blocks.groups {
        if key.0 != Evidence::NameOnly {
            continue;
        }
        let representatives = representatives(members, clusters);
        if !(2..=COMMON_NAME_GROUPS).contains(&representatives.len()) {
            continue;
        }
        for (position, &a) in representatives.iter().enumerate() {
            for &b in &representatives[position + 1..] {
                let name = best_match(&clusters.profiles[a].names, &clusters.profiles[b].names);
                if let Action::Suggest(score) = decide(Evidence::NameOnly, name) {
                    let reason = Reason {
                        evidence: Evidence::NameOnly,
                        name,
                        conflict: None,
                    };
                    proposals.push(Proposal {
                        a,
                        b,
                        reason,
                        score,
                    });
                }
            }
        }
    }
}

/// One record from each group the members fall into: the record with the smallest
/// identifier, listed in identifier order, so choices do not depend on input order.
fn representatives(members: &[usize], clusters: &mut Clusters) -> Vec<usize> {
    let mut chosen: BTreeMap<usize, usize> = BTreeMap::new();
    for &member in members {
        let slot = chosen.entry(clusters.find(member)).or_insert(member);
        if clusters.profiles[member].id < clusters.profiles[*slot].id {
            *slot = member;
        }
    }
    let mut chosen: Vec<usize> = chosen.into_values().collect();
    chosen.sort_unstable_by_key(|member| clusters.profiles[*member].id);
    chosen
}

#[derive(Debug, Clone, Copy)]
struct Proposal {
    a: usize,
    b: usize,
    reason: Reason,
    score: u8,
}

/// Two records that share a blocking key. Ordered so the strongest are handled first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Candidate {
    evidence: Evidence,
    name: NameMatch,
    a: usize,
    b: usize,
}

/// Records grouped by a value they share, so only plausible pairs are compared.
struct Blocks {
    groups: BTreeMap<(Evidence, String), Vec<usize>>,
}

impl Blocks {
    fn new(profiles: &[Profile]) -> Self {
        let mut groups: BTreeMap<(Evidence, String), Vec<usize>> = BTreeMap::new();
        let mut add = |evidence: Evidence, key: String, position: usize| {
            let members = groups.entry((evidence, key)).or_default();
            if members.last() != Some(&position) {
                members.push(position);
            }
        };
        for (position, profile) in profiles.iter().enumerate() {
            for ssn in &profile.ssns {
                add(
                    Evidence::Identifier(ElementKind::Ssn),
                    ssn.clone(),
                    position,
                );
            }
            for (kind, value) in &profile.identifiers {
                add(Evidence::Identifier(*kind), value.clone(), position);
            }
            for phone in &profile.phones {
                add(Evidence::Phone, phone.clone(), position);
            }
            for address in &profile.addresses {
                add(Evidence::Address, address.street.clone(), position);
            }
            for name in &profile.names {
                add(Evidence::NameOnly, name.key(), position);
                // Dates of birth are compared within a surname and within a first
                // name, so a typing error in either still finds its pair.
                for birth in &profile.births {
                    add(
                        Evidence::BirthDate,
                        format!("{birth} surname {}", name.last),
                        position,
                    );
                    add(
                        Evidence::BirthDate,
                        format!("{birth} given {}", name.first),
                        position,
                    );
                }
            }
        }
        groups.retain(|_, members| members.len() > 1);
        Self { groups }
    }

    fn candidates(&self, profiles: &[Profile]) -> Vec<Candidate> {
        let mut found: HashSet<Candidate> = HashSet::new();
        for ((evidence, _), members) in &self.groups {
            if *evidence == Evidence::NameOnly {
                continue;
            }
            let mut consider = |a: usize, b: usize| {
                let (left, right) = (&profiles[a], &profiles[b]);
                if *evidence == Evidence::Address
                    && !left
                        .addresses
                        .iter()
                        .any(|one| right.addresses.iter().any(|other| one.same_place(other)))
                {
                    return;
                }
                let name = best_match(&left.names, &right.names);
                found.insert(Candidate {
                    evidence: *evidence,
                    name,
                    a: a.min(b),
                    b: a.max(b),
                });
            };
            if members.len() <= DENSE_GROUP {
                for (position, &a) in members.iter().enumerate() {
                    for &b in &members[position + 1..] {
                        consider(a, b);
                    }
                }
            } else {
                // A value this common (a switchboard number, a shared mailbox) is only
                // evidence between records that also carry the same name.
                let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
                for &member in members {
                    for name in &profiles[member].names {
                        by_name.entry(name.key()).or_default().push(member);
                    }
                }
                for same_name in by_name.values() {
                    for pair in same_name.windows(2) {
                        consider(pair[0], pair[1]);
                    }
                }
            }
        }
        found.into_iter().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Merged,
    Already,
    Forbidden,
    Conflict(Conflict),
}

/// Disjoint sets of records with the facts each set has accumulated.
struct Clusters<'a> {
    profiles: &'a [Profile],
    parent: Vec<usize>,
    members: Vec<Vec<usize>>,
    ssns: Vec<BTreeSet<&'a str>>,
    births: Vec<BTreeSet<&'a str>>,
    suffixes: Vec<BTreeSet<&'static str>>,
    named: Vec<bool>,
    /// For each record, the records a reviewer said it is not.
    apart: Vec<Vec<usize>>,
}

impl<'a> Clusters<'a> {
    fn new(profiles: &'a [Profile]) -> Self {
        Self {
            profiles,
            parent: (0..profiles.len()).collect(),
            members: (0..profiles.len()).map(|position| vec![position]).collect(),
            ssns: profiles
                .iter()
                .map(|profile| profile.ssns.iter().map(String::as_str).collect())
                .collect(),
            births: profiles
                .iter()
                .map(|profile| profile.births.iter().map(String::as_str).collect())
                .collect(),
            suffixes: profiles
                .iter()
                .map(|profile| profile.suffixes().collect())
                .collect(),
            named: profiles
                .iter()
                .map(|profile| !profile.names.is_empty())
                .collect(),
            apart: vec![Vec::new(); profiles.len()],
        }
    }

    fn find(&mut self, mut position: usize) -> usize {
        while self.parent[position] != position {
            self.parent[position] = self.parent[self.parent[position]];
            position = self.parent[position];
        }
        position
    }

    /// True when the group a record belongs to holds at least one name.
    fn is_named(&mut self, record: usize) -> bool {
        let root = self.find(record);
        self.named[root]
    }

    /// The strongest agreement between any name in one record's group and any name in
    /// the other's.
    fn name_match(&mut self, a: usize, b: usize) -> NameMatch {
        let (a, b) = (self.find(a), self.find(b));
        let names = |root: usize| {
            self.members[root]
                .iter()
                .flat_map(|member| &self.profiles[*member].names)
        };
        names(a)
            .flat_map(|left| names(b).map(move |right| compare(left, right)))
            .min()
            .unwrap_or(NameMatch::Missing)
    }

    fn forbid(&mut self, a: usize, b: usize) {
        self.apart[a].push(b);
        self.apart[b].push(a);
    }

    /// True when a reviewer ruled that some record in one group is not some record in
    /// the other. Takes group roots.
    fn forbidden(&mut self, a: usize, b: usize) -> bool {
        let (small, large) = if self.members[a].len() <= self.members[b].len() {
            (a, b)
        } else {
            (b, a)
        };
        let partners: Vec<usize> = self.members[small]
            .iter()
            .flat_map(|member| self.apart[*member].iter().copied())
            .collect();
        partners
            .into_iter()
            .any(|partner| self.find(partner) == large)
    }

    /// A single-valued fact the two groups disagree on. Takes group roots.
    fn conflict(&self, a: usize, b: usize) -> Option<Conflict> {
        fn clash<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> bool {
            !left.is_empty() && !right.is_empty() && left.union(right).count() > 1
        }
        if clash(&self.ssns[a], &self.ssns[b]) {
            Some(Conflict::Ssn)
        } else if clash(&self.births[a], &self.births[b]) {
            Some(Conflict::BirthDate)
        } else if clash(&self.suffixes[a], &self.suffixes[b]) {
            Some(Conflict::Suffix)
        } else {
            None
        }
    }

    /// Joins the groups of two records. `forced` merges despite conflicting facts.
    fn union(&mut self, a: usize, b: usize, forced: bool) -> Outcome {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return Outcome::Already;
        }
        if self.forbidden(a, b) {
            return Outcome::Forbidden;
        }
        if !forced && let Some(conflict) = self.conflict(a, b) {
            return Outcome::Conflict(conflict);
        }
        let (keep, absorb) = if self.members[a].len() >= self.members[b].len() {
            (a, b)
        } else {
            (b, a)
        };
        self.parent[absorb] = keep;
        let moved = std::mem::take(&mut self.members[absorb]);
        self.members[keep].extend(moved);
        let ssns = std::mem::take(&mut self.ssns[absorb]);
        self.ssns[keep].extend(ssns);
        let births = std::mem::take(&mut self.births[absorb]);
        self.births[keep].extend(births);
        let suffixes = std::mem::take(&mut self.suffixes[absorb]);
        self.suffixes[keep].extend(suffixes);
        self.named[keep] |= self.named[absorb];
        Outcome::Merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ElementKind::{Address as Street, DateOfBirth, Email, Name, Phone, PostalCode, Ssn};

    fn profile(id: i64, values: &[(ElementKind, &str)]) -> Profile {
        Profile::new(id, values.iter().copied())
    }

    fn persons(profiles: &[Profile]) -> Vec<Vec<i64>> {
        resolve(profiles, &[]).persons
    }

    #[test]
    fn a_personal_identifier_joins_records_despite_name_variations() {
        let profiles = [
            profile(1, &[(Name, "Robert Smith"), (Ssn, "219-09-9999")]),
            profile(2, &[(Name, "Bob Smith"), (Ssn, "219-09-9999")]),
            profile(3, &[(Name, "Robert Smyth"), (Ssn, "219-09-9999")]),
            profile(4, &[(Ssn, "219-09-9999"), (Email, "x@example.com")]),
            profile(5, &[(Name, "Robert Smith"), (Ssn, "219-09-9998")]),
        ];
        let resolution = resolve(&profiles, &[]);
        assert_eq!(resolution.persons, vec![vec![1, 2, 3, 4], vec![5]]);
        assert_eq!(resolution.links.len(), 3);
        assert!(
            resolution.suggestions.is_empty(),
            "different SSNs rule out a same-name suggestion"
        );
    }

    #[test]
    fn the_same_identifier_under_different_names_is_a_question() {
        let profiles = [
            profile(1, &[(Name, "Jane Doe"), (Ssn, "219-09-9999")]),
            profile(2, &[(Name, "Mark Poe"), (Ssn, "219-09-9999")]),
        ];
        let resolution = resolve(&profiles, &[]);
        assert_eq!(resolution.persons.len(), 2);
        assert_eq!(resolution.suggestions.len(), 1);
        assert_eq!(resolution.suggestions[0].score, 70);
        assert_eq!(
            resolution.suggestions[0].reason.describe(),
            "Same SSN; names are different"
        );
    }

    #[test]
    fn shared_contact_details_need_a_matching_name() {
        let household = [
            profile(
                1,
                &[
                    (Name, "Jane Doe"),
                    (Phone, "+14155550134"),
                    (Email, "doe@example.com"),
                ],
            ),
            profile(
                2,
                &[
                    (Name, "John Doe"),
                    (Phone, "+14155550134"),
                    (Email, "doe@example.com"),
                ],
            ),
            profile(3, &[(Name, "Jane Doe"), (Phone, "+14155550134")]),
            profile(4, &[(Name, "Jane Roe"), (Email, "doe@example.com")]),
        ];
        let resolution = resolve(&household, &[]);
        assert_eq!(resolution.persons, vec![vec![1, 3], vec![2], vec![4]]);
        let asked: Vec<(i64, i64, u8)> = resolution
            .suggestions
            .iter()
            .map(|found| (found.a, found.b, found.score))
            .collect();
        assert_eq!(
            asked,
            vec![(1, 4, 55)],
            "a possible name change, and nothing about John"
        );
    }

    #[test]
    fn name_and_birth_date_join_but_a_typing_error_only_suggests() {
        let profiles = [
            profile(
                1,
                &[(Name, "Elizabeth Okafor"), (DateOfBirth, "1980-02-03")],
            ),
            profile(2, &[(Name, "Liz Okafor"), (DateOfBirth, "1980-02-03")]),
            profile(
                3,
                &[(Name, "Elizabeth Okafro"), (DateOfBirth, "1980-02-03")],
            ),
            profile(
                4,
                &[(Name, "Elizabeth Okafor"), (DateOfBirth, "1991-07-08")],
            ),
        ];
        let resolution = resolve(&profiles, &[]);
        assert_eq!(resolution.persons, vec![vec![1, 2], vec![3], vec![4]]);
        assert_eq!(resolution.suggestions.len(), 1);
        let suggestion = resolution.suggestions[0];
        assert_eq!((suggestion.b, suggestion.score), (3, 80));
        assert_eq!(suggestion.reason.name, NameMatch::Similar);
    }

    #[test]
    fn a_merge_never_puts_two_birth_dates_or_ssns_in_one_person() {
        // Record 2 links to 1 by email and to 3 by phone, but 1 and 3 are different
        // people with different dates of birth.
        let profiles = [
            profile(
                1,
                &[
                    (Name, "Ann Lee"),
                    (Email, "ann@example.com"),
                    (DateOfBirth, "1980-01-01"),
                ],
            ),
            profile(
                2,
                &[
                    (Name, "Ann Lee"),
                    (Email, "ann@example.com"),
                    (Phone, "+14155550134"),
                ],
            ),
            profile(
                3,
                &[
                    (Name, "Ann Lee"),
                    (Phone, "+14155550134"),
                    (DateOfBirth, "1975-05-05"),
                ],
            ),
        ];
        let resolution = resolve(&profiles, &[]);
        assert_eq!(resolution.persons, vec![vec![1, 2], vec![3]]);
        assert_eq!(resolution.suggestions.len(), 1);
        let suggestion = resolution.suggestions[0];
        assert_eq!(suggestion.reason.conflict, Some(Conflict::BirthDate));
        assert!(
            suggestion
                .reason
                .describe()
                .ends_with("different dates of birth")
        );
    }

    #[test]
    fn the_same_name_at_the_same_address_joins_unless_the_suffixes_differ() {
        let same = [
            profile(
                1,
                &[
                    (Name, "Omar Haddad"),
                    (Street, "12 North Main Street Apt 4"),
                    (PostalCode, "02134"),
                ],
            ),
            profile(
                2,
                &[
                    (Name, "Omar Haddad"),
                    (Street, "12 N Main St #4"),
                    (PostalCode, "02134-1234"),
                ],
            ),
            profile(
                3,
                &[
                    (Name, "Omar Haddad"),
                    (Street, "12 N Main St #4"),
                    (PostalCode, "60601"),
                ],
            ),
        ];
        assert_eq!(persons(&same), vec![vec![1, 2], vec![3]]);

        let father_and_son = [
            profile(
                1,
                &[
                    (Name, "Omar Haddad Sr"),
                    (Street, "12 Main St"),
                    (PostalCode, "02134"),
                ],
            ),
            profile(
                2,
                &[
                    (Name, "Omar Haddad Jr"),
                    (Street, "12 Main St"),
                    (PostalCode, "02134"),
                ],
            ),
        ];
        let resolution = resolve(&father_and_son, &[]);
        assert_eq!(resolution.persons.len(), 2);
        assert_eq!(
            resolution.suggestions[0].reason.conflict,
            Some(Conflict::Suffix)
        );
    }

    #[test]
    fn a_shared_name_alone_is_a_weak_question_and_a_common_name_is_none() {
        let pair = [
            profile(1, &[(Name, "Uma Xu")]),
            profile(2, &[(Name, "Uma Xu"), (Email, "u@example.com")]),
        ];
        let resolution = resolve(&pair, &[]);
        assert_eq!(resolution.persons.len(), 2);
        assert_eq!(resolution.suggestions[0].score, 40);

        let crowd: Vec<Profile> = (1..=9)
            .map(|id| profile(id, &[(Name, "Maria Garcia")]))
            .collect();
        let resolution = resolve(&crowd, &[]);
        assert_eq!(resolution.persons.len(), 9);
        assert!(resolution.suggestions.is_empty());
    }

    #[test]
    fn nameless_records_join_the_only_named_owner_of_their_email() {
        let single = [
            profile(1, &[(Name, "Zoe Ito"), (Email, "zoe@example.com")]),
            profile(2, &[(Email, "zoe@example.com"), (Phone, "+14155550134")]),
        ];
        assert_eq!(persons(&single), vec![vec![1, 2]]);

        let shared = [
            profile(1, &[(Name, "Zoe Ito"), (Email, "home@example.com")]),
            profile(2, &[(Name, "Ken Ito"), (Email, "home@example.com")]),
            profile(3, &[(Email, "home@example.com")]),
        ];
        let resolution = resolve(&shared, &[]);
        assert_eq!(resolution.persons.len(), 3);
        assert_eq!(
            resolution.suggestions.len(),
            2,
            "the record could be either person"
        );
    }

    #[test]
    fn names_gathered_through_merging_count_when_groups_are_compared() {
        // Record 2 has no name, so its email says nothing about record 1 by itself. Once
        // its SSN joins it to record 3, the group has a name close to record 1's.
        let profiles = [
            profile(1, &[(Name, "Tom Eriksen"), (Email, "tom@example.com")]),
            profile(2, &[(Email, "tom@example.com"), (Ssn, "219-09-9999")]),
            profile(3, &[(Name, "Thomas Erkisen"), (Ssn, "219-09-9999")]),
        ];
        let resolution = resolve(&profiles, &[]);
        assert_eq!(resolution.persons, vec![vec![1], vec![2, 3]]);
        assert_eq!(resolution.suggestions.len(), 1);
        let suggestion = resolution.suggestions[0];
        assert_eq!((suggestion.a, suggestion.score), (1, 80));
        assert_eq!(
            suggestion.reason.describe(),
            "Same email address; names are close but not identical"
        );

        // With the surname spelled the same, the short form is enough to merge.
        let exact = [
            profile(1, &[(Name, "Tom Eriksen"), (Email, "tom@example.com")]),
            profile(2, &[(Email, "tom@example.com"), (Ssn, "219-09-9999")]),
            profile(3, &[(Name, "Thomas Eriksen"), (Ssn, "219-09-9999")]),
        ];
        assert_eq!(resolve(&exact, &[]).persons, vec![vec![1, 2, 3]]);
    }

    #[test]
    fn reviewer_rulings_override_the_policy_in_both_directions() {
        let profiles = [
            profile(1, &[(Name, "Jane Doe"), (Ssn, "219-09-9999")]),
            profile(2, &[(Name, "Jane Doe"), (Ssn, "219-09-9999")]),
            profile(3, &[(Name, "Janet Dough")]),
        ];
        let rulings = [
            Constraint {
                a: 1,
                b: 2,
                same: false,
            },
            Constraint {
                a: 3,
                b: 1,
                same: true,
            },
        ];
        let resolution = resolve(&profiles, &rulings);
        assert_eq!(resolution.persons, vec![vec![1, 3], vec![2]]);
        assert_eq!(
            resolution.links[0].reason.describe(),
            "Confirmed by a reviewer"
        );
        assert!(
            resolution.suggestions.is_empty(),
            "a rejected pair is not asked about again"
        );

        // Rulings about records that no longer exist are ignored.
        let stale = [Constraint {
            a: 1,
            b: 99,
            same: true,
        }];
        assert_eq!(
            resolve(&profiles, &stale).persons,
            vec![vec![1, 2], vec![3]]
        );
    }

    #[test]
    fn a_very_common_value_only_links_records_with_the_same_name() {
        let mut profiles: Vec<Profile> = (0..60)
            .map(|id| {
                profile(
                    id,
                    &[
                        (Name, &format!("Person Number{id}")),
                        (Phone, "+14155550100"),
                    ],
                )
            })
            .collect();
        profiles.push(profile(
            100,
            &[(Name, "Person Number7"), (Phone, "+14155550100")],
        ));
        let resolution = resolve(&profiles, &[]);
        assert_eq!(resolution.persons.len(), 60);
        assert!(resolution.persons.contains(&vec![7, 100]));
    }

    #[test]
    fn results_do_not_depend_on_input_order() {
        let mut profiles = vec![
            profile(1, &[(Name, "Robert Smith"), (Ssn, "219-09-9999")]),
            profile(2, &[(Name, "Bob Smith"), (Email, "bob@example.com")]),
            profile(
                3,
                &[
                    (Name, "Bob Smith"),
                    (Ssn, "219-09-9999"),
                    (Email, "bob@example.com"),
                ],
            ),
            profile(4, &[(Name, "Uma Xu")]),
            profile(5, &[(Name, "Uma Xu"), (DateOfBirth, "1990-01-01")]),
        ];
        let forward = resolve(&profiles, &[]);
        profiles.reverse();
        let backward = resolve(&profiles, &[]);
        assert_eq!(forward.persons, backward.persons);
        assert_eq!(forward.suggestions, backward.suggestions);
        assert_eq!(forward.persons, vec![vec![1, 2, 3], vec![4], vec![5]]);
    }
}
