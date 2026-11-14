//! Short forms of English given names.
//!
//! Each group starts with the formal name. Two names are equivalent when some group
//! holds both. A few short forms belong to more than one formal name (`Alex`, `Pat`):
//! they are equivalent to each, but the formal names are not equivalent to each other.

use std::collections::HashMap;
use std::sync::OnceLock;

const GROUPS: &[&[&str]] = &[
    &["abigail", "abby", "abbie", "gail"],
    &["albert", "al", "bert", "bertie"],
    &["alexander", "alex", "alec", "xander", "sandy", "sasha"],
    &[
        "alexandra",
        "alex",
        "alexa",
        "sandra",
        "sandy",
        "sasha",
        "lexi",
    ],
    &["alfred", "al", "alf", "alfie", "fred"],
    &["andrew", "andy", "drew"],
    &["anthony", "tony", "ant"],
    &["barbara", "barb", "barbie", "babs"],
    &["benjamin", "ben", "benny", "benji"],
    &[
        "catherine",
        "cathy",
        "cate",
        "cat",
        "kate",
        "katie",
        "kathy",
        "kat",
        "kitty",
    ],
    &[
        "katherine",
        "kathy",
        "kate",
        "katie",
        "kat",
        "kitty",
        "kay",
        "cathy",
    ],
    &["charles", "charlie", "chuck", "chas", "chaz"],
    &["charlotte", "charlie", "lottie", "lotte"],
    &["christopher", "chris", "kit", "topher"],
    &["christine", "chris", "chrissy", "christy", "tina"],
    &["christina", "chris", "chrissy", "christy", "tina"],
    &["daniel", "dan", "danny"],
    &["david", "dave", "davey"],
    &["deborah", "deb", "debbie", "debby"],
    &["dorothy", "dot", "dottie", "dolly"],
    &["douglas", "doug"],
    &["edward", "ed", "eddie", "ted", "teddy", "ned"],
    &[
        "elizabeth",
        "liz",
        "lizzie",
        "beth",
        "betty",
        "betsy",
        "eliza",
        "libby",
        "liza",
        "lisa",
    ],
    &["emily", "em", "emmy", "millie"],
    &["eugene", "gene"],
    &["frances", "fran", "frankie", "fanny"],
    &["francis", "frank", "frankie", "fran"],
    &["franklin", "frank", "frankie"],
    &["frederick", "fred", "freddie", "freddy", "fritz"],
    &["gabriel", "gabe"],
    &["gerald", "gerry", "jerry"],
    &["gregory", "greg", "gregg"],
    &["harold", "harry", "hal"],
    &["henry", "hank", "harry", "hal"],
    &["isabella", "bella", "izzy", "isa", "belle"],
    &["jacob", "jake", "jakey"],
    &["james", "jim", "jimmy", "jamie", "jimbo"],
    &["jacqueline", "jackie", "jacqui"],
    &["jeffrey", "jeff", "geoff"],
    &["geoffrey", "geoff", "jeff"],
    &["jennifer", "jen", "jenny", "jenn"],
    &["jessica", "jess", "jessie"],
    &["john", "johnny", "jack", "jon"],
    &["jonathan", "jon", "jonny", "nathan"],
    &["joseph", "joe", "joey", "jo"],
    &["josephine", "jo", "josie", "joey"],
    &["joshua", "josh"],
    &["judith", "judy", "judi"],
    &["kenneth", "ken", "kenny"],
    &["kimberly", "kim", "kimmy"],
    &["lawrence", "larry", "lars", "laurie"],
    &["leonard", "leo", "len", "lenny"],
    &[
        "margaret", "maggie", "meg", "peggy", "marge", "margie", "greta", "madge", "rita",
    ],
    &["matthew", "matt", "matty"],
    &["michael", "mike", "mikey", "mick", "mickey"],
    &["michelle", "shelly", "chelle", "mich"],
    &["nathaniel", "nate", "nathan", "nat"],
    &["nicholas", "nick", "nicky", "nico", "cole"],
    &["nicole", "nicky", "nikki", "cole"],
    &["pamela", "pam"],
    &["patricia", "pat", "patty", "patsy", "trish", "tricia"],
    &["patrick", "pat", "paddy", "rick"],
    &["peter", "pete"],
    &["philip", "phil"],
    &["phillip", "phil"],
    &["rebecca", "becky", "becca", "reba"],
    &["richard", "rick", "ricky", "rich", "richie", "dick"],
    &["robert", "bob", "bobby", "rob", "robbie", "bert"],
    &["ronald", "ron", "ronnie"],
    &["samuel", "sam", "sammy"],
    &["samantha", "sam", "sammy"],
    &["stephanie", "steph", "stevie"],
    &["stephen", "steve", "stevie"],
    &["steven", "steve", "stevie"],
    &["susan", "sue", "susie", "suzy"],
    &["suzanne", "sue", "susie", "suzy"],
    &["theodore", "ted", "teddy", "theo"],
    &["thomas", "tom", "tommy", "thom"],
    &["timothy", "tim", "timmy"],
    &["victoria", "vicky", "vicki", "tori"],
    &["vincent", "vince", "vinny"],
    &["virginia", "ginny", "ginger"],
    &["walter", "walt", "wally"],
    &["william", "will", "bill", "billy", "willy", "liam"],
    &["zachary", "zach", "zack", "zac"],
];

fn index() -> &'static HashMap<&'static str, Vec<usize>> {
    static INDEX: OnceLock<HashMap<&'static str, Vec<usize>>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index: HashMap<&'static str, Vec<usize>> = HashMap::new();
        for (group, names) in GROUPS.iter().enumerate() {
            for name in *names {
                let groups = index.entry(name).or_default();
                if !groups.contains(&group) {
                    groups.push(group);
                }
            }
        }
        index
    })
}

/// True when two different folded given names are forms of the same name.
#[must_use]
pub fn equivalent(left: &str, right: &str) -> bool {
    let index = index();
    match (index.get(left), index.get(right)) {
        (Some(left), Some(right)) => left.iter().any(|group| right.contains(group)),
        _ => false,
    }
}

/// The formal name a folded given name stands for, when there is exactly one.
///
/// `bob` gives `robert`; `alex` could be Alexander or Alexandra and stays `alex`.
#[must_use]
pub fn formal(name: &str) -> &str {
    match index().get(name).map(Vec::as_slice) {
        Some([group]) => GROUPS[*group][0],
        _ => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_forms_match_their_formal_names_and_each_other() {
        assert!(equivalent("bob", "robert"));
        assert!(equivalent("bobby", "rob"));
        assert!(equivalent("liz", "betty"));
        assert!(equivalent("alex", "alexander") && equivalent("alex", "alexandra"));
        assert!(!equivalent("alexander", "alexandra"));
        assert!(!equivalent("robert", "richard"));
        assert!(
            !equivalent("zoe", "zoe"),
            "names outside the table are compared elsewhere"
        );
    }

    #[test]
    fn formal_names_are_given_only_when_unambiguous() {
        assert_eq!(formal("bob"), "robert");
        assert_eq!(formal("robert"), "robert");
        assert_eq!(formal("alex"), "alex");
        assert_eq!(formal("pat"), "pat");
        assert_eq!(formal("zoe"), "zoe");
    }
}
