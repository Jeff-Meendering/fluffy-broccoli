//! Comparing postal addresses written in different styles.

use crate::text::fold;

/// A street address reduced to a comparable form, with what is known of its locality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Street line with abbreviations unified, as produced by [`street_key`].
    pub street: String,
    pub postal: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
}

/// Reduces a street line so that `12 North Main Street, Apt. 4` and `12 N Main St #4`
/// compare equal. Lines without a number are not specific enough to compare.
#[must_use]
pub fn street_key(line: &str) -> Option<String> {
    let folded = fold(line);
    let folded = folded
        .replace("p o box", "pobox")
        .replace("po box", "pobox");
    let words: Vec<&str> = folded
        .split(' ')
        .filter_map(|word| match word {
            // Unit markers vary too much to compare; the unit number itself is kept.
            "apt" | "apartment" | "unit" | "suite" | "ste" | "no" | "number" => None,
            "street" | "str" => Some("st"),
            "avenue" | "av" => Some("ave"),
            "road" => Some("rd"),
            "drive" => Some("dr"),
            "lane" => Some("ln"),
            "boulevard" | "boul" => Some("blvd"),
            "court" => Some("ct"),
            "place" => Some("pl"),
            "circle" => Some("cir"),
            "highway" => Some("hwy"),
            "parkway" => Some("pkwy"),
            "terrace" => Some("ter"),
            "square" => Some("sq"),
            "north" => Some("n"),
            "south" => Some("s"),
            "east" => Some("e"),
            "west" => Some("w"),
            "northeast" => Some("ne"),
            "northwest" => Some("nw"),
            "southeast" => Some("se"),
            "southwest" => Some("sw"),
            "" => None,
            other => Some(other),
        })
        .collect();
    let numbered = words
        .iter()
        .any(|word| word.bytes().any(|byte| byte.is_ascii_digit()));
    (numbered && words.len() >= 2).then(|| words.join(" "))
}

impl Address {
    /// True when both addresses name the same street line and nothing known about
    /// their localities disagrees. US ZIP+4 codes are compared on their first five
    /// digits.
    #[must_use]
    pub fn same_place(&self, other: &Self) -> bool {
        fn agree(left: Option<&str>, right: Option<&str>) -> Option<bool> {
            Some(left? == right?)
        }
        fn zone(postal: Option<&str>) -> Option<&str> {
            postal.map(|code| code.split('-').next().unwrap_or(code))
        }
        if self.street != other.street {
            return false;
        }
        let checks = [
            agree(zone(self.postal.as_deref()), zone(other.postal.as_deref())),
            agree(self.city.as_deref(), other.city.as_deref()),
            agree(self.state.as_deref(), other.state.as_deref()),
        ];
        // At least one locality fact must be shared, and none may differ: the same
        // street line exists in many towns.
        checks.iter().all(|check| *check != Some(false)) && checks.contains(&Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(
        street: &str,
        postal: Option<&str>,
        city: Option<&str>,
        state: Option<&str>,
    ) -> Address {
        Address {
            street: street_key(street).unwrap(),
            postal: postal.map(str::to_owned),
            city: city.map(fold),
            state: state.map(str::to_owned),
        }
    }

    #[test]
    fn writing_styles_reduce_to_one_key() {
        let key = street_key("12 North Main Street, Apt. 4").unwrap();
        assert_eq!(key, "12 n main st 4");
        assert_eq!(
            street_key("12 N. Main St #4").as_deref(),
            Some(key.as_str())
        );
        assert_eq!(street_key("P.O. Box 77").as_deref(), Some("pobox 77"));
        assert_eq!(street_key("PO Box 77").as_deref(), Some("pobox 77"));
        assert_eq!(street_key("Main Street"), None);
        assert_eq!(street_key("77"), None);
    }

    #[test]
    fn the_same_street_line_in_another_town_is_another_place() {
        let boston = address("1 Main St", Some("02134"), Some("Boston"), Some("MA"));
        assert!(boston.same_place(&address("1 Main Street", Some("02134-1234"), None, None)));
        assert!(boston.same_place(&address("1 Main St", None, Some("boston"), Some("MA"))));
        assert!(!boston.same_place(&address("1 Main St", Some("60601"), None, None)));
        assert!(!boston.same_place(&address("1 Main St", None, Some("Boston"), Some("NY"))));
        assert!(
            !boston.same_place(&address("1 Main St", None, None, None)),
            "nothing to confirm the town"
        );
        assert!(!boston.same_place(&address("2 Main St", Some("02134"), None, None)));
    }
}
