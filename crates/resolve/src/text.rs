//! Text folding and string similarity.

/// Lower-cases text, reduces accented Latin letters to their base letters, drops
/// apostrophes and full stops, and turns every other mark into a space.
///
/// `José O'Brien-Núñez` folds to `jose obrien nunez`.
#[must_use]
pub fn fold(text: &str) -> String {
    let mut folded = String::with_capacity(text.len());
    for character in text.chars().flat_map(char::to_lowercase) {
        match character {
            '\'' | '\u{2019}' | '`' | '.' => {}
            _ if character.is_ascii_alphanumeric() => folded.push(character),
            _ => match base_letters(character) {
                Some(base) => folded.push_str(base),
                None if character.is_alphanumeric() => folded.push(character),
                None => folded.push(' '),
            },
        }
    }
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn base_letters(character: char) -> Option<&'static str> {
    Some(match character {
        'á' | 'à' | 'â' | 'ä' | 'ã' | 'å' | 'ā' | 'ă' | 'ą' => "a",
        'ç' | 'ć' | 'č' => "c",
        'ď' | 'ð' | 'đ' => "d",
        'é' | 'è' | 'ê' | 'ë' | 'ē' | 'ę' | 'ě' => "e",
        'ğ' => "g",
        'í' | 'ì' | 'î' | 'ï' | 'ī' | 'ı' => "i",
        'ł' => "l",
        'ñ' | 'ń' | 'ň' => "n",
        'ó' | 'ò' | 'ô' | 'ö' | 'õ' | 'ø' | 'ō' | 'ő' => "o",
        'ř' => "r",
        'ś' | 'š' | 'ș' | 'ş' => "s",
        'ť' | 'ț' | 'ţ' => "t",
        'ú' | 'ù' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' => "u",
        'ý' | 'ÿ' => "y",
        'ź' | 'ż' | 'ž' => "z",
        'ß' => "ss",
        'æ' => "ae",
        'œ' => "oe",
        'þ' => "th",
        _ => return None,
    })
}

/// Jaro-Winkler similarity, from 0.0 (nothing in common) to 1.0 (identical).
///
/// Counts characters that match within a sliding window and penalises those out of
/// order, then rewards a shared prefix: typing errors rarely hit the first letters.
#[must_use]
pub fn jaro_winkler(left: &str, right: &str) -> f64 {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    if left.is_empty() || right.is_empty() {
        return if left == right { 1.0 } else { 0.0 };
    }
    let window = (left.len().max(right.len()) / 2).saturating_sub(1);
    let mut right_used = vec![false; right.len()];
    let mut left_matches = Vec::new();
    for (index, character) in left.iter().enumerate() {
        let start = index.saturating_sub(window);
        let end = (index + window + 1).min(right.len());
        if let Some(found) =
            (start..end).find(|other| !right_used[*other] && right[*other] == *character)
        {
            right_used[found] = true;
            left_matches.push(*character);
        }
    }
    if left_matches.is_empty() {
        return 0.0;
    }
    let right_matches = right
        .iter()
        .zip(&right_used)
        .filter(|(_, used)| **used)
        .map(|(character, _)| character);
    let out_of_order = left_matches
        .iter()
        .zip(right_matches)
        .filter(|(a, b)| a != b)
        .count();
    #[allow(clippy::cast_precision_loss)]
    let (matches, transpositions) = (left_matches.len() as f64, (out_of_order / 2) as f64);
    #[allow(clippy::cast_precision_loss)]
    let jaro = (matches / left.len() as f64
        + matches / right.len() as f64
        + (matches - transpositions) / matches)
        / 3.0;
    let prefix = left
        .iter()
        .zip(&right)
        .take(4)
        .take_while(|(a, b)| a == b)
        .count();
    #[allow(clippy::cast_precision_loss)]
    let boost = prefix as f64 * 0.1 * (1.0 - jaro);
    jaro + boost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_case_accents_and_punctuation() {
        assert_eq!(fold("José O'Brien-Núñez"), "jose obrien nunez");
        assert_eq!(fold("  STRAßE,  Æther "), "strasse aether");
        assert_eq!(fold("St. John"), "st john");
        assert_eq!(fold("李 小龍"), "李 小龍");
    }

    #[test]
    fn similarity_matches_published_examples() {
        let close = |left, right, expected: f64| {
            let actual = jaro_winkler(left, right);
            assert!(
                (actual - expected).abs() < 0.001,
                "{left}/{right}: {actual}"
            );
        };
        close("martha", "marhta", 0.961);
        close("dixon", "dicksonx", 0.813);
        close("jellyfish", "smellyfish", 0.896);
        close("same", "same", 1.0);
        close("abc", "xyz", 0.0);
        close("", "", 1.0);
        close("a", "", 0.0);
    }
}
