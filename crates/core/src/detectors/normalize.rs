use std::borrow::Cow;

use super::EntitySpan;

/// A narrow detection view over the original evidence.
///
/// Only format controls, full-width ASCII, dash variants, Unicode space separators,
/// and decimal digits are changed. In particular, this does not perform NFKC,
/// case-folding, accent removal, or homoglyph guessing.
pub(super) struct DetectionText<'a> {
    original: &'a str,
    text: Cow<'a, str>,
    /// For each byte in `text`, the half-open byte range in `original` that produced it.
    offsets: Option<Vec<(usize, usize)>>,
}

impl<'a> DetectionText<'a> {
    pub(super) fn new(original: &'a str) -> Self {
        // The overwhelmingly common ASCII case needs no copy and no offset table.
        if original.is_ascii() {
            return Self {
                original,
                text: Cow::Borrowed(original),
                offsets: None,
            };
        }

        let mut normalized: Option<(String, Vec<(usize, usize)>)> = None;
        for (index, source) in original.char_indices() {
            let mapped = map_char(source);
            if normalized.is_none() && mapped == Some(source) {
                continue;
            }
            let (text, offsets) = normalized.get_or_insert_with(|| {
                let mut text = String::with_capacity(original.len());
                let mut offsets = Vec::with_capacity(original.len());
                for (prefix_index, c) in original[..index].char_indices() {
                    text.push(c);
                    let range = (prefix_index, prefix_index + c.len_utf8());
                    offsets.extend(std::iter::repeat_n(range, c.len_utf8()));
                }
                (text, offsets)
            });
            if let Some(mapped) = mapped {
                let mut encoded = [0; 4];
                let encoded = mapped.encode_utf8(&mut encoded);
                text.push_str(encoded);
                let range = (index, index + source.len_utf8());
                offsets.extend(std::iter::repeat_n(range, encoded.len()));
            }
        }

        if let Some((text, offsets)) = normalized {
            Self {
                original,
                text: Cow::Owned(text),
                offsets: Some(offsets),
            }
        } else {
            Self {
                original,
                text: Cow::Borrowed(original),
                offsets: None,
            }
        }
    }

    pub(super) fn text(&self) -> &str {
        &self.text
    }

    pub(super) fn original_span(&self, span: EntitySpan) -> EntitySpan {
        let Some(offsets) = &self.offsets else {
            return span;
        };
        if span.length == 0 {
            return span;
        }
        let normalized_end = span.start + span.length;
        let Some(&(start, _)) = offsets.get(span.start) else {
            return span;
        };
        let Some(&(_, end)) = offsets.get(normalized_end - 1) else {
            return span;
        };
        let normalized = &self.text[span.start..normalized_end];
        let changed = self.original.get(start..end) != Some(normalized);
        EntitySpan {
            start,
            length: end - start,
            method: if changed && !span.method.ends_with(" (Unicode normalized)") {
                format!("{} (Unicode normalized)", span.method)
            } else {
                span.method
            },
            ..span
        }
    }
}

fn map_char(c: char) -> Option<char> {
    match c {
        '\u{00ad}'
        | '\u{200b}'
        | '\u{200c}'
        | '\u{200d}'
        | '\u{200e}'
        | '\u{200f}'
        | '\u{2060}'
        | '\u{feff}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' => None,
        '\u{ff01}'..='\u{ff5e}' => Some(char::from((c as u32 - 0xfee0) as u8)),
        '\u{2010}'..='\u{2015}' | '\u{2212}' => Some('-'),
        '\u{00a0}'
        | '\u{1680}'
        | '\u{2000}'..='\u{200a}'
        | '\u{202f}'
        | '\u{205f}'
        | '\u{3000}' => Some(' '),
        _ if c > '\u{7f}' => decimal_digit(c)
            .map(|digit| char::from(b'0' + digit))
            .or(Some(c)),
        _ => Some(c),
    }
}

/// Unicode Nd blocks are ten contiguous code points, apart from mathematical digits,
/// which are five adjacent alphabets of ten digits.
fn decimal_digit(c: char) -> Option<u8> {
    const ZEROS: &[u32] = &[
        0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66, 0x0ce6,
        0x0d66, 0x0de6, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0,
        0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0,
        0xaa50, 0xabf0, 0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0,
        0x11450, 0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116e0, 0x11730, 0x118e0, 0x11950, 0x11bf0,
        0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16a60, 0x16ac0, 0x16b50, 0x1ccf0, 0x1e140, 0x1e2f0,
        0x1e4f0, 0x1e950, 0x1fbf0,
    ];
    let value = c as u32;
    if (0x1d7ce..=0x1d7ff).contains(&value) {
        return Some(((value - 0x1d7ce) % 10) as u8);
    }
    ZEROS
        .binary_search_by(|zero| {
            if value < *zero {
                std::cmp::Ordering::Greater
            } else if value >= *zero + 10 {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|index| (value - ZEROS[index]) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityType;

    #[test]
    fn ascii_detection_borrows_the_input() {
        let input = "alice@example.com";
        let view = DetectionText::new(input);
        assert!(matches!(view.text, Cow::Borrowed(_)));
        assert_eq!(view.text(), input);
    }

    #[test]
    fn narrow_normalization_does_not_fold_homoglyphs_or_accents() {
        let input = "Ｊosé ａ@ｅxämple.com";
        let view = DetectionText::new(input);
        assert_eq!(view.text(), "José a@exämple.com");
        let unchanged = DetectionText::new("josé@exämple.org");
        assert!(matches!(unchanged.text, Cow::Borrowed(_)));
        let homoglyph = DetectionText::new("аlice@example.com");
        assert_eq!(homoglyph.text(), "аlice@example.com");
    }

    #[test]
    fn removed_and_reencoded_characters_map_to_original_byte_spans() {
        let input = "emoji 😀 ａli\u{200b}ce＠example.com";
        let view = DetectionText::new(input);
        let start = view.text().find('a').unwrap_or_default();
        let span = EntitySpan::new(
            EntityType::Email,
            start,
            view.text().len() - start,
            0.99,
            "Pattern",
        );
        let mapped = view.original_span(span);
        assert_eq!(
            &input[mapped.start..mapped.start + mapped.length],
            "ａli\u{200b}ce＠example.com"
        );
        assert_eq!(mapped.method, "Pattern (Unicode normalized)");
    }

    #[test]
    fn unicode_decimal_blocks_map_without_guessing_other_numbers() {
        let view = DetectionText::new("١٢٣ ４５𝟞 Ⅻ");
        assert_eq!(view.text(), "123 456 Ⅻ");
    }

    #[test]
    fn normalization_outside_a_finding_does_not_change_its_method() {
        let input = "note\u{200b}: alice@example.com";
        let view = DetectionText::new(input);
        let start = view.text().find("alice").unwrap_or_default();
        let span = EntitySpan::new(EntityType::Email, start, 17, 0.99, "Pattern");
        let mapped = view.original_span(span);
        assert_eq!(mapped.method, "Pattern");
        assert_eq!(
            &input[mapped.start..mapped.start + mapped.length],
            "alice@example.com"
        );
    }
}
