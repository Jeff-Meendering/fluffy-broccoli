//! A small pull parser for the XML found inside office documents.
//!
//! It tokenizes well-formed UTF-8 XML into start tags, end tags and text. It never
//! resolves external entities or document type declarations, so entity-expansion and
//! external-fetch attacks have nothing to act on.

use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    Start {
        name: &'a str,
        attributes: &'a str,
        /// True for `<tag/>`, which has no matching end event.
        empty: bool,
    },
    End {
        name: &'a str,
    },
    Text {
        raw: &'a str,
        /// True for CDATA sections, whose content is literal.
        literal: bool,
    },
}

impl Event<'_> {
    /// Decoded character data for a text event; empty for tags.
    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        match self {
            Self::Text { raw, literal: true } => Cow::Borrowed(raw),
            Self::Text {
                raw,
                literal: false,
            } => unescape(raw),
            _ => Cow::Borrowed(""),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed {
    pub offset: usize,
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "malformed XML at byte {}", self.offset)
    }
}

pub struct Reader<'a> {
    input: &'a str,
    position: usize,
    failed: bool,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self {
            input: input.strip_prefix('\u{feff}').unwrap_or(input),
            position: 0,
            failed: false,
        }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.position..]
    }

    /// Advances past `terminator`, returning the text before it.
    fn take_until(&mut self, skip: usize, terminator: &str) -> Option<&'a str> {
        let body = &self.rest()[skip..];
        let end = body.find(terminator)?;
        self.position += skip + end + terminator.len();
        Some(&body[..end])
    }

    fn skip_declaration(&mut self) -> Option<()> {
        // `<!DOCTYPE ... [ internal subset ] >`: skipped whole, never interpreted.
        let mut depth = 0_usize;
        for (index, character) in self.rest().char_indices() {
            match character {
                '[' => depth += 1,
                ']' => depth = depth.saturating_sub(1),
                '>' if depth == 0 => {
                    self.position += index + 1;
                    return Some(());
                }
                _ => {}
            }
        }
        None
    }

    fn tag(&mut self) -> Option<Event<'a>> {
        let rest = self.rest();
        let mut quote = None;
        let mut close = None;
        for (index, character) in rest.char_indices().skip(1) {
            match (quote, character) {
                (None, '"' | '\'') => quote = Some(character),
                (Some(open), _) if open == character => quote = None,
                (None, '>') => {
                    close = Some(index);
                    break;
                }
                _ => {}
            }
        }
        let close = close?;
        let body = &rest[1..close];
        self.position += close + 1;
        if let Some(name) = body.strip_prefix('/') {
            return Some(Event::End { name: name.trim() });
        }
        let (body, empty) = match body.strip_suffix('/') {
            Some(inner) => (inner, true),
            None => (body, false),
        };
        let split = body.find(char::is_whitespace).unwrap_or(body.len());
        let name = &body[..split];
        if name.is_empty() {
            return None;
        }
        Some(Event::Start {
            name,
            attributes: body[split..].trim(),
            empty,
        })
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Event<'a>, Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.failed || self.position >= self.input.len() {
                return None;
            }
            let start = self.position;
            let rest = self.rest();
            let step = if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                self.position += end;
                Some(Some(Event::Text {
                    raw: &rest[..end],
                    literal: false,
                }))
            } else if rest.starts_with("<!--") {
                self.take_until(4, "-->").map(|_| None)
            } else if rest.starts_with("<![CDATA[") {
                self.take_until(9, "]]>")
                    .map(|raw| Some(Event::Text { raw, literal: true }))
            } else if rest.starts_with("<?") {
                self.take_until(2, "?>").map(|_| None)
            } else if rest.starts_with("<!") {
                self.skip_declaration().map(|()| None)
            } else {
                self.tag().map(Some)
            };
            match step {
                Some(Some(event)) => return Some(Ok(event)),
                Some(None) => {}
                None => {
                    self.failed = true;
                    return Some(Err(Malformed { offset: start }));
                }
            }
        }
    }
}

/// The part of a qualified name after its namespace prefix.
#[must_use]
pub fn local_name(name: &str) -> &str {
    name.rsplit_once(':').map_or(name, |(_, local)| local)
}

/// Looks up an attribute by local name in the raw attribute text of a start tag.
#[must_use]
pub fn attribute(attributes: &str, wanted: &str) -> Option<String> {
    let mut rest = attributes.trim_start();
    while !rest.is_empty() {
        let name_end =
            rest.find(|character: char| character == '=' || character.is_whitespace())?;
        let name = &rest[..name_end];
        rest = rest[name_end..]
            .trim_start()
            .strip_prefix('=')?
            .trim_start();
        let quote = rest
            .chars()
            .next()
            .filter(|character| matches!(character, '"' | '\''))?;
        let value_end = rest[1..].find(quote)?;
        let value = &rest[1..=value_end];
        if local_name(name) == wanted {
            return Some(unescape(value).into_owned());
        }
        rest = rest[value_end + 2..].trim_start();
    }
    None
}

/// Replaces the five predefined entities and numeric character references.
///
/// Unknown entities are kept as written: there is no document type to define them.
#[must_use]
pub fn unescape(text: &str) -> Cow<'_, str> {
    if !text.contains('&') {
        return Cow::Borrowed(text);
    }
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        rest = &rest[start..];
        let replaced = rest[1..]
            .find(';')
            .filter(|end| *end <= 10)
            .and_then(|end| decode_entity(&rest[1..=end]).map(|character| (character, end + 2)));
        match replaced {
            Some((character, consumed)) => {
                output.push(character);
                rest = &rest[consumed..];
            }
            None => {
                output.push('&');
                rest = &rest[1..];
            }
        }
    }
    output.push_str(rest);
    Cow::Owned(output)
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let number = entity.strip_prefix('#')?;
            let code = match number.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => number.parse().ok()?,
            };
            char::from_u32(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(input: &str) -> Vec<Event<'_>> {
        Reader::new(input).collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn tokenizes_tags_text_and_empty_elements() {
        let parsed = events(r#"<?xml version="1.0"?><a x="1"><b/>hi &amp; bye</a>"#);
        assert_eq!(
            parsed,
            vec![
                Event::Start {
                    name: "a",
                    attributes: r#"x="1""#,
                    empty: false
                },
                Event::Start {
                    name: "b",
                    attributes: "",
                    empty: true
                },
                Event::Text {
                    raw: "hi &amp; bye",
                    literal: false
                },
                Event::End { name: "a" },
            ]
        );
        assert_eq!(parsed[2].text(), "hi & bye");
    }

    #[test]
    fn skips_comments_and_doctype_without_expanding_entities() {
        let input = "<!DOCTYPE a [<!ENTITY big \"&big;&big;\">]><!-- note --><a>&big;</a>";
        let parsed = events(input);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[1].text(), "&big;");
    }

    #[test]
    fn keeps_cdata_literal_and_allows_angle_brackets_in_attribute_values() {
        let parsed = events(r#"<a note="1 > 0"><![CDATA[<raw> & text]]></a>"#);
        assert_eq!(parsed[1].text(), "<raw> & text");
        let Event::Start { attributes, .. } = parsed[0] else {
            panic!("expected a start tag");
        };
        assert_eq!(attribute(attributes, "note").as_deref(), Some("1 > 0"));
    }

    #[test]
    fn reads_attributes_by_local_name_with_either_quote() {
        let attributes = r#"name="Staff &amp; Pay" sheetId='3' r:id="rId7""#;
        assert_eq!(
            attribute(attributes, "name").as_deref(),
            Some("Staff & Pay")
        );
        assert_eq!(attribute(attributes, "sheetId").as_deref(), Some("3"));
        assert_eq!(attribute(attributes, "id").as_deref(), Some("rId7"));
        assert_eq!(attribute(attributes, "missing"), None);
    }

    #[test]
    fn decodes_numeric_references_and_leaves_unknown_entities() {
        assert_eq!(unescape("&#65;&#x42;&lt;&nbsp;&"), "AB<&nbsp;&");
    }

    #[test]
    fn reports_unterminated_markup_once() {
        let mut reader = Reader::new("<a><b");
        assert!(matches!(
            reader.next(),
            Some(Ok(Event::Start { name: "a", .. }))
        ));
        assert_eq!(reader.next(), Some(Err(Malformed { offset: 3 })));
        assert_eq!(reader.next(), None);
    }
}
