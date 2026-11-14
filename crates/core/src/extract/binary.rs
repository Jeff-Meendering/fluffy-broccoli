use super::ExtractionContext;
use crate::{
    AttentionItem, CoordinateUnit, EvidenceKind, EvidenceOrigin, ExtractedPart, Extraction,
};

const MINIMUM_RUN: usize = 6;
const SEGMENT_CHARS: usize = 24_000;
const OVERLAP_CHARS: usize = 512;
const CANCELLATION_MASK: usize = 0xfff;

/// Recover printable ASCII and UTF-16LE strings without combining unrelated byte ranges.
///
/// `chunk_start` is always an original byte offset. ASCII chunks have stride one and
/// UTF-16LE chunks have stride two, so detector offsets map back to the input exactly.
pub fn extract(name: &str, data: &[u8], context: &ExtractionContext) -> Extraction {
    let mut result = Extraction {
        partial: true,
        ..Extraction::default()
    };
    if context.is_cancelled() {
        cancelled(name, &mut result);
        return result;
    }

    let mut narrow = Run::new("ASCII", 1);
    let mut wide = Run::new("UTF-16LE", 2);
    let mut expect_high = false;
    let mut pending_wide = 0_u8;

    for (index, &byte) in data.iter().enumerate() {
        if index & CANCELLATION_MASK == 0 && context.is_cancelled() {
            cancelled(name, &mut result);
            return result;
        }

        let offset = index as u64;
        let printable = is_printable(byte);
        if printable {
            if !narrow.append(byte, offset, name, context, &mut result) {
                return result;
            }
        } else if !narrow.flush(name, context, &mut result) {
            return result;
        }

        if expect_high {
            if byte == 0 {
                if !wide.append(pending_wide, offset - 1, name, context, &mut result) {
                    return result;
                }
            } else if !wide.flush(name, context, &mut result) {
                return result;
            }
        } else if !printable && !wide.flush(name, context, &mut result) {
            return result;
        }

        expect_high = printable;
        if printable {
            pending_wide = byte;
        }
    }

    if context.is_cancelled() {
        cancelled(name, &mut result);
    } else if narrow.flush(name, context, &mut result) {
        wide.flush(name, context, &mut result);
    }
    result
}

const fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t')
}

struct Run {
    encoding: &'static str,
    stride: u32,
    text: Vec<u8>,
    start: u64,
    fresh: usize,
    continued: bool,
}

impl Run {
    fn new(encoding: &'static str, stride: u32) -> Self {
        Self {
            encoding,
            stride,
            text: Vec::with_capacity(SEGMENT_CHARS),
            start: 0,
            fresh: 0,
            continued: false,
        }
    }

    fn append(
        &mut self,
        byte: u8,
        offset: u64,
        name: &str,
        context: &ExtractionContext,
        result: &mut Extraction,
    ) -> bool {
        if self.text.is_empty() {
            self.start = offset;
        }
        self.text.push(byte);
        self.fresh += 1;
        if self.text.len() < SEGMENT_CHARS {
            return true;
        }

        // Prefer a nearby word boundary so a cut cannot create a plausible but false
        // identifier prefix. The next segment still overlaps the real identifier.
        let mut end = SEGMENT_CHARS;
        while end > SEGMENT_CHARS - OVERLAP_CHARS && !matches!(self.text[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        if end == SEGMENT_CHARS - OVERLAP_CHARS {
            end = SEGMENT_CHARS;
        }
        if !self.emit(end, true, name, context, result) {
            return false;
        }

        self.fresh = self.fresh.min(self.text.len() - end);
        let consumed = end - OVERLAP_CHARS;
        self.text.drain(..consumed);
        self.start += consumed as u64 * u64::from(self.stride);
        self.continued = true;
        true
    }

    fn flush(&mut self, name: &str, context: &ExtractionContext, result: &mut Extraction) -> bool {
        let should_emit = self.text.len() >= MINIMUM_RUN && self.fresh > 0;
        if should_emit && !self.emit(self.text.len(), false, name, context, result) {
            return false;
        }
        self.text.clear();
        self.fresh = 0;
        self.continued = false;
        true
    }

    fn emit(
        &mut self,
        length: usize,
        continues_after: bool,
        name: &str,
        context: &ExtractionContext,
        result: &mut Extraction,
    ) -> bool {
        let mut emitted = length;
        let mut limited = false;
        if !context.reserve_extracted_utf16(length) {
            // The context exposes atomic all-or-nothing reservations. If a whole chunk
            // does not fit, consume only the final remaining units one at a time. Failed
            // reservations do not alter the shared counter, and this fills the cap exactly.
            emitted = 0;
            while emitted < length && context.reserve_extracted_utf16(1) {
                emitted += 1;
            }
            limited = true;
        }

        if emitted > 0 {
            let mut text = String::new();
            if text.try_reserve(emitted).is_err() {
                result.attention.push(AttentionItem {
                    resource_id: name.to_owned(),
                    message: "Binary string output allocation failed; remaining content unchecked."
                        .into(),
                });
                return false;
            }
            text.extend(self.text[..emitted].iter().copied().map(char::from));
            let origin = EvidenceOrigin {
                resource_id: name.to_owned(),
                stream_id: format!("binary:{}", self.encoding),
                kind: EvidenceKind::BinaryStrings,
                representation: "binary-text".into(),
                chunk_start: self.start,
                coordinate_unit: CoordinateUnit::Bytes,
                stride: self.stride,
            };
            result.parts.push(
                ExtractedPart::new(text, origin)
                    .with_continuations(self.continued, continues_after || limited)
                    .at(format!(
                        "binary strings · byte {} ({})",
                        self.start, self.encoding
                    )),
            );
        }

        if limited {
            result.attention.push(AttentionItem {
                resource_id: name.to_owned(),
                message: "Binary string extraction limit reached; remaining content unchecked."
                    .into(),
            });
            return false;
        }
        true
    }
}

fn cancelled(name: &str, result: &mut Extraction) {
    result.attention.push(AttentionItem {
        resource_id: name.to_owned(),
        message: "Extraction cancelled or timed out; content was not fully checked.".into(),
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::ScanOptions;

    use super::*;

    fn context(max_extracted_utf16: usize) -> ExtractionContext {
        let options = ScanOptions {
            max_extracted_utf16,
            ..ScanOptions::default()
        };
        ExtractionContext::for_root(Arc::new(options), Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn runs_keep_encoding_and_exact_original_byte_offsets() {
        let ascii = b"alice@example.com";
        let wide: Vec<u8> = "bob@example.net"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut bytes = vec![0, 0, 0];
        bytes.extend_from_slice(ascii);
        bytes.extend_from_slice(&[0, 0]);
        let wide_start = bytes.len() as u64;
        bytes.extend_from_slice(&wide);
        bytes.extend_from_slice(&[0, 0]);

        let result = extract("root", &bytes, &context(1_000_000));
        let first = result
            .parts
            .iter()
            .find(|part| part.text == "alice@example.com")
            .unwrap();
        let second = result
            .parts
            .iter()
            .find(|part| part.text == "bob@example.net")
            .unwrap();
        assert_eq!(first.origin.chunk_start, 3);
        assert_eq!(first.origin.stride, 1);
        assert_eq!(first.origin.coordinate_unit, CoordinateUnit::Bytes);
        assert_eq!(second.origin.chunk_start, wide_start);
        assert_eq!(second.origin.stride, 2);
        assert_eq!(
            second.location.as_deref(),
            Some(format!("binary strings · byte {wide_start} (UTF-16LE)").as_str())
        );
        assert!(result.attention.is_empty());
    }

    #[test]
    fn separated_runs_do_not_invent_context_across_gaps() {
        let mut bytes = b"patient number:".to_vec();
        bytes.extend_from_slice(&[0, 1, 0]);
        bytes.extend_from_slice(b"123456");
        let result = extract("root", &bytes, &context(1_000));
        let texts: Vec<_> = result.parts.iter().map(|part| part.text.as_str()).collect();
        assert_eq!(texts, ["patient number:", "123456"]);
    }

    #[test]
    fn output_limit_is_strict_including_overlaps_and_the_final_run() {
        for wide in [false, true] {
            let text = "x".repeat(100_000);
            let bytes = if wide {
                text.encode_utf16().flat_map(u16::to_le_bytes).collect()
            } else {
                text.into_bytes()
            };
            let result = extract("root", &bytes, &context(50_000));
            assert_eq!(
                result
                    .parts
                    .iter()
                    .map(|part| part.text.len())
                    .sum::<usize>(),
                50_000
            );
            assert_eq!(result.attention.len(), 1);
            assert!(
                result
                    .parts
                    .iter()
                    .all(|part| part.text.len() <= SEGMENT_CHARS)
            );
        }
    }

    #[test]
    fn overlap_retains_an_identifier_and_maps_each_chunk_to_original_bytes() {
        let text = format!("{} alice@example.com tail", "x".repeat(23_989));
        let result = extract("root", text.as_bytes(), &context(200_000));
        assert!(
            result
                .parts
                .iter()
                .any(|part| part.text.contains("alice@example.com"))
        );
        for part in &result.parts {
            let offset = part.origin.chunk_start as usize;
            assert_eq!(
                part.text.as_bytes(),
                &text.as_bytes()[offset..offset + part.text.len()]
            );
        }
    }

    #[test]
    fn a_short_final_run_is_still_recovered() {
        let result = extract("root", b"abc\0abcdef\0", &context(100));
        assert_eq!(
            result
                .parts
                .iter()
                .map(|part| part.text.as_str())
                .collect::<Vec<_>>(),
            ["abcdef"]
        );
    }

    #[test]
    fn pre_cancelled_input_emits_attention_without_scanning() {
        let options = Arc::new(ScanOptions::default());
        let context = ExtractionContext::for_root(options, Arc::new(AtomicBool::new(true)));
        let result = extract("root", b"abcdef", &context);
        assert!(result.parts.is_empty());
        assert_eq!(result.attention.len(), 1);
    }
}
