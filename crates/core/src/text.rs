//! Text coordinates and bounded, overlapping chunking.
//!
//! Public findings retain the original application's UTF-16 offsets. Internally, all
//! slices are valid UTF-8 and detector spans are byte offsets until they are published.

use serde::{Deserialize, Serialize};

const INDEX_INTERVAL: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checkpoint {
    byte: usize,
    utf16: usize,
}

/// A sparse index for converting between UTF-8 byte and UTF-16 code-unit offsets.
///
/// Conversion scans at most 256 bytes rather than allocating a per-byte lookup table.
#[derive(Debug, Clone)]
pub struct Utf16Index<'a> {
    text: &'a str,
    checkpoints: Vec<Checkpoint>,
    utf16_len: usize,
}

impl<'a> Utf16Index<'a> {
    #[must_use]
    pub fn new(text: &'a str) -> Self {
        let mut checkpoints = Vec::with_capacity(text.len() / INDEX_INTERVAL + 2);
        let mut utf16 = 0;
        let mut next_checkpoint = INDEX_INTERVAL;
        checkpoints.push(Checkpoint { byte: 0, utf16: 0 });

        for (byte, character) in text.char_indices() {
            if byte >= next_checkpoint {
                checkpoints.push(Checkpoint { byte, utf16 });
                next_checkpoint = byte + INDEX_INTERVAL;
            }
            utf16 += character.len_utf16();
        }

        Self {
            text,
            checkpoints,
            utf16_len: utf16,
        }
    }

    #[must_use]
    pub const fn utf16_len(&self) -> usize {
        self.utf16_len
    }

    /// Converts a UTF-8 character boundary to a UTF-16 code-unit offset.
    #[must_use]
    pub fn utf16_offset(&self, byte_offset: usize) -> Option<usize> {
        if byte_offset > self.text.len() || !self.text.is_char_boundary(byte_offset) {
            return None;
        }

        let checkpoint = self.checkpoint_for_byte(byte_offset);
        let units = self.text[checkpoint.byte..byte_offset]
            .chars()
            .map(char::len_utf16)
            .sum::<usize>();
        Some(checkpoint.utf16 + units)
    }

    /// Converts a UTF-16 offset to a UTF-8 byte offset.
    ///
    /// Returns `None` when the offset is past the end or splits a surrogate pair.
    #[must_use]
    pub fn byte_offset(&self, utf16_offset: usize) -> Option<usize> {
        if utf16_offset > self.utf16_len {
            return None;
        }
        let index = self
            .checkpoints
            .partition_point(|checkpoint| checkpoint.utf16 <= utf16_offset);
        let checkpoint = self.checkpoints[index.saturating_sub(1)];
        let mut units = checkpoint.utf16;
        if units == utf16_offset {
            return Some(checkpoint.byte);
        }

        for (relative, character) in self.text[checkpoint.byte..].char_indices() {
            if units == utf16_offset {
                return Some(checkpoint.byte + relative);
            }
            let next = units + character.len_utf16();
            if next > utf16_offset {
                return None;
            }
            units = next;
        }
        (units == utf16_offset).then_some(self.text.len())
    }

    /// Returns a character-boundary byte offset no later than `utf16_offset`.
    #[must_use]
    pub fn byte_offset_floor(&self, utf16_offset: usize) -> usize {
        let target = utf16_offset.min(self.utf16_len);
        let index = self
            .checkpoints
            .partition_point(|checkpoint| checkpoint.utf16 <= target);
        let checkpoint = self.checkpoints[index.saturating_sub(1)];
        let mut units = checkpoint.utf16;
        let mut byte = checkpoint.byte;
        for (relative, character) in self.text[checkpoint.byte..].char_indices() {
            if units + character.len_utf16() > target {
                break;
            }
            units += character.len_utf16();
            byte = checkpoint.byte + relative + character.len_utf8();
            if units == target {
                break;
            }
        }
        byte
    }

    #[must_use]
    pub fn slice(&self, start: usize, length: usize) -> Option<&'a str> {
        let end = start.checked_add(length)?;
        let start_byte = self.byte_offset(start)?;
        let end_byte = self.byte_offset(end)?;
        self.text.get(start_byte..end_byte)
    }

    /// Returns surrounding evidence without discarding line breaks or changing coordinates.
    #[must_use]
    pub fn context(
        &self,
        start: usize,
        length: usize,
        before: usize,
        after: usize,
    ) -> Option<(usize, &'a str)> {
        let context_start = start.saturating_sub(before);
        let context_end = start
            .checked_add(length)?
            .checked_add(after)?
            .min(self.utf16_len);
        // Context edges may land inside an emoji's surrogate pair even when the finding
        // itself is valid. Round outwards instead of losing all surrounding evidence.
        let start_byte = self.byte_offset_floor(context_start);
        let mut end_byte = self.byte_offset_floor(context_end);
        if self.utf16_offset(end_byte)? < context_end {
            end_byte += self.text[end_byte..].chars().next()?.len_utf8();
        }
        Some((
            self.utf16_offset(start_byte)?,
            &self.text[start_byte..end_byte],
        ))
    }

    /// Splits text into bounded chunks with overlap, always covering the tail.
    #[must_use]
    pub fn chunks(&self, max_units: usize, overlap_units: usize) -> Vec<TextChunk<'a>> {
        assert!(max_units > 0, "chunk size must be positive");
        let overlap = overlap_units.min(max_units.saturating_sub(1));
        if self.utf16_len <= max_units {
            return vec![TextChunk {
                text: self.text,
                byte_start: 0,
                utf16_start: 0,
            }];
        }

        let estimated = self.utf16_len.div_ceil(max_units - overlap) + 1;
        let mut chunks = Vec::with_capacity(estimated);
        let mut start_units = 0;
        let mut start_byte = 0;

        while start_byte < self.text.len() {
            let remaining = self.utf16_len - start_units;
            if remaining <= max_units {
                chunks.push(TextChunk {
                    text: &self.text[start_byte..],
                    byte_start: start_byte,
                    utf16_start: start_units,
                });
                break;
            }

            let target_end = start_units + max_units;
            let mut end_byte = self.byte_offset_floor(target_end);
            if end_byte <= start_byte {
                end_byte = self.text[start_byte..]
                    .char_indices()
                    .nth(1)
                    .map_or(self.text.len(), |(relative, _)| start_byte + relative);
            }
            let actual_units = self.utf16_offset(end_byte).unwrap_or(target_end);
            chunks.push(TextChunk {
                text: &self.text[start_byte..end_byte],
                byte_start: start_byte,
                utf16_start: start_units,
            });

            if end_byte == self.text.len() {
                break;
            }
            let next_units = actual_units.saturating_sub(overlap);
            let next_byte = self.byte_offset_floor(next_units);
            if next_byte <= start_byte {
                start_byte = end_byte;
                start_units = actual_units;
            } else {
                start_byte = next_byte;
                start_units = self.utf16_offset(next_byte).unwrap_or(next_units);
            }
        }
        chunks
    }

    fn checkpoint_for_byte(&self, byte_offset: usize) -> Checkpoint {
        let index = self
            .checkpoints
            .partition_point(|checkpoint| checkpoint.byte <= byte_offset);
        self.checkpoints[index.saturating_sub(1)]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextChunk<'a> {
    pub text: &'a str,
    pub byte_start: usize,
    pub utf16_start: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_coordinates_are_zero_copy_compatible() {
        let index = Utf16Index::new("alice@example.com");
        assert_eq!(index.utf16_len(), 17);
        assert_eq!(index.utf16_offset(8), Some(8));
        assert_eq!(index.byte_offset(17), Some(17));
        assert_eq!(index.slice(0, 5), Some("alice"));
    }

    #[test]
    fn emoji_and_combining_text_keep_utf16_coordinates() {
        let text = "A😀B Nguyen\u{0303} C";
        let index = Utf16Index::new(text);
        assert_eq!(index.utf16_offset(0), Some(0));
        assert_eq!(index.utf16_offset(1), Some(1));
        assert_eq!(index.utf16_offset(5), Some(3));
        assert_eq!(index.byte_offset(2), None);
        assert_eq!(index.slice(3, 1), Some("B"));
        assert_eq!(index.byte_offset(index.utf16_len()), Some(text.len()));
    }

    #[test]
    fn sparse_index_handles_long_unicode_text() {
        let text = "a😀é".repeat(1_000);
        let index = Utf16Index::new(&text);
        for (byte, _) in text.char_indices() {
            let units = index.utf16_offset(byte).expect("valid character boundary");
            assert_eq!(index.byte_offset(units), Some(byte));
        }
    }

    #[test]
    fn chunks_cover_every_character_and_never_split_a_surrogate_pair() {
        let text = "start😀".to_owned() + &"abcdef".repeat(100) + "tail@example.com";
        let index = Utf16Index::new(&text);
        let chunks = index.chunks(31, 5);
        assert!(chunks.len() > 2);
        assert_eq!(chunks[0].utf16_start, 0);
        assert_eq!(
            chunks
                .last()
                .map(|chunk| chunk.text.ends_with("tail@example.com")),
            Some(true)
        );
        for pair in chunks.windows(2) {
            assert!(pair[1].utf16_start < pair[0].utf16_start + 31);
            assert!(pair[1].byte_start > pair[0].byte_start);
        }
        for chunk in chunks {
            assert!(chunk.text.len() <= 31 * 4);
            assert_eq!(
                &text[chunk.byte_start..chunk.byte_start + chunk.text.len()],
                chunk.text
            );
        }
    }

    #[test]
    fn empty_and_short_inputs_have_one_bounded_chunk() {
        assert_eq!(Utf16Index::new("").chunks(10, 2).len(), 1);
        assert_eq!(Utf16Index::new("short").chunks(10, 2).len(), 1);
    }
}
