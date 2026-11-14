use std::io::{self, BufRead};
use std::path::PathBuf;

use pii_explorer_core::{AttentionItem, EvidenceOrigin, ScanOptions};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 2;
pub const MAX_FRAME: usize = 1024 * 1024;
pub const MAX_RESPONSE: usize = 256 * 1024 * 1024;
pub const MAX_RECORDS: usize = 200_000;
pub const MAX_REQUESTS: usize = 128;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub name: String,
    pub length: u64,
    pub options: ScanOptions,
    pub tesseract_path: Option<PathBuf>,
    pub tessdata_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Part {
        origin: EvidenceOrigin,
        location: Option<String>,
        continues_before: bool,
        continues_after: bool,
    },
    Text {
        text: String,
    },
    PartEnd,
    Attention(AttentionItem),
    End {
        version: u32,
        partial: bool,
    },
}

/// Unlike read_line, an untrusted peer cannot cause an unlimited allocation.
pub fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::other("truncated worker frame"))
            };
        }
        let length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(length) > MAX_FRAME {
            return Err(io::Error::other("worker frame exceeds protocol limit"));
        }
        line.extend_from_slice(&available[..length]);
        reader.consume(length);
        if line.last() == Some(&b'\n') {
            return Ok(Some(line));
        }
    }
}
