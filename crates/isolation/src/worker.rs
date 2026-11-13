use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context, Result, bail};
use pii_explorer_core::extract::{ExtractionContext, extract_bytes};

use crate::protocol::{
    MAX_RECORDS, MAX_REQUESTS, MAX_RESPONSE, Request, Response, VERSION, read_frame,
};

/// The executable exposes this only as its worker entry point. Input paths are logical
/// identifiers: document bytes arrive over stdin, never by opening the evidence path.
pub fn run_worker() -> Result<()> {
    resource_limits()?;
    let mut input = BufReader::new(std::io::stdin().lock());
    let mut output = BufWriter::new(std::io::stdout().lock());
    for _ in 0..MAX_REQUESTS {
        let Some(header) = read_frame(&mut input)? else {
            return Ok(());
        };
        let mut request: Request =
            serde_json::from_slice(&header).context("invalid worker request")?;
        if request.version != VERSION
            || request.length > request.options.max_file_bytes
            || request.length > 1024 * 1024 * 1024
            || request.name.len() > 64 * 1024
            || request.options.max_extracted_utf16 > 64_000_000
            || request.options.max_archive_bytes > 1024 * 1024 * 1024
            || request.options.max_archive_members > 100_000
            || request.options.max_archive_depth > 32
            || request.options.file_timeout.is_zero()
        {
            bail!("worker request exceeds supported limits")
        }
        request.options.tesseract_path = request.tesseract_path;
        request.options.tessdata_path = request.tessdata_path;
        let mut data = vec![0; usize::try_from(request.length)?];
        input.read_exact(&mut data)?;
        let context = ExtractionContext::for_root(
            Arc::new(request.options),
            Arc::new(AtomicBool::new(false)),
        );
        // A panic terminates this helper. The coordinator records the incomplete resource
        // and replaces the worker on the next request.
        let extraction = extract_bytes(&request.name, &data, &context);
        let mut bytes = 0;
        let mut records = 0;
        for part in extraction.parts {
            emit(
                &mut output,
                &Response::Part {
                    origin: part.origin,
                    location: part.location,
                    continues_before: part.continues_before,
                    continues_after: part.continues_after,
                },
                &mut bytes,
                &mut records,
            )?;
            let mut remaining = part.text.as_str();
            while !remaining.is_empty() {
                let mut end = remaining.len().min(32_768);
                while !remaining.is_char_boundary(end) {
                    end -= 1;
                }
                emit(
                    &mut output,
                    &Response::Text {
                        text: remaining[..end].to_owned(),
                    },
                    &mut bytes,
                    &mut records,
                )?;
                remaining = &remaining[end..];
            }
            emit(&mut output, &Response::PartEnd, &mut bytes, &mut records)?;
        }
        for attention in extraction.attention {
            emit(
                &mut output,
                &Response::Attention(attention),
                &mut bytes,
                &mut records,
            )?;
        }
        emit(
            &mut output,
            &Response::End {
                version: VERSION,
                partial: extraction.partial,
            },
            &mut bytes,
            &mut records,
        )?;
        output.flush()?;
    }
    Ok(())
}

fn emit(
    output: &mut impl Write,
    record: &Response,
    bytes: &mut usize,
    count: &mut usize,
) -> Result<()> {
    let encoded = serde_json::to_vec(record)?;
    *bytes = bytes.saturating_add(encoded.len() + 1);
    *count += 1;
    if encoded.len() + 1 > crate::protocol::MAX_FRAME
        || *bytes > MAX_RESPONSE
        || *count > MAX_RECORDS
    {
        bail!("worker response exceeds protocol budget");
    }
    output.write_all(&encoded)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn resource_limits() -> Result<()> {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        // Core dumps could contain sensitive text. Respect any stricter inherited limits.
        for (resource, requested) in [(Resource::Core, 0), (Resource::Nofile, 256)] {
            let inherited = getrlimit(resource).maximum.unwrap_or(u64::MAX);
            let limit = requested.min(inherited);
            setrlimit(
                resource,
                Rlimit {
                    current: Some(limit),
                    maximum: Some(limit),
                },
            )?;
        }
        #[cfg(target_os = "linux")]
        {
            let inherited = getrlimit(Resource::As).maximum.unwrap_or(u64::MAX);
            let limit = (1536 * 1024 * 1024).min(inherited);
            setrlimit(
                Resource::As,
                Rlimit {
                    current: Some(limit),
                    maximum: Some(limit),
                },
            )?;
        }
    }
    Ok(())
}
