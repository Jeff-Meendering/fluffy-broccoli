#[cfg(feature = "ocr")]
use std::io::Cursor;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use super::Emitter;
use super::text::{Decoded, decode};

#[cfg(feature = "ocr")]
mod preprocess;

const MAX_IMAGE_PIXELS: u64 = 32_000_000;
#[cfg(feature = "ocr")]
const MAX_RENDERED_PIXELS: u64 = 40_000_000;
const MAX_OCR_STDOUT: usize = 8_000_000;
const MAX_OCR_STDERR: usize = 4_096;

#[derive(Default)]
struct ImageInfo {
    width: u32,
    height: u32,
    metadata: Vec<(String, String)>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct OcrReading {
    text: String,
    confidence: f64,
}

#[cfg(all(feature = "formats", not(feature = "ocr")))]
pub(super) fn pdf_pages(
    out: &mut Emitter<'_>,
    _data: &[u8],
    _pages: &std::collections::BTreeSet<u32>,
) {
    out.issue("PDF page OCR was not compiled in; enable the ocr feature to check scanned and embedded image content.");
}

/// Keep generated pixels in memory and place each page in a separate OCR coordinate space.
#[cfg(all(feature = "formats", feature = "ocr"))]
pub(super) fn pdf_pages(
    out: &mut Emitter<'_>,
    data: &[u8],
    pages: &std::collections::BTreeSet<u32>,
) {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use hayro::hayro_syntax::Pdf;
    use hayro::{PixmapSettings, RenderCache, RenderSettings};

    if !out.running() || pages.is_empty() {
        return;
    }
    let loaded = catch_unwind(AssertUnwindSafe(|| Pdf::new(data.to_vec())));
    let pdf = match loaded {
        Ok(Ok(pdf)) => pdf,
        _ => {
            out.issue("PDF rasterizer could not open this document; extracted text was retained but page images were not OCR checked.");
            return;
        }
    };
    let mut rendered_pixels = 0_u64;
    for &page_number in pages {
        if !out.running() {
            return;
        }
        let rendered = catch_unwind(AssertUnwindSafe(|| {
            let page = pdf
                .pages()
                .get(page_number.saturating_sub(1) as usize)
                .ok_or_else(|| "page was not available to the rasterizer".to_owned())?;
            let (width, height) = page.render_dimensions();
            let scale = 200.0 / 72.0;
            let pixels = pdf_pixel_budget(width, height, scale)?;
            // Bound cumulative work even for a document with thousands of small pages.
            if rendered_pixels.saturating_add(pixels) > 80_000_000 {
                rendered_pixels = 80_000_000;
                return Err("total PDF rendering limit of 80 megapixels reached".to_owned());
            }
            rendered_pixels += pixels;
            // A page-local cache avoids retaining all decoded images/glyphs across a large PDF.
            let pixmap = hayro::render(
                page,
                &RenderCache::new(),
                &hayro::hayro_interpret::InterpreterSettings::default(),
                &RenderSettings::default(),
                &PixmapSettings {
                    x_scale: scale,
                    y_scale: scale,
                    bg_color: hayro::vello_cpu::color::palette::css::WHITE,
                },
            );
            pixmap
                .into_png()
                .map_err(|error| format!("page image encoding failed: {error}"))
        }));
        let png = match rendered {
            Ok(Ok(png)) => png,
            Ok(Err(error)) => {
                out.issue(format!(
                    "PDF page {page_number} was not OCR checked: {error}."
                ));
                if rendered_pixels >= 80_000_000 {
                    out.issue(
                        "Remaining PDF pages were not OCR checked after the total rendering limit.",
                    );
                    return;
                }
                continue;
            }
            Err(_) => {
                out.issue(format!(
                    "PDF page {page_number} rasterizer failed; earlier evidence was retained."
                ));
                continue;
            }
        };
        if !out.running() {
            return;
        }
        let prepared = match preprocess::prepare(&png, out.context) {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                out.issue(format!(
                    "PDF page {page_number} OCR preprocessing unavailable: {error}"
                ));
                None
            }
        };
        if !out.running() {
            return;
        }
        match run_tesseract(out, prepared.as_deref().unwrap_or(&png)) {
            Ok(reading) => {
                out.ocr(
                    &reading.text,
                    format!(
                        "PDF page {page_number} OCR · average word confidence {:.0}%",
                        reading.confidence
                    ),
                    &format!("ocr:pdf:page:{page_number}"),
                );
                if reading.text.trim().is_empty() || reading.confidence < 65.0 {
                    out.issue(format!("PDF page {page_number} OCR was uncertain; review the page for missed or misread PII."));
                }
            }
            Err(error) => {
                out.issue(format!("PDF page {page_number} OCR incomplete: {error}"));
                // Missing OCR binaries/language data affect every remaining page as well.
                out.issue("Remaining PDF pages were not OCR checked after the OCR failure.");
                return;
            }
        }
    }
}

#[cfg(all(feature = "formats", feature = "ocr"))]
fn pdf_pixel_budget(width: f32, height: f32, scale: f32) -> Result<u64, String> {
    let width = (width * scale).ceil();
    let height = (height * scale).ceil();
    if !width.is_finite()
        || !height.is_finite()
        || !(1.0..=65535.0).contains(&width)
        || !(1.0..=65535.0).contains(&height)
    {
        return Err("page dimensions are invalid or exceed the rasterizer limit".into());
    }
    let pixels = width as u64 * height as u64;
    if pixels > MAX_RENDERED_PIXELS {
        return Err("page exceeds the 40 megapixel rendering limit".into());
    }
    Ok(pixels)
}

pub(super) fn is_image(data: &[u8]) -> bool {
    data.starts_with(b"\x89PNG\r\n\x1a\n")
        || data.starts_with(&[0xff, 0xd8])
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || (data.starts_with(b"BM")
            && data.len() >= 26
            && matches!(le_u32(data, 14), Ok(12 | 40 | 52 | 56 | 64 | 108 | 124)))
        || (data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP"))
        || data.starts_with(b"II*\0")
        || data.starts_with(b"MM\0*")
        || (matches!(
            data.get(..2),
            Some(b"P1") | Some(b"P2") | Some(b"P3") | Some(b"P4") | Some(b"P5") | Some(b"P6")
        ) && data.get(2).is_some_and(u8::is_ascii_whitespace))
}

pub(super) fn extract(out: &mut Emitter<'_>, data: &[u8]) {
    let info = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image_info(data))) {
        Ok(Ok(info)) => info,
        Ok(Err(error)) => {
            out.issue(format!("Image decoder could not read this file: {error}"));
            return;
        }
        Err(_) => {
            out.issue(
                "Image metadata parser failed on malformed input; pixels were not OCR checked.",
            );
            return;
        }
    };
    out.metadata("Image width", &info.width.to_string(), 0);
    out.metadata("Image height", &info.height.to_string(), 1);
    for (ordinal, (key, value)) in info.metadata.iter().enumerate() {
        out.metadata(key, value, ordinal + 2);
    }
    for warning in info.warnings {
        out.issue(warning);
    }
    if !out.running() {
        return;
    }
    let pixels = u64::from(info.width) * u64::from(info.height);
    if info.width == 0 || info.height == 0 {
        out.issue("Image has invalid zero dimensions; pixels were not OCR checked.");
        return;
    }
    if pixels > MAX_IMAGE_PIXELS {
        out.issue("Image exceeds 32 megapixel decoding limit; metadata was checked but pixels were not OCR checked.");
        return;
    }
    if !out.context.options.ocr {
        out.issue("Image content was not OCR checked (OCR is off); metadata was checked.");
        return;
    }

    #[cfg(feature = "ocr")]
    let prepared = match preprocess::prepare(data, out.context) {
        Ok(prepared) => Some(prepared),
        Err(error) => {
            out.issue(format!("Image preprocessing unavailable: {error}"));
            None
        }
    };
    #[cfg(feature = "ocr")]
    let data = prepared.as_deref().unwrap_or(data);
    if !out.running() {
        return;
    }
    #[allow(unused_mut)]
    let mut best = match run_tesseract(out, data) {
        Ok(reading) => reading,
        Err(error) => {
            out.issue(format!("Image OCR incomplete: {error}"));
            return;
        }
    };
    #[cfg(feature = "ocr")]
    if (best.confidence < 65.0 || best.text.len() <= 5) && out.running() {
        match rendered_variants(data) {
            Ok(variants) => {
                for (angle, rendered) in variants {
                    if !out.running() {
                        break;
                    }
                    match run_tesseract(out, &rendered) {
                        Ok(reading) => {
                            if reading.confidence > best.confidence || best.text.is_empty() {
                                best = reading;
                            }
                            if best.confidence >= 65.0 && best.text.len() > 5 {
                                break;
                            }
                        }
                        Err(error) => {
                            out.issue(format!(
                                "Image OCR rotation {angle} was incomplete: {error}"
                            ));
                            break;
                        }
                    }
                }
            }
            Err(error) => out.issue(format!("Image rotation/upscaling was unavailable: {error}")),
        }
    }

    out.ocr(
        &best.text,
        format!("OCR · average word confidence {:.0}%", best.confidence),
        "ocr:frame:0",
    );
    if best.text.trim().is_empty() || best.confidence < 65.0 {
        out.issue("OCR found little or uncertain text. Handwriting, rotation, skew or low resolution may hide PII; review the image.");
    }
}

fn image_info(data: &[u8]) -> Result<ImageInfo, String> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        png_info(data)
    } else if data.starts_with(&[0xff, 0xd8]) {
        jpeg_info(data)
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        gif_info(data)
    } else if data.starts_with(b"BM") {
        bmp_info(data)
    } else if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        webp_info(data)
    } else if data.starts_with(b"II*\0") || data.starts_with(b"MM\0*") {
        let (dimensions, metadata) = tiff_info(data)?;
        let (width, height) = dimensions.ok_or("TIFF dimensions are missing")?;
        Ok(ImageInfo {
            width,
            height,
            metadata,
            warnings: Vec::new(),
        })
    } else if data
        .first()
        .is_some_and(|byte| matches!(*byte, b'P' | b'p'))
    {
        pnm_info(data)
    } else {
        Err("unrecognized image signature".to_owned())
    }
}

fn png_info(data: &[u8]) -> Result<ImageInfo, String> {
    if data.len() < 33 {
        return Err("truncated PNG header".to_owned());
    }
    let mut info = ImageInfo {
        width: be_u32(data, 16)?,
        height: be_u32(data, 20)?,
        ..ImageInfo::default()
    };
    let mut offset = 8usize;
    let mut chunks = 0usize;
    while offset + 12 <= data.len() && chunks < 100_000 {
        chunks += 1;
        let length = be_u32(data, offset)? as usize;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .filter(|end| *end <= data.len())
            .ok_or("truncated PNG chunk")?;
        let kind = &data[offset + 4..offset + 8];
        let payload = &data[offset + 8..end - 4];
        match kind {
            b"tEXt" => {
                if let Some(separator) = payload.iter().position(|byte| *byte == 0) {
                    let key = latin1(&payload[..separator]);
                    let value = latin1(&payload[separator + 1..]);
                    info.metadata.push((format!("PNG:{key}"), value));
                }
            }
            b"iTXt" => {
                if let Some(value) = parse_itxt(payload) {
                    info.metadata.push(value);
                } else {
                    info.warnings.push("Compressed or malformed PNG iTXt metadata was not checked.".to_owned());
                }
            }
            b"zTXt" => info.warnings.push(
                "Compressed PNG zTXt metadata was not checked; no external decompressor was invoked.".to_owned(),
            ),
            b"eXIf" => {
                if let Ok((_, metadata)) = tiff_info(payload) {
                    info.metadata.extend(metadata);
                }
            }
            b"IEND" => break,
            _ => {}
        }
        offset = end;
    }
    if chunks >= 100_000 {
        info.warnings.push(
            "PNG metadata chunk limit reached; remaining metadata was not checked.".to_owned(),
        );
    }
    Ok(info)
}

fn parse_itxt(payload: &[u8]) -> Option<(String, String)> {
    let key_end = payload.iter().position(|byte| *byte == 0)?;
    let key = std::str::from_utf8(&payload[..key_end]).ok()?.to_owned();
    let rest = payload.get(key_end + 1..)?;
    let compressed = *rest.first()?;
    if compressed != 0 || rest.get(1) != Some(&0) {
        return None;
    }
    let language_end = rest[2..].iter().position(|byte| *byte == 0)? + 2;
    let translated_start = language_end + 1;
    let translated_end = rest
        .get(translated_start..)?
        .iter()
        .position(|byte| *byte == 0)?
        + translated_start;
    let value = std::str::from_utf8(rest.get(translated_end + 1..)?)
        .ok()?
        .to_owned();
    Some((format!("PNG:{key}"), value))
}

fn jpeg_info(data: &[u8]) -> Result<ImageInfo, String> {
    let mut info = ImageInfo::default();
    let mut offset = 2usize;
    while offset < data.len() {
        while data.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let marker = *data.get(offset).ok_or("truncated JPEG marker")?;
        offset += 1;
        if marker == 0xd9 || marker == 0xda {
            break;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = be_u16(data, offset)? as usize;
        if length < 2 {
            return Err("invalid JPEG segment length".to_owned());
        }
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or("truncated JPEG segment")?;
        let payload = &data[offset + 2..end];
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if payload.len() < 5 {
                return Err("truncated JPEG frame".to_owned());
            }
            info.height = u16::from_be_bytes([payload[1], payload[2]]) as u32;
            info.width = u16::from_be_bytes([payload[3], payload[4]]) as u32;
        } else if marker == 0xfe {
            if let Some(value) = metadata_bytes(payload) {
                info.metadata.push(("JPEG:Comment".to_owned(), value));
            }
        } else if marker == 0xe1 && payload.starts_with(b"Exif\0\0") {
            if let Ok((_, metadata)) = tiff_info(&payload[6..]) {
                info.metadata.extend(metadata);
            }
        } else if marker == 0xe1
            && payload.starts_with(b"http://ns.adobe.com/xap/1.0/\0")
            && let Ok(value) = std::str::from_utf8(&payload[29..])
        {
            info.metadata
                .push(("JPEG:XMP".to_owned(), value.to_owned()));
        }
        offset = end;
    }
    if info.width == 0 || info.height == 0 {
        return Err("JPEG dimensions are missing".to_owned());
    }
    Ok(info)
}

fn gif_info(data: &[u8]) -> Result<ImageInfo, String> {
    if data.len() < 10 {
        return Err("truncated GIF header".to_owned());
    }
    let mut info = ImageInfo {
        width: le_u16(data, 6)? as u32,
        height: le_u16(data, 8)? as u32,
        ..ImageInfo::default()
    };
    // Comment extensions are ASCII by specification. Bounding the scan avoids retaining
    // arbitrary image data as metadata; the direct OCR decoder still applies its own limits.
    let mut offset = 0usize;
    while let Some(relative) = data[offset..]
        .windows(2)
        .position(|window| window == [0x21, 0xfe])
    {
        offset += relative + 2;
        let mut comment = Vec::new();
        loop {
            let length = *data.get(offset).ok_or("truncated GIF comment")? as usize;
            offset += 1;
            if length == 0 {
                break;
            }
            let end = offset + length;
            if end > data.len() || comment.len() + length > 1_000_000 {
                return Err("GIF comment is truncated or exceeds its metadata limit".to_owned());
            }
            comment.extend_from_slice(&data[offset..end]);
            offset = end;
        }
        if let Some(comment) = metadata_bytes(&comment) {
            info.metadata.push(("GIF:Comment".to_owned(), comment));
        }
    }
    Ok(info)
}

fn bmp_info(data: &[u8]) -> Result<ImageInfo, String> {
    if data.len() < 26 {
        return Err("truncated BMP header".to_owned());
    }
    let width =
        i32::from_le_bytes(data[18..22].try_into().map_err(|_| "BMP width")?).unsigned_abs();
    let height =
        i32::from_le_bytes(data[22..26].try_into().map_err(|_| "BMP height")?).unsigned_abs();
    Ok(ImageInfo {
        width,
        height,
        ..ImageInfo::default()
    })
}

fn webp_info(data: &[u8]) -> Result<ImageInfo, String> {
    let mut info = ImageInfo::default();
    let mut offset = 12usize;
    while offset + 8 <= data.len() {
        let kind = &data[offset..offset + 4];
        let length = le_u32(data, offset + 4)? as usize;
        let start = offset + 8;
        let end = start
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or("truncated WebP chunk")?;
        let payload = &data[start..end];
        match kind {
            b"VP8X" if payload.len() >= 10 => {
                info.width = 1 + u32::from_le_bytes([payload[4], payload[5], payload[6], 0]);
                info.height = 1 + u32::from_le_bytes([payload[7], payload[8], payload[9], 0]);
            }
            b"VP8 " if payload.len() >= 10 && payload[3..6] == [0x9d, 0x01, 0x2a] => {
                info.width = u32::from(u16::from_le_bytes([payload[6], payload[7]]) & 0x3fff);
                info.height = u32::from(u16::from_le_bytes([payload[8], payload[9]]) & 0x3fff);
            }
            b"VP8L" if payload.len() >= 5 && payload[0] == 0x2f => {
                let bits = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                info.width = (bits & 0x3fff) + 1;
                info.height = ((bits >> 14) & 0x3fff) + 1;
            }
            b"EXIF" => {
                let payload = payload.strip_prefix(b"Exif\0\0").unwrap_or(payload);
                if let Ok((_, metadata)) = tiff_info(payload) {
                    info.metadata.extend(metadata);
                }
            }
            b"XMP " => {
                if let Ok(value) = std::str::from_utf8(payload) {
                    info.metadata
                        .push(("WebP:XMP".to_owned(), value.to_owned()));
                }
            }
            _ => {}
        }
        offset = end + (length & 1);
    }
    if info.width == 0 || info.height == 0 {
        return Err("WebP dimensions are missing".to_owned());
    }
    Ok(info)
}

fn pnm_info(data: &[u8]) -> Result<ImageInfo, String> {
    let mut tokens = Vec::new();
    let mut metadata = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() && tokens.len() < 3 {
        while data.get(offset).is_some_and(u8::is_ascii_whitespace) {
            offset += 1;
        }
        if data.get(offset) == Some(&b'#') {
            let end = data[offset..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(data.len(), |end| offset + end + 1);
            if let Some(comment) = metadata_bytes(&data[offset + 1..end]) {
                metadata.push(("PNM:Comment".to_owned(), comment));
            }
            offset = end;
            continue;
        }
        let start = offset;
        while data
            .get(offset)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            offset += 1;
        }
        if start == offset {
            break;
        }
        let token =
            std::str::from_utf8(&data[start..offset]).map_err(|_| "non-ASCII PNM header")?;
        tokens.push(token.to_owned());
    }
    let Some(magic) = tokens.first() else {
        return Err("PNM signature is missing".to_owned());
    };
    if !matches!(magic.as_str(), "P1" | "P2" | "P3" | "P4" | "P5" | "P6") {
        return Err("unsupported PNM variant".to_owned());
    }
    let width = tokens
        .get(1)
        .ok_or("PNM width is missing")?
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    let height = tokens
        .get(2)
        .ok_or("PNM height is missing")?
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    Ok(ImageInfo {
        width,
        height,
        metadata,
        warnings: Vec::new(),
    })
}

type TiffInfo = (Option<(u32, u32)>, Vec<(String, String)>);

fn tiff_info(data: &[u8]) -> Result<TiffInfo, String> {
    let little = match data.get(..2) {
        Some(b"II") => true,
        Some(b"MM") => false,
        _ => return Err("invalid TIFF byte order".to_owned()),
    };
    if tiff_u16(data, 2, little)? != 42 {
        return Err("unsupported TIFF signature".to_owned());
    }
    let ifd = tiff_u32(data, 4, little)? as usize;
    let count = tiff_u16(data, ifd, little)? as usize;
    if count > 4_096 {
        return Err("TIFF metadata entry limit reached".to_owned());
    }
    let mut width = None;
    let mut height = None;
    let mut metadata = Vec::new();
    for index in 0..count {
        let offset = ifd + 2 + index * 12;
        if offset + 12 > data.len() {
            return Err("truncated TIFF directory".to_owned());
        }
        let tag = tiff_u16(data, offset, little)?;
        let kind = tiff_u16(data, offset + 2, little)?;
        let count = tiff_u32(data, offset + 4, little)? as usize;
        let numeric = if kind == 3 && count >= 1 {
            Some(tiff_u16(data, offset + 8, little)? as u32)
        } else if kind == 4 && count >= 1 {
            Some(tiff_u32(data, offset + 8, little)?)
        } else {
            None
        };
        match tag {
            256 => width = numeric,
            257 => height = numeric,
            270 | 271 | 272 | 305 | 306 | 315 | 33432 | 37510
                if kind == 2 && count <= 1_000_000 =>
            {
                let value = if count <= 4 {
                    &data[offset + 8..offset + 8 + count]
                } else {
                    let start = tiff_u32(data, offset + 8, little)? as usize;
                    let end = start
                        .checked_add(count)
                        .ok_or("TIFF metadata offset overflow")?;
                    data.get(start..end).ok_or("truncated TIFF metadata")?
                };
                if let Some(value) = metadata_bytes(value) {
                    let key = match tag {
                        270 => "ImageDescription",
                        271 => "Make",
                        272 => "Model",
                        305 => "Software",
                        306 => "DateTime",
                        315 => "Artist",
                        33432 => "Copyright",
                        _ => "UserComment",
                    };
                    metadata.push((format!("EXIF:{key}"), value.trim_matches('\0').to_owned()));
                }
            }
            _ => {}
        }
    }
    Ok((width.zip(height), metadata))
}

fn metadata_bytes(bytes: &[u8]) -> Option<String> {
    let mut bytes = bytes.strip_prefix(b"ASCII\0\0\0").unwrap_or(bytes);
    while bytes.last() == Some(&0) {
        bytes = &bytes[..bytes.len() - 1];
    }
    if bytes.is_empty() {
        return None;
    }
    match decode(bytes) {
        Decoded::Text(text) => Some(text),
        Decoded::Binary(_) | Decoded::Invalid(_) => None,
    }
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn be_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or("truncated 16-bit value")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or("truncated 32-bit value")?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u16(data: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or("truncated 16-bit value")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or("truncated 32-bit value")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn tiff_u16(data: &[u8], offset: usize, little: bool) -> Result<u16, String> {
    if little {
        le_u16(data, offset)
    } else {
        be_u16(data, offset)
    }
}

fn tiff_u32(data: &[u8], offset: usize, little: bool) -> Result<u32, String> {
    if little {
        le_u32(data, offset)
    } else {
        be_u32(data, offset)
    }
}

fn run_tesseract(out: &Emitter<'_>, data: &[u8]) -> Result<OcrReading, String> {
    let executable = out
        .context
        .options
        .tesseract_path
        .clone()
        .unwrap_or_else(|| "tesseract".into());
    let mut command = Command::new(executable);
    command
        .arg("stdin")
        .arg("stdout")
        .arg("-l")
        .arg("eng")
        .arg("--psm")
        .arg("11")
        .arg("-c")
        .arg("tessedit_create_tsv=1")
        .env("OMP_THREAD_LIMIT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(tessdata) = &out.context.options.tessdata_path {
        command.arg("--tessdata-dir").arg(tessdata);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start tesseract: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("tesseract stdin was unavailable")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("tesseract stdout was unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("tesseract stderr was unavailable")?;
    let input = data.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&input));
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_bounded_reader(stdout, MAX_OCR_STDOUT, Arc::clone(&overflow));
    let stderr_reader =
        spawn_bounded_reader(stderr, MAX_OCR_STDERR, Arc::new(AtomicBool::new(false)));

    let timeout = out
        .context
        .remaining_time()
        .map_or(out.context.options.ocr_timeout, |remaining| {
            remaining.min(out.context.options.ocr_timeout)
        });
    let started = Instant::now();
    let mut status = None;
    let mut failure = None;
    loop {
        match child.try_wait() {
            Ok(Some(exit)) => {
                status = Some(exit);
                break;
            }
            Ok(None) => {}
            Err(error) => {
                failure = Some(format!("could not wait for tesseract: {error}"));
                break;
            }
        }
        if overflow.load(Ordering::Relaxed) {
            failure = Some("OCR output limit reached; image was not fully checked".to_owned());
            break;
        }
        if out.context.is_cancelled() {
            failure = Some("OCR cancelled by the file deadline or cancellation request".to_owned());
            break;
        }
        if started.elapsed() >= timeout {
            failure = Some(format!("OCR timed out after {} ms", timeout.as_millis()));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if status.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    let _ = writer.join();
    let stdout = stdout_reader
        .join()
        .map_err(|_| "OCR stdout reader failed".to_owned())?
        .map_err(|error| error.to_string())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "OCR stderr reader failed".to_owned())?
        .map_err(|error| error.to_string())?;
    if let Some(failure) = failure {
        return Err(failure);
    }
    let status = status.ok_or("tesseract exit status was unavailable")?;
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        let detail: String = detail.chars().take(300).collect();
        return Err(format!("tesseract exited with {status}: {}", detail.trim()));
    }
    let stdout = String::from_utf8(stdout).map_err(|_| "tesseract returned invalid UTF-8")?;
    Ok(parse_tsv(&stdout))
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                return Ok(output);
            }
            let remaining = limit.saturating_sub(output.len());
            output.extend_from_slice(&buffer[..read.min(remaining)]);
            if read > remaining {
                overflow.store(true, Ordering::Relaxed);
            }
        }
    })
}

fn parse_tsv(output: &str) -> OcrReading {
    let mut reading = OcrReading::default();
    let mut previous_line = String::new();
    let mut weight = 0usize;
    for line in output.lines().skip(1) {
        let columns: Vec<_> = line.trim_end_matches('\r').splitn(12, '\t').collect();
        if columns.len() < 12 || columns[0] != "5" || columns[11].trim().is_empty() {
            continue;
        }
        let Ok(confidence) = columns[10].parse::<f64>() else {
            continue;
        };
        if confidence < 0.0 {
            continue;
        }
        let line_key = columns[1..5].join("/");
        if !reading.text.is_empty() {
            reading
                .text
                .push(if previous_line == line_key { ' ' } else { '\n' });
        }
        reading.text.push_str(columns[11]);
        previous_line = line_key;
        reading.confidence += confidence * columns[11].len() as f64;
        weight += columns[11].len();
    }
    if weight > 0 {
        reading.confidence /= weight as f64;
    }
    reading
}

#[cfg(feature = "ocr")]
fn rendered_variants(data: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, String> {
    use image::Limits;

    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(32_000);
    limits.max_image_height = Some(32_000);
    limits.max_alloc = Some(160 * 1024 * 1024);
    reader.limits(limits);
    let original = reader.decode().map_err(|error| error.to_string())?;
    let mut variants = Vec::new();
    for angle in [0, 90, 180, 270] {
        let image = match angle {
            90 => original.rotate90(),
            180 => original.rotate180(),
            270 => original.rotate270(),
            _ => original.clone(),
        };
        let image = upscale(image);
        let mut bytes = Cursor::new(Vec::new());
        image
            .write_to(&mut bytes, image::ImageFormat::Png)
            .map_err(|error| error.to_string())?;
        variants.push((angle, bytes.into_inner()));
    }
    Ok(variants)
}

#[cfg(feature = "ocr")]
fn upscale(image: image::DynamicImage) -> image::DynamicImage {
    let scale = (1200.0 / image.width().max(1) as f64).clamp(1.0, 3.0);
    let width = (image.width() as f64 * scale).ceil() as u32;
    let height = (image.height() as f64 * scale).ceil() as u32;
    if u64::from(width) * u64::from(height) > MAX_RENDERED_PIXELS {
        return image;
    }
    image.resize(width, height, image::imageops::FilterType::Triangle)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::ScanOptions;
    use crate::extract::ExtractionContext;

    use super::*;

    #[test]
    fn tsv_output_keeps_line_and_confidence_semantics() {
        let reading = parse_tsv(
            "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n5\t1\t2\t3\t4\t6\t0\t0\t1\t1\t90.5\thello@example.net\n",
        );
        assert_eq!(reading.text, "hello@example.net");
        assert!((reading.confidence - 90.5).abs() < 0.01);
    }

    #[cfg(all(feature = "formats", feature = "ocr"))]
    #[test]
    fn pdf_raster_dimensions_reject_nonfinite_overflow_and_excessive_work() {
        assert!(pdf_pixel_budget(612.0, 792.0, 200.0 / 72.0).is_ok());
        for (width, height) in [
            (f32::NAN, 10.0),
            (f32::INFINITY, 10.0),
            (0.0, 10.0),
            (-1.0, 10.0),
            (100_000.0, 10.0),
            (10_000.0, 10_000.0),
        ] {
            assert!(pdf_pixel_budget(width, height, 1.0).is_err());
        }
    }

    #[cfg(all(feature = "ocr", feature = "formats"))]
    #[test]
    fn scanned_pdf_ocr_preserves_page_origin_when_tesseract_is_installed() {
        if !Command::new("tesseract")
            .arg("--version")
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
        let data = include_bytes!("../../../../../tests/fixtures/corpus/03_pdf/scanned-memo.pdf");
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions::default()),
            Arc::new(AtomicBool::new(false)),
        );
        let result = crate::extract::extract_bytes("memo.pdf", data, &context);
        let part = result
            .parts
            .iter()
            .find(|part| part.origin.stream_id == "ocr:pdf:page:1")
            .unwrap_or_else(|| panic!("missing page OCR: {:?}", result.attention));
        assert!(
            part.text.contains("maria.hernandez@example.com"),
            "{:?}",
            part.text
        );
        assert_eq!(part.origin.resource_id, "memo.pdf");
        assert_eq!(part.origin.kind, crate::EvidenceKind::Ocr);
        assert_eq!(
            part.origin.coordinate_unit,
            crate::CoordinateUnit::Utf16CodeUnits
        );
    }

    #[cfg(all(feature = "ocr", feature = "formats"))]
    #[test]
    fn missing_pdf_ocr_runtime_retains_extracted_text_and_reports_attention() {
        let data = include_bytes!("../../../../../tests/fixtures/corpus/03_pdf/invoice.pdf");
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions {
                tesseract_path: Some(std::path::PathBuf::from(
                    "/nonexistent/pii-explorer-tesseract",
                )),
                ..ScanOptions::default()
            }),
            Arc::new(AtomicBool::new(false)),
        );
        let result = crate::extract::extract_bytes("invoice.pdf", data, &context);
        assert!(
            result
                .parts
                .iter()
                .any(|part| part.text.contains("priya.r@example.net"))
        );
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("OCR incomplete")),
            "{:?}",
            result.attention
        );
    }

    #[test]
    fn real_image_metadata_is_available_without_ocr() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/04_images/badge.png");
        let data = std::fs::read(path).expect("fixture");
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions {
                ocr: false,
                ..ScanOptions::default()
            }),
            Arc::new(AtomicBool::new(false)),
        );
        for name in ["badge.png", "misleading.txt"] {
            let result = crate::extract::extract_bytes(name, &data, &context);
            assert!(result.parts.iter().any(|part| part.text == "820"));
            assert!(
                result
                    .attention
                    .iter()
                    .any(|item| item.message.contains("OCR is off"))
            );
        }
    }

    #[test]
    fn oversized_image_still_emits_text_metadata_without_starting_ocr() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/04_images/badge.png");
        let original = std::fs::read(path).expect("fixture");
        let mut modified = original.clone();
        modified[16..20].copy_from_slice(&8000u32.to_be_bytes());
        modified[20..24].copy_from_slice(&5000u32.to_be_bytes());
        let payload = b"Comment\0metadata.only@example.net";
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(b"tEXt");
        chunk.extend_from_slice(payload);
        chunk.extend_from_slice(&[0; 4]);
        modified.splice(33..33, chunk);
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions {
                ocr: true,
                ..ScanOptions::default()
            }),
            Arc::new(AtomicBool::new(false)),
        );
        let result = crate::extract::extract_bytes("oversized.png", &modified, &context);
        assert!(result.parts.iter().any(|part| {
            part.origin.kind == crate::EvidenceKind::Metadata
                && part.text == "metadata.only@example.net"
        }));
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("32 megapixel"))
        );
        assert!(
            !result
                .parts
                .iter()
                .any(|part| part.origin.kind == crate::EvidenceKind::Ocr)
        );
    }

    #[test]
    fn direct_ocr_reads_real_fixture_when_tesseract_is_installed() {
        let available = Command::new("tesseract").arg("--version").output().is_ok();
        if !available {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/04_images/badge.png");
        let data = std::fs::read(path).expect("fixture");
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions {
                ocr: true,
                ..ScanOptions::default()
            }),
            Arc::new(AtomicBool::new(false)),
        );
        let result = crate::extract::extract_bytes("badge.png", &data, &context);
        let text: String = result.parts.iter().map(|part| part.text.as_str()).collect();
        assert!(
            text.contains("maria.hernandez@example.com"),
            "{text:?}; {:?}",
            result.attention
        );
    }

    #[cfg(feature = "ocr")]
    #[test]
    fn skew_correction_recovers_confidently_fragmented_email_when_tesseract_is_installed() {
        if !Command::new("tesseract")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return;
        }
        let data =
            include_bytes!("../../../../../tests/fixtures/corpus/04_images/whiteboard-crooked.png");
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions::default()),
            Arc::new(AtomicBool::new(false)),
        );
        let result = crate::extract::extract_bytes("whiteboard.png", data, &context);
        assert!(
            result
                .parts
                .iter()
                .any(|part| part.text.contains("tomas.andersson@example.co.uk")),
            "{:?}; {:?}",
            result.parts,
            result.attention
        );
    }
}
