//! Bounded deskew and scaling before OCR, including confidently fragmented sparse text.

use std::io::Cursor;

use image::{GrayImage, ImageFormat, Limits, Luma};

use crate::extract::ExtractionContext;

pub(super) fn prepare(data: &[u8], context: &ExtractionContext) -> Result<Vec<u8>, String> {
    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(32_000);
    limits.max_image_height = Some(32_000);
    limits.max_alloc = Some(160 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|error| error.to_string())?
        .to_rgba8();
    if u64::from(decoded.width()) * u64::from(decoded.height()) > super::MAX_IMAGE_PIXELS {
        return Err("decoded image exceeds the pixel limit".into());
    }
    let mut gray = GrayImage::new(decoded.width(), decoded.height());
    for (y, row) in decoded.enumerate_rows() {
        if context.is_cancelled() {
            return Err("image preprocessing cancelled or timed out".into());
        }
        for (x, _, pixel) in row {
            // Transparent pixels must become white rather than black OCR strokes.
            let alpha = u32::from(pixel[3]);
            let luminance =
                (299 * u32::from(pixel[0]) + 587 * u32::from(pixel[1]) + 114 * u32::from(pixel[2]))
                    / 1000;
            gray.put_pixel(
                x,
                y,
                Luma([((luminance * alpha + 255 * (255 - alpha)) / 255) as u8]),
            );
        }
    }
    drop(decoded);
    let angle = estimate_skew(&gray, context)?;
    let corrected = rotate(&gray, angle, context)?;
    let image = super::upscale(image::DynamicImage::ImageLuma8(corrected));
    let mut output = Cursor::new(Vec::new());
    image
        .write_to(&mut output, ImageFormat::Png)
        .map_err(|error| error.to_string())?;
    Ok(output.into_inner())
}

fn estimate_skew(image: &GrayImage, context: &ExtractionContext) -> Result<i32, String> {
    let step = image.width().max(image.height()).div_ceil(600).max(1);
    let mut points = Vec::new();
    for y in (0..image.height()).step_by(step as usize) {
        if context.is_cancelled() {
            return Err("skew estimation cancelled or timed out".into());
        }
        for x in (0..image.width()).step_by(step as usize) {
            if image.get_pixel(x, y)[0] < 150 {
                points.push((
                    (f64::from(x) - f64::from(image.width()) / 2.0) / f64::from(step),
                    (f64::from(y) - f64::from(image.height()) / 2.0) / f64::from(step),
                ));
            }
        }
    }
    if points.len() < 50 {
        return Ok(0);
    }
    let (mut best, mut baseline, mut selected) = (0_u64, 0_u64, 0);
    for angle in -15_i32..=15 {
        if context.is_cancelled() {
            return Err("skew estimation cancelled or timed out".into());
        }
        let (sin, cos) = f64::from(angle).to_radians().sin_cos();
        let mut rows = [0_u32; 2000];
        for &(x, y) in &points {
            let row = (x * sin + y * cos).round() as i32 + 1000;
            if let Some(count) = usize::try_from(row).ok().and_then(|row| rows.get_mut(row)) {
                *count += 1;
            }
        }
        let score: u64 = rows.iter().map(|count| u64::from(*count).pow(2)).sum();
        if angle == 0 {
            baseline = score;
        }
        if score > best {
            best = score;
            selected = angle;
        }
    }
    Ok(if best as f64 > baseline as f64 * 1.1 {
        selected
    } else {
        0
    })
}

fn rotate(image: &GrayImage, angle: i32, context: &ExtractionContext) -> Result<GrayImage, String> {
    if angle == 0 {
        return Ok(image.clone());
    }
    let (sin, cos) = f64::from(angle).to_radians().sin_cos();
    let width = (f64::from(image.width()) * cos.abs() + f64::from(image.height()) * sin.abs())
        .ceil() as u32;
    let height = (f64::from(image.width()) * sin.abs() + f64::from(image.height()) * cos.abs())
        .ceil() as u32;
    if u64::from(width) * u64::from(height) > super::MAX_RENDERED_PIXELS {
        return Err("deskewed image exceeds the 40 megapixel rendering limit".into());
    }
    let mut output = GrayImage::from_pixel(width, height, Luma([255]));
    for y in 0..height {
        if context.is_cancelled() {
            return Err("deskew rotation cancelled or timed out".into());
        }
        for x in 0..width {
            let dx = f64::from(x) - f64::from(width) / 2.0;
            let dy = f64::from(y) - f64::from(height) / 2.0;
            let sx = dx * cos + dy * sin + f64::from(image.width()) / 2.0;
            let sy = -dx * sin + dy * cos + f64::from(image.height()) / 2.0;
            if sx >= 0.0
                && sy >= 0.0
                && sx < f64::from(image.width() - 1)
                && sy < f64::from(image.height() - 1)
            {
                let (left, top) = (sx.floor() as u32, sy.floor() as u32);
                let (fx, fy) = (sx.fract(), sy.fract());
                let value = f64::from(image.get_pixel(left, top)[0]) * (1.0 - fx) * (1.0 - fy)
                    + f64::from(image.get_pixel(left + 1, top)[0]) * fx * (1.0 - fy)
                    + f64::from(image.get_pixel(left, top + 1)[0]) * (1.0 - fx) * fy
                    + f64::from(image.get_pixel(left + 1, top + 1)[0]) * fx * fy;
                output.put_pixel(x, y, Luma([value.round() as u8]));
            }
        }
    }
    Ok(output)
}
