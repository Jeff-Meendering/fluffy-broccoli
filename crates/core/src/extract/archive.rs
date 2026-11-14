use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;
use std::rc::Rc;

use super::ExtractionContext;
use crate::{
    AttentionItem, CoordinateUnit, EvidenceKind, EvidenceOrigin, ExtractedPart, Extraction,
};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const RAR_BUFFERED_DECODE_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveKind {
    Zip,
    Rar,
    SevenZip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
}

/// Extract an archive entirely in memory. Entry names are logical evidence identifiers;
/// they are never interpreted as host paths and no links are followed.
pub fn extract(name: &str, data: &[u8], depth: usize, context: &ExtractionContext) -> Extraction {
    let mut result = Extraction::default();
    if context.is_cancelled() {
        cancelled(name, &mut result);
        return result;
    }
    let Some(kind) = detect_kind(name, data) else {
        return Extraction::default();
    };
    if context.is_cancelled() {
        cancelled(name, &mut result);
        return result;
    }
    if depth >= context.options.max_archive_depth {
        attention(
            name,
            "Archive nesting limit reached; archive content was not checked.",
            &mut result,
        );
        return result;
    }

    match kind {
        ArchiveKind::Zip => extract_zip(name, data, depth, context),
        ArchiveKind::Rar => extract_rar(name, data, depth, context),
        ArchiveKind::SevenZip => extract_seven_zip(name, data, depth, context),
        ArchiveKind::Tar => extract_tar(name, data, depth, context),
        ArchiveKind::Gzip => extract_single_stream(
            name,
            flate2::read::MultiGzDecoder::new(data),
            ArchiveKind::Gzip,
            depth,
            context,
        ),
        ArchiveKind::Bzip2 => extract_single_stream(
            name,
            bzip2::read::MultiBzDecoder::new(data),
            ArchiveKind::Bzip2,
            depth,
            context,
        ),
        ArchiveKind::Xz => {
            let memory_limit = xz_memory_limit(context);
            extract_single_stream(
                name,
                lzma_rust2::XzReader::new_mem_limit(data, true, memory_limit),
                ArchiveKind::Xz,
                depth,
                context,
            )
        }
    }
}

fn detect_kind(name: &str, data: &[u8]) -> Option<ArchiveKind> {
    if is_zip_signature(data) {
        return Some(ArchiveKind::Zip);
    }
    if data.starts_with(b"Rar!\x1a\x07") && data.get(6).is_some_and(|version| *version <= 1) {
        return Some(ArchiveKind::Rar);
    }
    if data.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some(ArchiveKind::SevenZip);
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return Some(ArchiveKind::Gzip);
    }
    if data.starts_with(b"BZh") {
        return Some(ArchiveKind::Bzip2);
    }
    if data.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0]) {
        return Some(ArchiveKind::Xz);
    }
    if data.get(257..262).is_some_and(|magic| magic == b"ustar") {
        return Some(ArchiveKind::Tar);
    }

    match extension(name).as_deref() {
        Some("zip" | "jar") => Some(ArchiveKind::Zip),
        Some("rar") => Some(ArchiveKind::Rar),
        Some("7z") => Some(ArchiveKind::SevenZip),
        Some("tar") => Some(ArchiveKind::Tar),
        Some("gz" | "tgz" | "gzip") => Some(ArchiveKind::Gzip),
        Some("bz2" | "tbz" | "tbz2" | "bzip2") => Some(ArchiveKind::Bzip2),
        Some("xz" | "txz") => Some(ArchiveKind::Xz),
        _ => None,
    }
}

fn is_zip_signature(data: &[u8]) -> bool {
    data.starts_with(&[0x50, 0x4b, 0x03, 0x04])
        || data.starts_with(&[0x50, 0x4b, 0x05, 0x06])
        || data.starts_with(&[0x50, 0x4b, 0x07, 0x08])
}

fn extension(name: &str) -> Option<String> {
    Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
}

fn extract_zip(name: &str, data: &[u8], depth: usize, context: &ExtractionContext) -> Extraction {
    let mut result = Extraction::default();
    let probe = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(archive) => archive,
        Err(error) => {
            attention(
                name,
                &format!("Could not read ZIP archive: {error}; archive content unchecked."),
                &mut result,
            );
            return result;
        }
    };
    let duplicates = probe.has_duplicate_names();
    let central_start = probe.central_directory_start();
    drop(probe);

    // zip's central-directory index is name-keyed. Preserve duplicate entries by
    // renaming only their later central records in a private byte copy. Evidence
    // retains the parsed original names, and local payloads are never rewritten.
    let (input, original_names) = if duplicates {
        match disambiguate_duplicate_zip_names(data, central_start) {
            Ok((bytes, names)) => (Cow::Owned(bytes), Some(names)),
            Err(error) => {
                attention(name, &error, &mut result);
                return result;
            }
        }
    } else {
        (Cow::Borrowed(data), None)
    };
    let mut archive = match zip::ZipArchive::new(Cursor::new(input.as_ref())) {
        Ok(archive) => archive,
        Err(error) => {
            attention(
                name,
                &format!(
                    "Could not read disambiguated ZIP archive: {error}; archive content unchecked."
                ),
                &mut result,
            );
            return result;
        }
    };
    if original_names
        .as_ref()
        .is_some_and(|names| names.len() != archive.len())
    {
        attention(
            name,
            "Duplicate ZIP names could not be preserved; archive content unchecked.",
            &mut result,
        );
        return result;
    }

    for ordinal in 0..archive.len() {
        if context.is_cancelled() {
            cancelled(name, &mut result);
            break;
        }
        let fallback_id = member_id(name, ordinal, "member");
        let (logical, directory, link, encrypted) = match archive.by_index_data(ordinal) {
            Ok(entry) => {
                let original = original_names
                    .as_ref()
                    .and_then(|names| names.get(ordinal))
                    .map(Vec::as_slice);
                let raw_name = original.unwrap_or_else(|| entry.name_raw());
                (
                    logical_name(raw_name),
                    entry.is_dir() || original.is_some_and(|name| name.ends_with(b"/")),
                    entry.is_symlink(),
                    entry.encrypted(),
                )
            }
            Err(error) => {
                attention(
                    &fallback_id,
                    &format!("ZIP member metadata could not be read: {error}; member unchecked."),
                    &mut result,
                );
                continue;
            }
        };
        let id = member_id(name, ordinal, &logical);
        if !context.reserve_archive_member() {
            attention(
                &id,
                "Archive member count limit reached; remaining archive content unchecked.",
                &mut result,
            );
            break;
        }
        emit_member_name(&id, &logical, &mut result);
        if directory {
            continue;
        }
        if encrypted {
            attention(
                &id,
                "Password-protected archive member; member unchecked.",
                &mut result,
            );
            continue;
        }
        if link {
            attention(
                &id,
                "Archive link not followed; member unchecked.",
                &mut result,
            );
            continue;
        }

        let mut entry = match archive.by_index(ordinal) {
            Ok(entry) => entry,
            Err(error) => {
                attention(
                    &id,
                    &format!("ZIP member could not be opened: {error}; member unchecked."),
                    &mut result,
                );
                continue;
            }
        };
        match read_bounded(&mut entry, context) {
            Ok(data) => merge(
                &mut result,
                super::extract_bytes_at(&id, &data, depth + 1, context),
            ),
            Err(error) => {
                let stop = report_member_error(&id, error, "", &mut result);
                if stop {
                    break;
                }
            }
        }
    }
    result
}

fn disambiguate_duplicate_zip_names(
    data: &[u8],
    central_start: u64,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let mut cursor = usize::try_from(central_start)
        .map_err(|_| "ZIP central directory offset is not addressable.".to_owned())?;
    let mut records = Vec::new();
    while data.get(cursor..cursor + 4) == Some(&[0x50, 0x4b, 0x01, 0x02]) {
        let fixed_end = cursor
            .checked_add(46)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                "Truncated ZIP central directory; duplicate names unchecked.".to_owned()
            })?;
        let length = |offset: usize| {
            usize::from(u16::from_le_bytes([
                data[cursor + offset],
                data[cursor + offset + 1],
            ]))
        };
        let name_length = length(28);
        let extra_length = length(30);
        let comment_length = length(32);
        let name_start = fixed_end;
        let name_end = name_start
            .checked_add(name_length)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| "Truncated ZIP member name; duplicate names unchecked.".to_owned())?;
        let record_end = name_end
            .checked_add(extra_length)
            .and_then(|end| end.checked_add(comment_length))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| "Truncated ZIP central entry; duplicate names unchecked.".to_owned())?;
        records.push((name_start..name_end, data[name_start..name_end].to_vec()));
        cursor = record_end;
    }
    if records.is_empty() {
        return Err("ZIP duplicate directory entries could not be located.".into());
    }

    let mut totals = HashMap::<&[u8], usize>::new();
    for (_, name) in &records {
        *totals.entry(name).or_default() += 1;
    }
    let mut used: HashSet<Vec<u8>> = records.iter().map(|(_, name)| name.clone()).collect();
    let mut seen = HashMap::<&[u8], usize>::new();
    let mut patched = data.to_vec();
    for (ordinal, (range, name)) in records.iter().enumerate() {
        let occurrence = seen.entry(name).or_default();
        let duplicate = totals.get(name.as_slice()).copied().unwrap_or(0) > 1 && *occurrence > 0;
        *occurrence += 1;
        if !duplicate {
            continue;
        }
        let replacement = unique_zip_name(name.len(), name.ends_with(b"/"), ordinal, &mut used)
            .ok_or_else(|| {
                "A duplicate ZIP name is too short to disambiguate safely; archive content unchecked."
                    .to_owned()
            })?;
        patched[range.clone()].copy_from_slice(&replacement);
    }
    let original_names = records.into_iter().map(|(_, name)| name).collect();
    Ok((patched, original_names))
}

fn unique_zip_name(
    length: usize,
    directory: bool,
    salt: usize,
    used: &mut HashSet<Vec<u8>>,
) -> Option<Vec<u8>> {
    if length == 0 || (directory && length == 1) {
        return None;
    }
    let encoded_length = length - usize::from(directory);
    let mut value = salt;
    loop {
        let mut candidate = vec![b'~'; length];
        if directory {
            candidate[length - 1] = b'/';
        }
        let mut remaining = value;
        for byte in candidate[..encoded_length].iter_mut().rev() {
            *byte = remaining as u8;
            remaining >>= 8;
        }
        if remaining != 0 {
            return None;
        }
        if used.insert(candidate.clone()) {
            return Some(candidate);
        }
        value = value.checked_add(1)?;
    }
}

fn extract_single_stream<R: Read>(
    name: &str,
    reader: R,
    kind: ArchiveKind,
    depth: usize,
    context: &ExtractionContext,
) -> Extraction {
    let mut result = Extraction::default();
    let logical = compressed_member_name(name, kind);
    let id = member_id(name, 0, &logical);
    if !context.reserve_archive_member() {
        attention(
            &id,
            "Archive member count limit reached; compressed stream was not checked.",
            &mut result,
        );
        return result;
    }
    emit_member_name(&id, &logical, &mut result);
    match read_bounded(reader, context) {
        Ok(data) => merge(
            &mut result,
            super::extract_bytes_at(&id, &data, depth + 1, context),
        ),
        Err(error) => {
            report_member_error(&id, error, "", &mut result);
        }
    }
    result
}

fn compressed_member_name(name: &str, kind: ArchiveKind) -> String {
    let file_name = Path::new(name)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("member");
    let mut stem = Path::new(file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("member")
        .to_owned();
    let tar_alias = match kind {
        ArchiveKind::Gzip => extension(name).is_some_and(|extension| extension == "tgz"),
        ArchiveKind::Bzip2 => {
            extension(name).is_some_and(|extension| matches!(extension.as_str(), "tbz" | "tbz2"))
        }
        ArchiveKind::Xz => extension(name).is_some_and(|extension| extension == "txz"),
        _ => false,
    };
    if tar_alias {
        stem.push_str(".tar");
    }
    stem
}

fn extract_tar(name: &str, data: &[u8], depth: usize, context: &ExtractionContext) -> Extraction {
    let mut result = Extraction::default();
    let mut archive = tar::Archive::new(data);
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            attention(
                name,
                &format!("Could not read TAR archive: {error}; archive content unchecked."),
                &mut result,
            );
            return result;
        }
    };

    for (ordinal, entry) in entries.enumerate() {
        if context.is_cancelled() {
            cancelled(name, &mut result);
            break;
        }
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                attention(
                    name,
                    &format!(
                        "TAR member metadata could not be read: {error}; remaining archive content unchecked."
                    ),
                    &mut result,
                );
                break;
            }
        };
        let logical = logical_name(entry.path_bytes().as_ref());
        let id = member_id(name, ordinal, &logical);
        if !context.reserve_archive_member() {
            attention(
                &id,
                "Archive member count limit reached; remaining archive content unchecked.",
                &mut result,
            );
            break;
        }
        emit_member_name(&id, &logical, &mut result);

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            attention(
                &id,
                "Archive link not followed; member unchecked.",
                &mut result,
            );
            continue;
        }
        if !(entry_type.is_file() || entry_type.is_contiguous() || entry_type.is_gnu_sparse()) {
            attention(
                &id,
                "Special TAR entry was not extracted; member unchecked.",
                &mut result,
            );
            continue;
        }

        match read_bounded(&mut entry, context) {
            Ok(data) => merge(
                &mut result,
                super::extract_bytes_at(&id, &data, depth + 1, context),
            ),
            Err(error) => {
                report_member_error(
                    &id,
                    error,
                    "; remaining sequential archive content unchecked",
                    &mut result,
                );
                // A TAR iterator may drain an unread payload to reach its sibling.
                // Stop rather than letting that bypass the expansion budgets.
                break;
            }
        }
    }
    result
}

fn extract_seven_zip(
    name: &str,
    data: &[u8],
    depth: usize,
    context: &ExtractionContext,
) -> Extraction {
    let mut result = Extraction::default();
    let mut reader = match sevenz_rust2::ArchiveReader::new_with_memory_limit(
        Cursor::new(data),
        sevenz_rust2::Password::empty(),
        seven_zip_memory_limit(context),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            attention(
                name,
                &format!("Could not read 7z archive: {error}; archive content unchecked."),
                &mut result,
            );
            return result;
        }
    };
    reader.set_thread_count(1);
    let ordinals: HashMap<_, _> = reader
        .archive()
        .files
        .iter()
        .enumerate()
        .map(|(ordinal, entry)| (entry as *const _, ordinal))
        .collect();
    let mut visited = HashSet::new();
    let mut member_budget_exhausted = false;
    let mut metadata_stopped = false;

    let iteration = reader.for_each_entries_with_decision(|entry, input| {
        if context.is_cancelled() {
            cancelled(name, &mut result);
            metadata_stopped = true;
            return Ok(sevenz_rust2::EntryDecision::Stop);
        }
        let Some(&ordinal) = ordinals.get(&(entry as *const _)) else {
            attention(
                name,
                "7z member identity could not be determined; remaining archive content unchecked.",
                &mut result,
            );
            metadata_stopped = true;
            return Ok(sevenz_rust2::EntryDecision::Stop);
        };
        visited.insert(ordinal);
        let logical = logical_name(entry.name.as_bytes());
        let id = member_id(name, ordinal, &logical);
        if !context.reserve_archive_member() {
            attention(
                &id,
                "Archive member count limit reached; remaining archive content unchecked.",
                &mut result,
            );
            member_budget_exhausted = true;
            return Ok(sevenz_rust2::EntryDecision::Stop);
        }
        emit_member_name(&id, &logical, &mut result);
        if entry.is_directory {
            return Ok(sevenz_rust2::EntryDecision::Continue);
        }
        if seven_zip_link(entry) {
            attention(
                &id,
                "Archive link not followed; dependent block members may be unchecked.",
                &mut result,
            );
            return Ok(sevenz_rust2::EntryDecision::SkipBlock);
        }

        match read_bounded(input, context) {
            Ok(data) => {
                merge(
                    &mut result,
                    super::extract_bytes_at(&id, &data, depth + 1, context),
                );
                Ok(sevenz_rust2::EntryDecision::Continue)
            }
            Err(error) => {
                let stop = report_member_error(
                    &id,
                    error,
                    "; dependent members in this compression block may be unchecked",
                    &mut result,
                );
                metadata_stopped |= stop;
                Ok(if stop {
                    sevenz_rust2::EntryDecision::Stop
                } else {
                    sevenz_rust2::EntryDecision::SkipBlock
                })
            }
        }
    });
    if let Err(error) = iteration {
        if context.is_cancelled() {
            if result.attention.is_empty() {
                cancelled(name, &mut result);
            }
        } else {
            attention(
                name,
                &format!(
                    "7z archive could not be fully read: {error}; remaining archive content unchecked."
                ),
                &mut result,
            );
        }
    }

    // Skipping a failed solid block skips its remaining callbacks. Their names
    // are still known metadata and must remain visible even though their content
    // cannot be recovered independently.
    if !metadata_stopped && !member_budget_exhausted {
        for (ordinal, entry) in reader.archive().files.iter().enumerate() {
            if visited.contains(&ordinal) {
                continue;
            }
            let logical = logical_name(entry.name.as_bytes());
            let id = member_id(name, ordinal, &logical);
            if !context.reserve_archive_member() {
                attention(
                    &id,
                    "Archive member count limit reached; remaining archive content unchecked.",
                    &mut result,
                );
                break;
            }
            emit_member_name(&id, &logical, &mut result);
        }
    }
    result
}

fn seven_zip_link(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    if !entry.has_windows_attributes {
        return false;
    }
    let attributes = entry.windows_attributes;
    let windows_reparse = attributes & 0x400 != 0;
    let unix_mode = attributes >> 16;
    windows_reparse || unix_mode & 0o170000 == 0o120000
}

fn seven_zip_memory_limit(context: &ExtractionContext) -> usize {
    usize::try_from(context.options.max_archive_bytes / 1024)
        .unwrap_or(usize::MAX)
        .clamp(1, usize::MAX / 1024)
}

fn xz_memory_limit(context: &ExtractionContext) -> u32 {
    u32::try_from(context.options.max_archive_bytes / 1024)
        .unwrap_or(u32::MAX)
        .max(1)
}

fn rar_link(member: &rars::ArchiveMember) -> bool {
    member.meta.is_redirection
        || (member.meta.attr_source() == rars::AttrSource::Unix
            && member.meta.file_attr & 0o170000 == 0o120000)
}

fn extract_rar(name: &str, data: &[u8], depth: usize, context: &ExtractionContext) -> Extraction {
    let mut result = Extraction::default();
    let archive = match rars::ArchiveReader::read(data) {
        Ok(archive) => archive,
        Err(error) => {
            attention(
                name,
                &format!("Could not read RAR archive: {error}; archive content unchecked."),
                &mut result,
            );
            return result;
        }
    };
    let solid = match &archive {
        rars::Archive::Rar13(archive) => archive.main.is_solid(),
        rars::Archive::Rar15To40(archive) => archive.main.is_solid(),
        rars::Archive::Rar50Plus(archive) => archive.main.is_solid(),
        _ => {
            attention(
                name,
                "Unsupported RAR archive variant; archive content unchecked.",
                &mut result,
            );
            return result;
        }
    };

    let result = RefCell::new(result);
    let ordinal = Cell::new(0_usize);
    let last_id = RefCell::new(name.to_owned());
    let pending = RefCell::new(None::<PendingRar>);
    let error_reported = Cell::new(false);
    let options =
        rars::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(RAR_BUFFERED_DECODE_LIMIT);
    let extraction = archive.extract_with_control_and_errors(
        options,
        |member| {
            finish_rar_member(
                &mut pending.borrow_mut(),
                depth,
                context,
                &mut result.borrow_mut(),
            );
            if context.is_cancelled() {
                cancelled(name, &mut result.borrow_mut());
                return Err(rars::Error::Cancelled);
            }

            let logical = logical_name(member.meta.name_bytes());
            let id = member_id(name, ordinal.get(), &logical);
            ordinal.set(ordinal.get() + 1);
            *last_id.borrow_mut() = id.clone();
            if !context.reserve_archive_member() {
                attention(
                    &id,
                    "Archive member count limit reached; remaining archive content unchecked.",
                    &mut result.borrow_mut(),
                );
                return Ok(rars::ExtractionDecision::Stop);
            }
            emit_member_name(&id, &logical, &mut result.borrow_mut());
            if member.meta.is_directory {
                return Ok(rars::ExtractionDecision::Skip);
            }
            if rar_link(member) {
                attention(
                    &id,
                    "Archive link not followed; member unchecked.",
                    &mut result.borrow_mut(),
                );
                return Ok(rars::ExtractionDecision::Skip);
            }
            if member.meta.is_split_before || member.meta.is_split_after {
                attention(
                    &id,
                    "Multi-volume RAR member is incomplete in a single in-memory archive; remaining archive content unchecked.",
                    &mut result.borrow_mut(),
                );
                return Ok(rars::ExtractionDecision::Stop);
            }
            if member.meta.is_encrypted {
                attention(
                    &id,
                    if solid {
                        "Password-protected RAR member; remaining solid archive content unchecked."
                    } else {
                        "Password-protected RAR member; member unchecked."
                    },
                    &mut result.borrow_mut(),
                );
                return Ok(if solid {
                    rars::ExtractionDecision::Stop
                } else {
                    rars::ExtractionDecision::Skip
                });
            }

            let bytes = Rc::new(RefCell::new(Vec::new()));
            let error = Rc::new(RefCell::new(None));
            let writer = RarWriter {
                context: context.clone(),
                bytes: Rc::clone(&bytes),
                error: Rc::clone(&error),
                maximum: context.options.max_file_bytes,
            };
            *pending.borrow_mut() = Some(PendingRar {
                id,
                bytes,
                error,
                publish: true,
            });
            Ok(rars::ExtractionDecision::Extract(Box::new(writer)))
        },
        |_member, error| {
            error_reported.set(true);
            let mut pending = pending.borrow_mut();
            if let Some(member) = pending.as_mut() {
                member.publish = false;
                let custom = member.error.borrow_mut().take();
                let stop = if let Some(custom) = custom {
                    report_member_error(&member.id, custom, "", &mut result.borrow_mut())
                } else {
                    attention(
                        &member.id,
                        &format!("RAR member could not be extracted: {error}; member unchecked."),
                        &mut result.borrow_mut(),
                    );
                    false
                };
                Ok(if stop {
                    rars::ExtractionErrorAction::Abort
                } else {
                    rars::ExtractionErrorAction::Continue
                })
            } else {
                attention(
                    &last_id.borrow(),
                    &format!("RAR member could not be extracted: {error}; remaining archive content unchecked."),
                    &mut result.borrow_mut(),
                );
                Ok(rars::ExtractionErrorAction::Abort)
            }
        },
    );

    if let Err(error) = extraction {
        if let Some(member) = pending.borrow_mut().as_mut() {
            member.publish = false;
        }
        if !error_reported.get() {
            let custom = pending
                .borrow()
                .as_ref()
                .and_then(|member| member.error.borrow_mut().take());
            if let Some(custom) = custom {
                report_member_error(
                    &last_id.borrow(),
                    custom,
                    "; remaining archive content unchecked",
                    &mut result.borrow_mut(),
                );
            } else if context.is_cancelled() || error.kind() == rars::ErrorKind::Cancelled {
                if result.borrow().attention.is_empty() {
                    cancelled(name, &mut result.borrow_mut());
                }
            } else {
                attention(
                    &last_id.borrow(),
                    &format!(
                        "RAR archive could not be fully read: {error}; remaining archive content unchecked."
                    ),
                    &mut result.borrow_mut(),
                );
            }
        }
    }
    finish_rar_member(
        &mut pending.borrow_mut(),
        depth,
        context,
        &mut result.borrow_mut(),
    );
    result.into_inner()
}

struct PendingRar {
    id: String,
    bytes: Rc<RefCell<Vec<u8>>>,
    error: Rc<RefCell<Option<MemberReadError>>>,
    publish: bool,
}

fn finish_rar_member(
    pending: &mut Option<PendingRar>,
    depth: usize,
    context: &ExtractionContext,
    result: &mut Extraction,
) {
    let Some(member) = pending.take() else {
        return;
    };
    if !member.publish {
        return;
    }
    let data = member.bytes.borrow();
    merge(
        result,
        super::extract_bytes_at(&member.id, &data, depth + 1, context),
    );
}

struct RarWriter {
    context: ExtractionContext,
    bytes: Rc<RefCell<Vec<u8>>>,
    error: Rc<RefCell<Option<MemberReadError>>>,
    maximum: u64,
}

impl Write for RarWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.error.borrow().is_some() {
            return Err(io::Error::other(
                "archive member output is no longer available",
            ));
        }
        let mut output = self.bytes.borrow_mut();
        if let Err(error) = append_bounded(&self.context, &mut output, bytes, self.maximum) {
            *self.error.borrow_mut() = Some(error);
            return Err(io::Error::other(
                "archive member output limit or cancellation",
            ));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum MemberReadError {
    Cancelled,
    SharedLimit,
    MemberLimit,
    Allocation,
    Io(io::Error),
}

fn read_bounded<R: Read>(
    reader: R,
    context: &ExtractionContext,
) -> Result<Vec<u8>, MemberReadError> {
    // `Take` is a hard per-member decoder ceiling. Shared accounting below uses
    // only bytes actually returned by the decoder, never an advertised size.
    let mut reader = reader.take(context.options.max_file_bytes.saturating_add(1));
    let mut output = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        if context.is_cancelled() {
            return Err(MemberReadError::Cancelled);
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(count) => append_bounded(
                context,
                &mut output,
                &buffer[..count],
                context.options.max_file_bytes,
            )?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(MemberReadError::Io(error)),
        }
    }
}

fn append_bounded(
    context: &ExtractionContext,
    output: &mut Vec<u8>,
    bytes: &[u8],
    maximum: u64,
) -> Result<(), MemberReadError> {
    if context.is_cancelled() {
        return Err(MemberReadError::Cancelled);
    }
    let count = u64::try_from(bytes.len()).map_err(|_| MemberReadError::MemberLimit)?;
    if !context.reserve_archive_bytes(count) {
        return Err(MemberReadError::SharedLimit);
    }
    let expanded = (output.len() as u64).saturating_add(count);
    if expanded > maximum {
        return Err(MemberReadError::MemberLimit);
    }
    output
        .try_reserve(bytes.len())
        .map_err(|_| MemberReadError::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(())
}

/// Returns true when no sibling or dependent stream may safely continue.
fn report_member_error(
    id: &str,
    error: MemberReadError,
    suffix: &str,
    result: &mut Extraction,
) -> bool {
    match error {
        MemberReadError::Cancelled => {
            cancelled(id, result);
            true
        }
        MemberReadError::SharedLimit => {
            attention(
                id,
                "Archive expanded byte budget reached; remaining archive content unchecked.",
                result,
            );
            true
        }
        MemberReadError::MemberLimit => {
            attention(
                id,
                &format!("Archive member expanded size limit reached; member unchecked{suffix}."),
                result,
            );
            false
        }
        MemberReadError::Allocation => {
            attention(
                id,
                &format!("Archive member buffer allocation failed; member unchecked{suffix}."),
                result,
            );
            false
        }
        MemberReadError::Io(error) => {
            attention(
                id,
                &format!(
                    "Archive member could not be extracted: {error}; member unchecked{suffix}."
                ),
                result,
            );
            false
        }
    }
}

fn logical_name(bytes: &[u8]) -> String {
    let name = String::from_utf8_lossy(bytes);
    if name.is_empty() {
        "member".into()
    } else {
        name.into_owned()
    }
}

fn member_id(parent: &str, ordinal: usize, logical: &str) -> String {
    format!("{parent}!entry:{ordinal}:{logical}")
}

fn emit_member_name(id: &str, logical: &str, result: &mut Extraction) {
    let origin = EvidenceOrigin {
        resource_id: id.to_owned(),
        stream_id: "name".into(),
        kind: EvidenceKind::ArchiveMemberName,
        representation: "synthesized-text".into(),
        chunk_start: 0,
        coordinate_unit: CoordinateUnit::Utf16CodeUnits,
        stride: 1,
    };
    result
        .parts
        .push(ExtractedPart::new(logical.replace('_', " "), origin).at("archive member name"));
}

fn merge(result: &mut Extraction, nested: Extraction) {
    result.parts.extend(nested.parts);
    result.attention.extend(nested.attention);
    result.partial |= nested.partial;
}

fn attention(resource_id: &str, message: &str, result: &mut Extraction) {
    result.partial = true;
    result.attention.push(AttentionItem {
        resource_id: resource_id.to_owned(),
        message: message.to_owned(),
    });
}

fn cancelled(resource_id: &str, result: &mut Extraction) {
    attention(
        resource_id,
        "Extraction cancelled or timed out; content was not fully checked.",
        result,
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use zip::write::SimpleFileOptions;

    use crate::ScanOptions;

    use super::*;

    fn context(configure: impl FnOnce(&mut ScanOptions)) -> ExtractionContext {
        let mut options = ScanOptions::default();
        configure(&mut options);
        ExtractionContext::for_root(Arc::new(options), Arc::new(AtomicBool::new(false)))
    }

    fn zip(entries: &[(&str, &[u8])], directories: &[&str]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for directory in directories {
            writer
                .add_directory(*directory, SimpleFileOptions::default())
                .unwrap();
        }
        for (name, data) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn zip_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new_stream(Cursor::new(Vec::new()));
        for (name, data) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner().into_inner()
    }

    fn names(result: &Extraction) -> Vec<(&str, &str)> {
        result
            .parts
            .iter()
            .filter(|part| part.origin.kind == EvidenceKind::ArchiveMemberName)
            .map(|part| (part.origin.resource_id.as_str(), part.text.as_str()))
            .collect()
    }

    #[test]
    fn duplicate_empty_and_directory_entries_have_stable_distinct_identities() {
        let mut bytes = zip(
            &[("same.txt", b""), ("peer.txt", b"second")],
            &["directory/"],
        );
        let positions: Vec<_> = bytes
            .windows(8)
            .enumerate()
            .filter_map(|(index, name)| (name == b"peer.txt").then_some(index))
            .collect();
        assert_eq!(
            positions.len(),
            2,
            "local and central names must both change"
        );
        for position in positions {
            bytes[position..position + 8].copy_from_slice(b"same.txt");
        }
        let result = extract("parent", &bytes, 0, &context(|_| {}));
        assert_eq!(
            names(&result),
            [
                ("parent!entry:0:directory/", "directory/"),
                ("parent!entry:1:same.txt", "same.txt"),
                ("parent!entry:2:same.txt", "same.txt"),
            ]
        );
        assert!(result.attention.is_empty());
    }

    #[test]
    fn duplicate_data_descriptor_entries_recurse_to_distinct_payloads() {
        let first = zip(&[("first.txt", b"")], &[]);
        let second = zip(&[("second.txt", b"")], &[]);
        let mut bytes = zip_stream(&[("same.zip", &first), ("peer.zip", &second)]);
        let positions: Vec<_> = bytes
            .windows(8)
            .enumerate()
            .filter_map(|(index, name)| (name == b"peer.zip").then_some(index))
            .collect();
        assert_eq!(positions.len(), 2);
        for position in positions {
            bytes[position..position + 8].copy_from_slice(b"same.zip");
        }
        let result = extract("parent", &bytes, 0, &context(|_| {}));
        let names = names(&result);
        assert!(
            names
                .iter()
                .any(|(id, _)| *id == "parent!entry:0:same.zip!entry:0:first.txt")
        );
        assert!(
            names
                .iter()
                .any(|(id, _)| *id == "parent!entry:1:same.zip!entry:0:second.txt")
        );
        assert!(result.attention.is_empty(), "{:?}", result.attention);
    }

    #[test]
    fn traversal_names_stay_logical_and_do_not_hide_the_healthy_sibling() {
        let bytes = zip(&[("../../escaped.txt", b"bad"), ("ok.txt", b"good")], &[]);
        let result = extract("parent", &bytes, 0, &context(|_| {}));
        assert_eq!(names(&result)[0].0, "parent!entry:0:../../escaped.txt");
        assert_eq!(names(&result)[1].0, "parent!entry:1:ok.txt");
        assert!(result.attention.is_empty());
    }

    #[test]
    fn encrypted_or_invalid_zip_member_does_not_hide_independent_siblings() {
        for encrypted in [false, true] {
            let mut bytes = zip(&[("bad.txt", b"broken"), ("good.txt", b"good")], &[]);
            let central = bytes
                .windows(4)
                .position(|window| window == [0x50, 0x4b, 0x01, 0x02])
                .unwrap();
            if encrypted {
                bytes[6] |= 1;
                bytes[central + 8] |= 1;
            } else {
                bytes[8] = 0xff;
                bytes[9] = 0xff;
                bytes[central + 10] = 0xff;
                bytes[central + 11] = 0xff;
            }
            let result = extract("parent", &bytes, 0, &context(|_| {}));
            assert!(
                result
                    .attention
                    .iter()
                    .any(|item| item.resource_id.ends_with(":bad.txt"))
            );
            assert!(
                names(&result)
                    .iter()
                    .any(|(id, _)| id.ends_with(":good.txt"))
            );
        }
    }

    #[test]
    fn member_and_shared_expanded_budgets_are_enforced_from_actual_output() {
        let bytes = zip(&[("large.txt", b"12345"), ("after.txt", b"ok")], &[]);
        let result = extract(
            "parent",
            &bytes,
            0,
            &context(|options| options.max_file_bytes = 4),
        );
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("expanded size"))
        );
        assert!(
            names(&result)
                .iter()
                .any(|(id, _)| id.ends_with(":after.txt"))
        );

        let result = extract(
            "parent",
            &bytes,
            0,
            &context(|options| options.max_archive_bytes = 5),
        );
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("byte budget"))
        );
    }

    #[test]
    fn directories_consume_the_shared_member_budget() {
        let bytes = zip(&[("unchecked.txt", b"text")], &["directory/"]);
        let result = extract(
            "parent",
            &bytes,
            0,
            &context(|options| options.max_archive_members = 1),
        );
        assert_eq!(names(&result).len(), 1);
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("member count"))
        );
    }

    #[test]
    fn depth_limit_and_cancellation_are_visible() {
        let bytes = zip(&[("file.txt", b"text")], &[]);
        let result = extract("parent", &bytes, 4, &context(|_| {}));
        assert!(result.parts.is_empty());
        assert!(result.attention[0].message.contains("nesting limit"));

        let options = Arc::new(ScanOptions::default());
        let cancelled_context =
            ExtractionContext::for_root(options, Arc::new(AtomicBool::new(true)));
        let result = extract("parent", &bytes, 0, &cancelled_context);
        assert!(result.parts.is_empty());
        assert!(result.attention[0].message.contains("cancelled"));
    }

    #[test]
    fn malformed_zip_reports_attention_instead_of_panicking() {
        let result = extract("broken.zip", b"not an archive", 0, &context(|_| {}));
        assert!(result.parts.is_empty());
        assert_eq!(result.attention.len(), 1);
        assert!(result.partial);
    }

    #[test]
    fn renamed_archive_fixtures_are_detected_by_magic() {
        const FIXTURES: &[(&str, &[u8])] = &[
            (
                "zip",
                include_bytes!("../../../../tests/fixtures/corpus/09_archives/team-backup.zip"),
            ),
            (
                "rar",
                include_bytes!("../../../../tests/fixtures/corpus/09_archives/records.rar"),
            ),
            (
                "7z",
                include_bytes!("../../../../tests/fixtures/corpus/09_archives/payroll.7z"),
            ),
            (
                "gzip",
                include_bytes!("../../../../tests/fixtures/corpus/09_archives/handover.txt.gz"),
            ),
        ];
        for (label, bytes) in FIXTURES {
            let result = extract("renamed.data", bytes, 0, &context(|_| {}));
            assert!(!result.parts.is_empty(), "{label} emitted no member names");
            assert!(
                result.attention.is_empty(),
                "{label}: {:?}",
                result.attention
            );
        }
    }

    #[test]
    fn rar_and_seven_zip_recover_independent_siblings_after_member_limits() {
        let cases: &[(&[u8], &str)] = &[
            (
                include_bytes!("../../../../tests/fixtures/corpus/09_archives/records.rar"),
                "contacts.txt",
            ),
            (
                include_bytes!("../../../../tests/fixtures/corpus/09_archives/payroll.7z"),
                "staff/contact.txt",
            ),
        ];
        for (bytes, rejected) in cases {
            let result = extract(
                "renamed.data",
                bytes,
                0,
                &context(|options| options.max_file_bytes = 110),
            );
            assert_eq!(
                names(&result).len(),
                2,
                "{rejected}: {:?}",
                result.attention
            );
            assert_eq!(result.attention.len(), 1, "{:?}", result.attention);
            assert!(result.attention[0].resource_id.ends_with(rejected));
            assert!(result.attention[0].message.contains("expanded size"));
        }
    }

    #[test]
    fn corpus_nested_archives_and_compressed_tar_recurse_in_memory() {
        let logs = include_bytes!("../../../../tests/fixtures/corpus/09_archives/logs.tar.gz");
        let result = extract("logs.tar.gz", logs, 0, &context(|_| {}));
        let log_names = names(&result);
        assert!(
            log_names
                .iter()
                .any(|(id, _)| { *id == "logs.tar.gz!entry:0:logs.tar!entry:0:logs/app.log" })
        );
        assert!(result.attention.is_empty(), "{:?}", result.attention);

        let nested =
            include_bytes!("../../../../tests/fixtures/corpus/09_archives/nested-outer.zip");
        let result = extract("nested-outer.zip", nested, 0, &context(|_| {}));
        let names = names(&result);
        assert!(
            names.iter().any(|(id, _)| {
                id.starts_with("nested-outer.zip!entry:0:layer1/inner.zip!entry:")
            })
        );
        assert!(result.attention.is_empty(), "{:?}", result.attention);
    }

    #[test]
    fn corpus_encryption_traversal_and_malformed_inputs_are_explicit() {
        let locked = include_bytes!("../../../../tests/fixtures/corpus/09_archives/locked.zip");
        let result = extract("locked.zip", locked, 0, &context(|_| {}));
        assert_eq!(names(&result).len(), 1);
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("Password-protected"))
        );

        let traversal =
            include_bytes!("../../../../tests/fixtures/corpus/09_archives/traversal.zip");
        let result = extract("traversal.zip", traversal, 0, &context(|_| {}));
        assert_eq!(names(&result).len(), 2);
        assert!(names(&result)[0].0.contains("../../../ESCAPED-pii.txt"));
        assert!(result.attention.is_empty());

        let broken = include_bytes!("../../../../tests/fixtures/corpus/09_archives/broken.zip");
        let result = extract("broken.zip", broken, 0, &context(|_| {}));
        assert!(!result.attention.is_empty());
    }

    #[test]
    fn corpus_zip_bomb_is_cut_off_by_actual_expanded_bytes() {
        let bomb = include_bytes!("../../../../tests/fixtures/corpus/09_archives/bomb.zip");
        let result = extract(
            "bomb.zip",
            bomb,
            0,
            &context(|options| {
                options.max_file_bytes = 1_024;
                options.max_archive_bytes = 2_048;
            }),
        );
        assert_eq!(names(&result).len(), 1);
        assert_eq!(result.attention.len(), 1);
        assert!(result.attention[0].message.contains("expanded size"));
    }

    #[test]
    fn bzip2_xz_and_tar_magic_are_supported_without_extensions() {
        let payload = b"printable archive payload";
        let mut bzip = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bzip.write_all(payload).unwrap();
        let bzip = bzip.finish().unwrap();

        let mut xz =
            lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::default()).unwrap();
        xz.write_all(payload).unwrap();
        let xz = xz.finish().unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, "file.txt", payload.as_slice())
            .unwrap();
        let tar = tar.into_inner().unwrap();

        for bytes in [bzip, xz, tar] {
            let result = extract("renamed.data", &bytes, 0, &context(|_| {}));
            assert!(!result.parts.is_empty());
            assert!(result.attention.is_empty(), "{:?}", result.attention);
        }
    }

    #[test]
    fn tar_links_are_named_but_never_followed() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder
            .append_link(&mut header, "link", "../../target")
            .unwrap();
        let bytes = builder.into_inner().unwrap();
        let result = extract("archive.tar", &bytes, 0, &context(|_| {}));
        assert_eq!(names(&result).len(), 1);
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("not followed"))
        );
    }
}
