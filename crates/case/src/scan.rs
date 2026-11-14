use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use pii_explorer_core::hash::sha256_reader;
use pii_explorer_core::{AttentionItem, ScanEvent, ScanSummary, Scanner};
use serde_json::Value;
use walkdir::WalkDir;

use crate::{CaseStore, CaseSummary};

pub struct CaseScanOptions {
    pub resume: bool,
    pub refresh: bool,
    /// Fingerprint the executable, models and OCR environment, not just a version string.
    pub engine: Value,
}

pub fn scan_case(
    scanner: Scanner,
    root: &Path,
    case: &Path,
    options: CaseScanOptions,
    cancelled: Arc<AtomicBool>,
) -> Result<CaseSummary> {
    let started = Instant::now();
    let root = root.canonicalize().context("resolve evidence root")?;
    let metadata = std::fs::symlink_metadata(&root)?;
    if !metadata.is_file() && !metadata.is_dir() {
        bail!("evidence root must be a file or directory");
    }
    if root.to_str().is_none() {
        bail!("the evidence root must have a UTF-8 path");
    }
    let case = absolute_destination(case)?;
    if (metadata.is_dir() && case.starts_with(&root)) || case == root {
        bail!("place the case database outside the evidence root");
    }
    let mut store = if options.resume {
        CaseStore::open(&case, false)?
    } else {
        CaseStore::create(&case, &root)?
    };
    let _capture_lock = store.capture_lock()?;
    let (run, config) = store.begin_run(&root, scanner.options(), &options.engine)?;
    for item in scanner.startup_attention() {
        store.run_attention(run, item)?;
    }
    let workers = scanner.options().workers;
    let excluded = scanner.options().excluded_directories.clone();
    let max_bytes = scanner.options().max_file_bytes;
    let scanner = scanner.with_result_retention(false);
    let store = Arc::new(Mutex::new(store));
    let failure = Arc::new(Mutex::new(None::<String>));
    let (sender, receiver) = crossbeam_channel::bounded::<(PathBuf, String)>(64);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let scanner = &scanner;
            let receiver = receiver.clone();
            let store = store.clone();
            let cancelled = cancelled.clone();
            let failure = failure.clone();
            let config = &config;
            let refresh = options.refresh;
            scope.spawn(move || {
                while let Ok((path, resource)) = receiver.recv() {
                    if cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    let outcome = process(
                        scanner, &store, run, config, &path, &resource, max_bytes, refresh,
                        &cancelled,
                    );
                    if let Err(error) = outcome {
                        *failure
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(format!("case checkpoint failed: {error:#}"));
                        cancelled.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            });
        }
        drop(receiver);
        let inventory = (|| -> Result<()> {
            let base = if metadata.is_dir() {
                &root
            } else {
                root.parent().context("source parent")?
            };
            let walker = WalkDir::new(&root)
                .follow_links(false)
                .max_open(32)
                .into_iter()
                .filter_entry(|entry| {
                    if cancelled.load(Ordering::Relaxed) { return false; }
                    if entry.depth() > 0
                            && entry.file_type().is_dir()
                            && entry
                                .file_name()
                                .to_str()
                                .is_some_and(|name| excluded.contains(name)) {
                        let resource_id = entry.path().strip_prefix(base).ok().and_then(Path::to_str).unwrap_or("discovery").replace('\\',"/");
                        let outcome = store.lock().map_err(|_| anyhow::anyhow!("case lock poisoned")).and_then(|store| store.run_attention(run,&AttentionItem {resource_id,message:"Excluded dependency or system directory was not scanned.".into()}));
                        if let Err(error) = outcome {
                            *failure.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
                            cancelled.store(true,Ordering::Relaxed);
                        }
                        return false;
                    }
                    true
                });
            let mut pending = Vec::with_capacity(64);
            for entry in walker {
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        store.lock().map_err(|_| anyhow::anyhow!("case lock poisoned"))?.run_attention(run, &AttentionItem { resource_id:"discovery".into(),message:"A filesystem entry could not be inspected; discovery coverage is incomplete.".into() })?;
                        continue;
                    }
                };
                let Some(relative) = entry.path().strip_prefix(base).ok().and_then(Path::to_str)
                else {
                    store.lock().map_err(|_| anyhow::anyhow!("case lock poisoned"))?.run_attention(run, &AttentionItem {resource_id:"discovery".into(),message:"A non-UTF-8 filesystem name could not be represented safely and was not scanned.".into()})?;
                    continue;
                };
                let resource = relative.replace('\\', "/");
                if entry.file_type().is_symlink() {
                    store
                        .lock()
                        .map_err(|_| anyhow::anyhow!("case lock poisoned"))?
                        .run_attention(
                            run,
                            &AttentionItem {
                                resource_id: resource,
                                message: "Symbolic link was not followed.".into(),
                            },
                        )?;
                    continue;
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                pending.push((entry.into_path(), resource));
                if pending.len() >= 64 && !enqueue(&store, run, &sender, &mut pending)? {
                    break;
                }
            }
            if !pending.is_empty() {
                enqueue(&store, run, &sender, &mut pending)?;
            }
            Ok(())
        })();
        if let Err(error) = inventory {
            *failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(format!("case inventory failed: {error:#}"));
            cancelled.store(true, Ordering::Relaxed);
        }
        drop(sender);
    });
    if let Some(error) = failure
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        bail!("{error}");
    }
    let mut store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("case lock poisoned"))?;
    store.finish_run(
        run,
        cancelled.load(Ordering::Relaxed),
        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    )
}

fn enqueue(
    store: &Mutex<CaseStore>,
    run: i64,
    sender: &crossbeam_channel::Sender<(PathBuf, String)>,
    pending: &mut Vec<(PathBuf, String)>,
) -> Result<bool> {
    // Discovery is durable before dispatch, with one journal sync per bounded batch.
    // Each root's completed capture still has its own atomic durability checkpoint.
    store
        .lock()
        .map_err(|_| anyhow::anyhow!("case lock poisoned"))?
        .reserve_many(run, pending.iter().map(|(_, resource)| resource.as_str()))?;
    for resource in pending.drain(..) {
        if sender.send(resource).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn process(
    scanner: &Scanner,
    store: &Mutex<CaseStore>,
    run: i64,
    config: &str,
    path: &Path,
    resource: &str,
    max_bytes: u64,
    refresh: bool,
    cancelled: &Arc<AtomicBool>,
) -> Result<()> {
    let digest = if refresh {
        None
    } else {
        source_hash(path, max_bytes, cancelled).ok().flatten()
    };
    if cancelled.load(Ordering::Relaxed) {
        return Ok(());
    }
    let snapshot = store
        .lock()
        .map_err(|_| anyhow::anyhow!("case lock poisoned"))?
        .start_resource(run, resource, config, digest.as_deref(), refresh)?;
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let write_failure = Mutex::new(None::<String>);
    let result = scanner.scan_resource_with_events(path, resource, cancelled.clone(), |event| {
        if matches!(event, ScanEvent::Progress(_)) {
            return;
        }
        let outcome = store
            .lock()
            .map_err(|_| anyhow::anyhow!("case lock poisoned"))
            .and_then(|mut store| store.record(snapshot, event));
        if let Err(error) = outcome {
            *write_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
            cancelled.store(true, Ordering::Relaxed);
        }
    });
    if let Some(error) = write_failure
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        bail!("{error}");
    }
    let summary = match result {
        Ok(result) => result.summary,
        Err(_) => {
            store.lock().map_err(|_| anyhow::anyhow!("case lock poisoned"))?.record(snapshot, ScanEvent::Attention(vec![AttentionItem {resource_id:resource.into(),message:"Source became inaccessible or ceased to be a regular file before scanning.".into()}]))?;
            ScanSummary {
                discovered: 1,
                completed: 1,
                attention: 1,
                ..ScanSummary::default()
            }
        }
    };
    store
        .lock()
        .map_err(|_| anyhow::anyhow!("case lock poisoned"))?
        .finish_resource(run, snapshot, &summary)?;
    Ok(())
}

struct CancelledReader<'a> {
    file: File,
    cancelled: &'a AtomicBool,
}
impl Read for CancelledReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("cancelled"));
        }
        self.file.read(bytes)
    }
}

fn source_hash(path: &Path, max_bytes: u64, cancelled: &AtomicBool) -> Result<Option<String>> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Ok(None);
    }
    let file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > max_bytes {
        return Ok(None);
    }
    let mut reader = CancelledReader { file, cancelled };
    let digest = sha256_reader(&mut reader.by_ref().take(max_bytes.saturating_add(1)))?;
    let after = reader.file.metadata()?;
    if cancelled.load(Ordering::Relaxed)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Ok(None);
    }
    Ok(Some(digest))
}

fn absolute_destination(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent
        .canonicalize()?
        .join(path.file_name().context("case filename")?))
}
