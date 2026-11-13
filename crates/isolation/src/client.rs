use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use crossbeam_channel::{Receiver, Sender, bounded};
use pii_explorer_core::extract::{ExtractionContext, Extractor};
use pii_explorer_core::{AttentionItem, ExtractedPart, Extraction};

use crate::protocol::{
    MAX_FRAME, MAX_RECORDS, MAX_REQUESTS, MAX_RESPONSE, Request, Response, VERSION,
};

pub fn default_worker() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name(if cfg!(windows) {
        "pii-explorer-worker.exe"
    } else {
        "pii-explorer-worker"
    }))
}

pub struct WorkerPool {
    executable: PathBuf,
    idle: Mutex<Vec<Worker>>,
}

impl WorkerPool {
    pub fn new(executable: impl Into<PathBuf>) -> Result<Self> {
        let executable = executable.into();
        let metadata = std::fs::symlink_metadata(&executable)
            .context("extraction helper is missing; build/install pii-explorer-worker beside the application")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("extraction helper must be a regular executable")
        }
        Ok(Self {
            executable,
            idle: Mutex::new(Vec::new()),
        })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    fn run(&self, name: &str, data: &[u8], context: &ExtractionContext) -> Result<Extraction> {
        let mut worker = self
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .map_or_else(|| Worker::spawn(&self.executable), Ok)?;
        let mut options = (*context.options).clone();
        options.custom_rules.clear();
        options.excluded_directories.clear();
        options.detect_names = false;
        options.file_timeout = context
            .remaining_time()
            .context("extraction requires a deadline")?;
        let request = Request {
            version: VERSION,
            name: name.into(),
            length: data.len() as u64,
            tesseract_path: options.tesseract_path.clone(),
            tessdata_path: options.tessdata_path.clone(),
            options,
        };
        let mut header = serde_json::to_vec(&request)?;
        header.push(b'\n');
        if header.len() > MAX_FRAME {
            bail!("extraction request exceeds protocol budget")
        }
        let result = worker.exchange(&header, data, name, context);
        if result.is_ok() && worker.requests < MAX_REQUESTS && !context.is_cancelled() {
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if idle.len() < 8 {
                idle.push(worker);
            }
        }
        result
    }
}

impl Extractor for WorkerPool {
    fn extract(&self, name: &str, data: &[u8], context: &ExtractionContext) -> Extraction {
        if context.is_cancelled() {
            return failure(name, "Extraction cancelled or timed out before dispatch");
        }
        match self.run(name, data, context) {
            Ok(extraction) => extraction,
            Err(error) => failure(
                name,
                &format!("Isolated extraction did not complete: {error:#}"),
            ),
        }
    }
}

fn failure(name: &str, reason: &str) -> Extraction {
    Extraction {
        partial: true,
        attention: vec![AttentionItem {
            resource_id: name.into(),
            message: format!(
                "{reason}; content was not fully checked. The next resource receives a fresh worker."
            ),
        }],
        ..Extraction::default()
    }
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    frames: Option<Receiver<Result<Vec<u8>, &'static str>>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    requests: usize,
}

impl Worker {
    fn spawn(executable: &Path) -> Result<Self> {
        let mut command = Command::new(executable);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Do not pass credentials, model caches or user-provided dynamic-loader variables.
        // Tesseract and asset locations are explicit in the request.
        command.env_clear();
        #[cfg(windows)]
        for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn().context("cannot start extraction helper")?;
        let stdin = child.stdin.take().context("worker stdin unavailable")?;
        let mut stdout = child.stdout.take().context("worker stdout unavailable")?;
        #[cfg(unix)]
        {
            use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
            if let Err(error) = fcntl_getfl(&stdout)
                .and_then(|flags| fcntl_setfl(&stdout, flags | OFlags::NONBLOCK))
                .and_then(|()| {
                    fcntl_getfl(&stdin)
                        .and_then(|flags| fcntl_setfl(&stdin, flags | OFlags::NONBLOCK))
                })
            {
                terminate(&mut child);
                return Err(error).context("cannot configure bounded worker reads");
            }
        }
        let (sender, frames) = bounded(8);
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = stop.clone();
        let reader = std::thread::Builder::new()
            .name("extraction-pipe".into())
            .spawn(move || {
                let mut pending = Vec::new();
                let mut buffer = [0_u8; 8192];
                while !reader_stop.load(Ordering::Relaxed) {
                    match stdout.read(&mut buffer) {
                        Ok(0) => {
                            let _ = send_frame(
                                &sender,
                                Err("worker exited before its completion record"),
                                &reader_stop,
                            );
                            break;
                        }
                        Ok(count) => {
                            for byte in &buffer[..count] {
                                pending.push(*byte);
                                if pending.len() > MAX_FRAME {
                                    let _ = send_frame(
                                        &sender,
                                        Err("worker frame exceeds protocol budget"),
                                        &reader_stop,
                                    );
                                    return;
                                }
                                if *byte == b'\n'
                                    && !send_frame(
                                        &sender,
                                        Ok(std::mem::take(&mut pending)),
                                        &reader_stop,
                                    )
                                {
                                    return;
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            #[cfg(unix)]
                            if wait_pipe(&stdout, false).is_err() {
                                let _ = send_frame(
                                    &sender,
                                    Err("worker pipe readiness failed"),
                                    &reader_stop,
                                );
                                break;
                            }
                            #[cfg(not(unix))]
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => {
                            let _ = send_frame(&sender, Err("worker pipe failed"), &reader_stop);
                            break;
                        }
                    }
                }
            });
        let reader = match reader {
            Ok(reader) => reader,
            Err(error) => {
                terminate(&mut child);
                return Err(error).context("cannot start worker reader");
            }
        };
        Ok(Self {
            child,
            stdin,
            frames: Some(frames),
            stop,
            reader: Some(reader),
            requests: 0,
        })
    }

    fn exchange(
        &mut self,
        header: &[u8],
        data: &[u8],
        name: &str,
        context: &ExtractionContext,
    ) -> Result<Extraction> {
        self.requests += 1;
        let Self {
            child,
            stdin,
            frames,
            ..
        } = self;
        let frames = frames
            .as_ref()
            .context("worker response channel unavailable")?;
        std::thread::scope(|scope| {
            let (written, received) = bounded(1);
            scope.spawn(move || {
                let result = write_input(stdin, header, context)
                    .and_then(|()| write_input(stdin, data, context));
                let _ = written.send(result);
            });
            let result = receive(frames, name, context);
            let result = result.and_then(|extraction| {
                loop {
                    if context.is_cancelled() {
                        bail!("worker deadline/cancellation reached while writing input")
                    }
                    match received.recv_timeout(Duration::from_millis(25)) {
                        Ok(result) => {
                            result.context("worker input pipe failed")?;
                            return Ok(extraction);
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(_) => bail!("worker input writer stopped"),
                    }
                }
            });
            // Killing the reader process closes its stdin before scoped writer joining.
            if result.is_err() {
                kill_held(child);
            }
            result
        })
    }
}

fn receive(
    frames: &Receiver<Result<Vec<u8>, &'static str>>,
    name: &str,
    context: &ExtractionContext,
) -> Result<Extraction> {
    let mut extraction = Extraction::default();
    let mut part: Option<ExtractedPart> = None;
    let mut bytes = 0_usize;
    let mut units = 0_usize;
    let mut count = 0_usize;
    loop {
        if context.is_cancelled() {
            bail!("worker deadline/cancellation reached")
        }
        let frame = match frames.recv_timeout(Duration::from_millis(25)) {
            Ok(Ok(frame)) => frame,
            Ok(Err(reason)) => bail!(reason),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(_) => bail!("worker response channel closed"),
        };
        bytes = bytes.saturating_add(frame.len());
        count += 1;
        if bytes > MAX_RESPONSE || count > MAX_RECORDS {
            bail!("worker response exceeds protocol budget")
        }
        let response: Response = serde_json::from_slice(&frame)
            .map_err(|_| anyhow::anyhow!("invalid worker response"))?;
        match response {
            Response::Part {
                origin,
                location,
                continues_before,
                continues_after,
            } => {
                if part.is_some()
                    || !belongs_to(&origin.resource_id, name)
                    || origin.stream_id.len() > 65_536
                    || origin.representation.len() > 65_536
                    || !(1..=4).contains(&origin.stride)
                    || location
                        .as_ref()
                        .is_some_and(|location| location.len() > 65_536)
                {
                    bail!("worker returned invalid evidence provenance")
                }
                part = Some(ExtractedPart {
                    text: String::new(),
                    location,
                    origin,
                    continues_before,
                    continues_after,
                });
            }
            Response::Text { text } => {
                let part = part
                    .as_mut()
                    .context("worker text has no evidence origin")?;
                units = units.saturating_add(text.encode_utf16().count());
                if units > context.options.max_extracted_utf16 {
                    bail!("worker exceeded extracted-text budget")
                }
                part.text.push_str(&text);
            }
            Response::PartEnd => extraction
                .parts
                .push(part.take().context("worker part ended without an origin")?),
            Response::Attention(attention) => {
                if !belongs_to(&attention.resource_id, name)
                    || attention.message.len() > 65_536
                    || extraction.attention.len() >= context.options.max_attention
                {
                    bail!("worker exceeded attention/provenance budget")
                }
                extraction.attention.push(attention);
            }
            Response::End { version, partial } => {
                if version != VERSION || part.is_some() {
                    bail!("worker completion record is inconsistent")
                }
                extraction.partial = partial;
                return Ok(extraction);
            }
        }
    }
}

fn belongs_to(resource: &str, root: &str) -> bool {
    resource.len() <= 65_536
        && (resource == root
            || resource
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('/') || suffix.starts_with("!entry:")))
}

fn send_frame(
    sender: &Sender<Result<Vec<u8>, &'static str>>,
    mut frame: Result<Vec<u8>, &'static str>,
    stop: &AtomicBool,
) -> bool {
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        match sender.send_timeout(frame, Duration::from_millis(25)) {
            Ok(()) => return true,
            Err(crossbeam_channel::SendTimeoutError::Timeout(value)) => frame = value,
            Err(_) => return false,
        }
    }
}

fn write_input(
    stdin: &mut ChildStdin,
    mut data: &[u8],
    context: &ExtractionContext,
) -> std::io::Result<()> {
    while !data.is_empty() {
        if context.is_cancelled() {
            return Err(std::io::Error::other("worker input cancelled"));
        }
        match stdin.write(data) {
            Ok(0) => return Err(std::io::Error::other("worker input pipe closed")),
            Ok(length) => data = &data[length..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                #[cfg(unix)]
                wait_pipe(stdin, true)?;
                #[cfg(not(unix))]
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn wait_pipe(pipe: &impl std::os::fd::AsFd, writable: bool) -> std::io::Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let flags = if writable {
        PollFlags::OUT
    } else {
        PollFlags::IN
    };
    let mut descriptors = [PollFd::new(pipe, flags)];
    match poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 25_000_000,
        }),
    ) {
        Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn kill_held(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32)
        .filter(|pid| pid.as_raw_nonzero().get() > 1)
    {
        // The child remains unreaped until this point, so its group ID cannot be reused.
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
}

fn terminate(child: &mut Child) {
    kill_held(child);
    let _ = child.wait();
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.frames.take();
        terminate(&mut self.child);
        #[cfg(unix)]
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        // Windows anonymous-pipe reads can remain blocked if another process inherited a
        // handle. Detach rather than block the coordinator; Job Object support is pending.
    }
}
