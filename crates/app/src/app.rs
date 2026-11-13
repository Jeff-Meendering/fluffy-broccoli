use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, Vec2};
use pii_explorer_core::scanner::{ScanEvent, Scanner};
use pii_explorer_core::{
    AttentionItem, CoordinateUnit, EntityType, EvidenceKind, Finding, ScanOptions, ScanResult,
};

use crate::export::{
    ensure_json_extension, ensure_pdf_extension, export_json, export_pdf,
    validate_export_destination,
};
use crate::filter::FindingFilter;
use crate::preferences::{ThemeChoice, load_theme, save_theme};
use crate::settings::{ScanSettings, resolve_folder};
use crate::source::reveal_source;
use crate::state::ReviewState;

const MAX_MESSAGES_PER_FRAME: usize = 192;
const FILTER_DELAY: Duration = Duration::from_millis(140);

#[derive(Debug)]
enum WorkerMessage {
    Event(ScanEvent),
    Finished(Box<Result<ScanResult, String>>),
}

#[derive(Debug)]
struct ScanTask {
    cancelled: Arc<AtomicBool>,
    receiver: Receiver<WorkerMessage>,
    handle: JoinHandle<()>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ResultsTab {
    #[default]
    Findings,
    Attention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selection {
    Finding(usize),
    Attention(usize),
}

#[derive(Debug)]
enum DetailAction {
    Copy(String),
    Reveal(String),
}

#[derive(Clone, Copy)]
struct Palette {
    canvas: Color32,
    surface: Color32,
    line: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    accent_ink: Color32,
    warning: Color32,
    header: Color32,
}

impl Palette {
    fn from_ui(ui: &egui::Ui) -> Self {
        if ui.visuals().dark_mode {
            Self {
                canvas: Color32::from_rgb(0x10, 0x17, 0x1f),
                surface: Color32::from_rgb(0x19, 0x23, 0x2e),
                line: Color32::from_rgb(0x33, 0x43, 0x52),
                text: Color32::from_rgb(0xe4, 0xeb, 0xf1),
                muted: Color32::from_rgb(0xa1, 0xb1, 0xc0),
                accent: Color32::from_rgb(0x63, 0xd3, 0xbf),
                accent_ink: Color32::from_rgb(0x10, 0x2b, 0x28),
                warning: Color32::from_rgb(0xf1, 0xbe, 0x70),
                header: Color32::from_rgb(0x14, 0x27, 0x30),
            }
        } else {
            Self {
                canvas: Color32::from_rgb(0xf3, 0xf5, 0xf8),
                surface: Color32::WHITE,
                line: Color32::from_rgb(0xd2, 0xdc, 0xe5),
                text: Color32::from_rgb(0x20, 0x32, 0x40),
                muted: Color32::from_rgb(0x52, 0x66, 0x75),
                accent: Color32::from_rgb(0x08, 0x70, 0x68),
                accent_ink: Color32::WHITE,
                warning: Color32::from_rgb(0x86, 0x50, 0x10),
                header: Color32::from_rgb(0x17, 0x35, 0x41),
            }
        }
    }
}

pub struct ExplorerApp {
    folder: String,
    settings: ScanSettings,
    theme: ThemeChoice,
    review: ReviewState,
    filter: FindingFilter,
    search: String,
    entity_filter: Option<EntityType>,
    filter_dirty_since: Option<Instant>,
    active_tab: ResultsTab,
    selection: Option<Selection>,
    scan: Option<ScanTask>,
    scan_root: Option<PathBuf>,
    has_result: bool,
    hide_file_names_in_report: bool,
    include_context_in_report: bool,
    close_requested: bool,
    status: String,
}

impl ExplorerApp {
    #[must_use]
    pub fn new(creation: &eframe::CreationContext<'_>) -> Self {
        let theme = load_theme();
        theme.apply(&creation.egui_ctx);
        configure_styles(&creation.egui_ctx);
        Self {
            folder: String::new(),
            settings: ScanSettings::default(),
            theme,
            review: ReviewState::default(),
            filter: FindingFilter::default(),
            search: String::new(),
            entity_filter: None,
            filter_dirty_since: None,
            active_tab: ResultsTab::Findings,
            selection: None,
            scan: None,
            scan_root: None,
            has_result: false,
            hide_file_names_in_report: false,
            include_context_in_report: false,
            close_requested: false,
            status: "Ready. Source files are not changed, and findings are never saved unless you export them."
                .into(),
        }
    }

    fn is_scanning(&self) -> bool {
        self.scan.is_some()
    }

    fn is_stopping(&self) -> bool {
        self.scan
            .as_ref()
            .is_some_and(|task| task.cancelled.load(Ordering::Relaxed))
    }

    fn start_scan(&mut self, context: &egui::Context) {
        if self.is_scanning() {
            return;
        }
        let root = match resolve_folder(&self.folder) {
            Ok(root) => root,
            Err(error) => {
                self.status = error;
                return;
            }
        };
        let options = match self.settings.scan_options() {
            Ok(options) => options,
            Err(error) => {
                self.status = error;
                return;
            }
        };

        self.review.reset();
        self.selection = None;
        self.has_result = false;
        self.scan_root = Some(root.clone());
        self.status = "Discovering files and loading local detection…".into();

        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let (sender, receiver) = crossbeam_channel::bounded(512);
        let context = context.clone();
        let spawn = thread::Builder::new()
            .name("pii-explorer-scan".into())
            .spawn(move || run_scan(root, options, worker_cancelled, sender, context));
        match spawn {
            Ok(handle) => {
                self.scan = Some(ScanTask {
                    cancelled,
                    receiver,
                    handle,
                });
            }
            Err(error) => {
                self.status = format!("Could not start the scan worker: {error}");
            }
        }
    }

    fn stop_scan(&mut self) {
        if let Some(task) = &self.scan {
            task.cancelled.store(true, Ordering::Relaxed);
            self.status = "Stopping after active file operations finish…".into();
        }
    }

    fn drain_worker(&mut self, context: &egui::Context) {
        let mut finished = None;
        let mut disconnected = false;
        if let Some(task) = &self.scan {
            for _ in 0..MAX_MESSAGES_PER_FRAME {
                match task.receiver.try_recv() {
                    Ok(WorkerMessage::Event(event)) => {
                        let is_progress = matches!(event, ScanEvent::Progress(_));
                        self.review.apply_event(event, &self.filter);
                        if is_progress && !task.cancelled.load(Ordering::Relaxed) {
                            self.status = format!(
                                "Checking files locally · {} / {} completed",
                                self.review.progress.completed, self.review.progress.discovered
                            );
                        }
                    }
                    Ok(WorkerMessage::Finished(result)) => {
                        finished = Some(result);
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        if let Some(result) = finished {
            self.finish_scan(*result);
        } else if disconnected {
            if let Some(task) = self.scan.take() {
                let _ = task.handle.join();
            }
            self.status = "The scan worker stopped unexpectedly. Partial results remain available for review.".into();
        }

        if self.is_scanning() || self.filter_dirty_since.is_some() {
            context.request_repaint_after(Duration::from_millis(60));
        }
        if self.close_requested && !self.is_scanning() {
            context.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn finish_scan(&mut self, outcome: Result<ScanResult, String>) {
        let selected_finding = self.selected_finding_key();
        let selected_attention = self.selected_attention_key();
        match outcome {
            Ok(result) => {
                let summary = result.summary.clone();
                self.review.finish(result, &self.filter);
                self.has_result = true;
                let state = if summary.cancelled {
                    "Stopped"
                } else {
                    "Finished"
                };
                self.status = format!(
                    "{state} · {} / {} files · {} findings · {} attention items · {:.1}s",
                    summary.completed,
                    summary.discovered,
                    summary.findings,
                    summary.attention,
                    summary.elapsed_ms as f64 / 1000.0
                );
                if let Some(limit) = summary.limit_reached {
                    self.status.push_str(&format!(" · {limit} reached"));
                }
            }
            Err(error) => {
                self.has_result = false;
                self.status =
                    format!("Scan failed: {error}. Partial results remain available for review.");
            }
        }
        if let Some(task) = self.scan.take() {
            let _ = task.handle.join();
        }
        self.restore_selection(selected_finding, selected_attention);
    }

    fn selected_finding_key(&self) -> Option<(String, String, EntityType, u64, u64)> {
        match self.selection {
            Some(Selection::Finding(index)) => {
                self.review.result.findings.get(index).map(|finding| {
                    let key = finding.occurrence_key();
                    (key.0.to_owned(), key.1.to_owned(), key.2, key.3, key.4)
                })
            }
            _ => None,
        }
    }

    fn selected_attention_key(&self) -> Option<(String, String)> {
        match self.selection {
            Some(Selection::Attention(index)) => self
                .review
                .result
                .attention
                .get(index)
                .map(|item| (item.resource_id.clone(), item.message.clone())),
            _ => None,
        }
    }

    fn restore_selection(
        &mut self,
        finding_key: Option<(String, String, EntityType, u64, u64)>,
        attention_key: Option<(String, String)>,
    ) {
        self.selection = if let Some(key) = finding_key {
            self.review
                .result
                .findings
                .iter()
                .position(|finding| {
                    finding.occurrence_key()
                        == (key.0.as_str(), key.1.as_str(), key.2, key.3, key.4)
                })
                .map(Selection::Finding)
        } else if let Some(key) = attention_key {
            self.review
                .result
                .attention
                .iter()
                .position(|item| item.resource_id == key.0 && item.message == key.1)
                .map(Selection::Attention)
        } else {
            None
        };
        self.ensure_selection_visible();
    }

    fn mark_filter_changed(&mut self) {
        self.filter_dirty_since = Some(Instant::now());
    }

    fn apply_pending_filter(&mut self, force: bool) {
        let Some(changed) = self.filter_dirty_since else {
            return;
        };
        let item_count = self.review.result.findings.len() + self.review.result.attention.len();
        if !force && item_count >= 5_000 && changed.elapsed() < FILTER_DELAY {
            return;
        }
        self.filter = FindingFilter::new(&self.search, self.entity_filter);
        self.review.refilter(&self.filter);
        self.filter_dirty_since = None;
        self.ensure_selection_visible();
    }

    fn ensure_selection_visible(&mut self) {
        let visible = match self.selection {
            Some(Selection::Finding(index)) => self.review.visible_findings.contains(&index),
            Some(Selection::Attention(index)) => self.review.visible_attention.contains(&index),
            None => true,
        };
        if !visible {
            self.selection = None;
        }
    }

    fn choose_folder(&mut self) {
        let mut dialog = rfd::FileDialog::new().set_title("Choose a folder to scan");
        if let Ok(root) = resolve_folder(&self.folder) {
            dialog = dialog.set_directory(root);
        }
        if let Some(path) = dialog.pick_folder() {
            self.folder = path.to_string_lossy().into_owned()
        }
    }

    fn export_all_json(&mut self) {
        if self.is_scanning() || !self.has_result {
            return;
        }
        let Some(root) = self.scan_root.as_deref() else {
            return;
        };
        let Some(mut destination) = rfd::FileDialog::new()
            .set_title("Save all PII findings as JSON (choose a new filename)")
            .set_file_name("pii-findings.json")
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };
        ensure_json_extension(&mut destination);
        let outcome = validate_export_destination(&destination)
            .and_then(|()| export_json(&destination, root, &self.review.result));
        self.status = match outcome {
            Ok(()) => format!(
                "JSON saved with all {} findings and {} attention items: {}",
                self.review.result.findings.len(),
                self.review.result.attention.len(),
                destination.display()
            ),
            Err(error) => format!("Could not save JSON: {error:#}"),
        };
    }

    fn export_all_pdf(&mut self) {
        if self.is_scanning() || !self.has_result {
            return;
        }
        let Some(root) = self.scan_root.as_deref() else {
            return;
        };
        let Some(mut destination) = rfd::FileDialog::new()
            .set_title("Save all PII findings as PDF (choose a new filename)")
            .set_file_name("pii-findings.pdf")
            .add_filter("PDF report", &["pdf"])
            .save_file()
        else {
            return;
        };
        ensure_pdf_extension(&mut destination);
        let outcome = validate_export_destination(&destination).and_then(|()| {
            export_pdf(
                &destination,
                root,
                &self.review.result,
                self.hide_file_names_in_report,
                self.include_context_in_report,
            )
            .map_err(anyhow::Error::from)
        });
        self.status = match outcome {
            Ok(()) => format!(
                "PDF saved with all {} findings and {} attention items. Identifying metadata is omitted: {}",
                self.review.result.findings.len(),
                self.review.result.attention.len(),
                destination.display()
            ),
            Err(error) => format!("Could not save PDF: {error:#}"),
        };
    }

    fn header(&mut self, ui: &mut egui::Ui, _palette: Palette) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("PII Explorer")
                        .size(23.0)
                        .strong()
                        .color(Color32::from_rgb(0xf4, 0xfa, 0xfc)),
                );
                ui.label(
                    RichText::new("Local detection. Occurrence-level review.")
                        .size(12.0)
                        .color(Color32::from_rgb(0xb0, 0xc7, 0xd0)),
                );
            });
            let width = ui.available_width();
            ui.allocate_ui_with_layout(
                Vec2::new(width.max(0.0), 52.0),
                Layout::right_to_left(Align::Center),
                |ui| {
                    let previous = self.theme;
                    egui::ComboBox::from_label(
                        RichText::new("Theme").color(Color32::from_rgb(0xb0, 0xc7, 0xd0)),
                    )
                    .selected_text(self.theme.as_str())
                    .width(94.0)
                    .show_ui(ui, |ui| {
                        for theme in ThemeChoice::ALL {
                            ui.selectable_value(&mut self.theme, theme, theme.as_str());
                        }
                    });
                    if self.theme != previous {
                        self.theme.apply(ui.ctx());
                        self.status = match save_theme(self.theme) {
                            Ok(()) => format!(
                                "{} theme selected. Only this preference is saved.",
                                self.theme.as_str()
                            ),
                            Err(_) => {
                                "Theme applied for this session; the preference could not be saved."
                                    .into()
                            }
                        };
                    }
                    if width > 360.0 {
                        ui.label(
                            RichText::new("LOCAL · PRIVATE")
                                .small()
                                .strong()
                                .color(Color32::from_rgb(0xb4, 0xe9, 0xdd)),
                        );
                    }
                },
            );
        });
    }

    fn scan_settings(&mut self, ui: &mut egui::Ui, compact: bool, palette: Palette) {
        ui.scope(|ui| {
            if self.is_scanning() {
                ui.disable();
            }
            if ui.add(egui::Button::new("Choose folder…")).clicked() {
                self.choose_folder();
            }
            let folder_label = ui.label("Folder to scan");
            ui.add(
                egui::TextEdit::multiline(&mut self.folder)
                    .hint_text("Or paste a folder path")
                    .desired_rows(2)
                    .desired_width(ui.available_width()),
            )
            .labelled_by(folder_label.id);

            if compact {
                egui::CollapsingHeader::new("Detection options")
                    .default_open(false)
                    .show(ui, |ui| self.detection_options(ui));
            } else {
                ui.add_space(10.0);
                self.detection_options(ui);
            }
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Detection can miss information. Review Needs attention for incomplete files.",
            )
            .small()
            .color(palette.muted),
        );
    }

    fn detection_options(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("Include in scan").small().strong());
        ui.checkbox(&mut self.settings.ocr, "Text inside images (OCR)");
        ui.checkbox(&mut self.settings.detect_names, "People’s names");
        ui.label("Images and scanned pages take longer. Files stay on this computer.");

        let size_label = ui.label("Maximum file size (MiB)");
        ui.add(
            egui::DragValue::new(&mut self.settings.max_file_mib)
                .range(1..=2048)
                .speed(1),
        )
        .labelled_by(size_label.id);

        let workers_label = ui.label("Parallel file workers");
        ui.add(
            egui::DragValue::new(&mut self.settings.workers)
                .range(1..=8)
                .speed(1),
        )
        .labelled_by(workers_label.id)
        .on_hover_text(
            "Lower this when memory is limited; each worker may start a document parser.",
        );

        let regions_label = ui.label("Phone number regions");
        ui.add(
            egui::TextEdit::singleline(&mut self.settings.phone_regions)
                .hint_text("US, GB")
                .desired_width(ui.available_width()),
        )
        .labelled_by(regions_label.id)
        .on_hover_text(
            "Comma-separated ISO country codes for numbers without an international prefix.",
        );

        ui.add_space(8.0);
        ui.separator();
        ui.label(RichText::new("PDF report privacy").small().strong());
        ui.checkbox(
            &mut self.hide_file_names_in_report,
            "Replace filenames with stable IDs",
        );
        ui.checkbox(
            &mut self.include_context_in_report,
            "Include surrounding context",
        );
        ui.label("Exports include all findings. PDF metadata is omitted; visible PII remains.");
    }

    fn scan_controls(&mut self, ui: &mut egui::Ui, palette: Palette) {
        let scanning = self.is_scanning();
        let stopping = self.is_stopping();
        ui.horizontal(|ui| {
            let scan_width = (ui.available_width() - 82.0).max(120.0);
            if ui
                .add_enabled(
                    !scanning,
                    egui::Button::new(
                        RichText::new("Scan folder")
                            .strong()
                            .color(palette.accent_ink),
                    )
                    .fill(palette.accent)
                    .min_size(Vec2::new(scan_width, 36.0)),
                )
                .clicked()
            {
                self.start_scan(ui.ctx());
            }
            if ui
                .add_enabled(
                    scanning && !stopping,
                    egui::Button::new("Stop").min_size(Vec2::new(66.0, 36.0)),
                )
                .clicked()
            {
                self.stop_scan();
            }
        });
        let progress = if self.review.progress.discovered == 0 {
            0.0
        } else {
            (self.review.progress.completed as f32 / self.review.progress.discovered as f32)
                .clamp(0.0, 1.0)
        };
        ui.add(
            egui::ProgressBar::new(progress)
                .desired_height(4.0)
                .desired_width(ui.available_width())
                .animate(scanning && self.review.progress.discovered == 0),
        )
        .accessible_name(format!(
            "Scan progress: {} of {} files completed",
            self.review.progress.completed, self.review.progress.discovered
        ));
    }

    fn review_area(&mut self, ui: &mut egui::Ui, palette: Palette) {
        let action = egui::Panel::bottom("selected_evidence")
            .resizable(true)
            .default_size(224.0)
            .size_range(154.0..=340.0)
            .frame(panel_frame(palette.surface, palette.line, 12))
            .show(ui, |ui| self.detail_contents(ui, palette))
            .inner;
        if let Some(action) = action {
            self.perform_detail_action(action, ui.ctx());
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(palette.canvas).inner_margin(16.0))
            .show(ui, |ui| {
                self.summary(ui, palette);
                ui.add_space(12.0);
                self.filter_toolbar(ui, palette);
                ui.add_space(12.0);
                self.results(ui, palette);
            });
    }

    fn summary(&self, ui: &mut egui::Ui, palette: Palette) {
        let width = ui.available_width();
        let card_width = ((width - 20.0) / 3.0).max(80.0);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            stat_card(
                ui,
                card_width,
                "POTENTIAL PII",
                self.review.result.findings.len().to_string(),
                palette.accent,
                palette,
            );
            stat_card(
                ui,
                card_width,
                "FILES PROCESSED",
                format!(
                    "{} / {}",
                    self.review.progress.completed, self.review.progress.discovered
                ),
                palette.text,
                palette,
            );
            stat_card(
                ui,
                card_width,
                "NEED ATTENTION",
                self.review.result.attention.len().to_string(),
                palette.warning,
                palette,
            );
        });
    }

    fn filter_toolbar(&mut self, ui: &mut egui::Ui, palette: Palette) {
        ui.horizontal(|ui| {
            let search_width = (ui.available_width() - 292.0).max(150.0);
            if ui
                .add_sized(
                    [search_width, 34.0],
                    egui::TextEdit::singleline(&mut self.search)
                        .hint_text("Search values, evidence, files, or methods…"),
                )
                .accessible_name("Search findings and attention items")
                .changed()
            {
                self.mark_filter_changed();
            }
            let previous_type = self.entity_filter;
            egui::ComboBox::from_id_salt("entity_filter")
                .selected_text(self.entity_filter.map_or("All types", EntityType::as_str))
                .width(150.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.entity_filter, None, "All types");
                    for entity in EntityType::ALL {
                        ui.selectable_value(&mut self.entity_filter, Some(entity), entity.as_str());
                    }
                });
            if self.entity_filter != previous_type {
                self.mark_filter_changed();
            }
            ui.add_enabled_ui(self.has_result && !self.is_scanning(), |ui| {
                ui.menu_button("Export…", |ui| {
                    if ui.button("Save all as JSON…").clicked() {
                        ui.close();
                        self.export_all_json();
                    }
                    if ui.button("Save all as PDF…").clicked() {
                        ui.close();
                        self.export_all_pdf();
                    }
                })
                .response
                .on_hover_text(
                    "Export all findings and attention items, including results hidden by filters.",
                );
            });
        });
        if !self.filter.is_empty() || self.filter_dirty_since.is_some() {
            ui.label(
                RichText::new(format!(
                    "Showing {} of {} findings and {} of {} attention items",
                    self.review.visible_findings.len(),
                    self.review.result.findings.len(),
                    self.review.visible_attention.len(),
                    self.review.result.attention.len()
                ))
                .small()
                .color(palette.muted),
            );
        }
    }

    fn results(&mut self, ui: &mut egui::Ui, palette: Palette) {
        let previous_tab = self.active_tab;
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.active_tab,
                ResultsTab::Findings,
                format!("Findings  {}", self.review.visible_findings.len()),
            );
            ui.selectable_value(
                &mut self.active_tab,
                ResultsTab::Attention,
                format!("Needs attention  {}", self.review.visible_attention.len()),
            );
        });
        if self.active_tab != previous_tab {
            self.selection = None;
        }
        ui.separator();
        match self.active_tab {
            ResultsTab::Findings => self.findings_table(ui, palette),
            ResultsTab::Attention => self.attention_table(ui, palette),
        }
    }

    fn findings_table(&mut self, ui: &mut egui::Ui, palette: Palette) {
        if self.review.visible_findings.is_empty() {
            self.empty_results(ui, false, palette);
            return;
        }
        let widths = finding_column_widths(ui.available_width());
        table_header(
            ui,
            widths,
            ["Type", "Value", "File", "Inside file / archive"],
            palette,
        );
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("findings_rows")
            .auto_shrink([false, false])
            .show_rows(ui, 29.0, self.review.visible_findings.len(), |ui, rows| {
                ui.spacing_mut().item_spacing = Vec2::ZERO;
                for row in rows {
                    let index = self.review.visible_findings[row];
                    let finding = &self.review.result.findings[index];
                    let selected = self.selection == Some(Selection::Finding(index));
                    ui.horizontal(|ui| {
                        let cells = [
                            finding.entity_type.as_str().to_owned(),
                            single_line(&finding.value),
                            single_line(&finding.origin.resource_id),
                            single_line(&finding.origin.stream_id),
                        ];
                        for (cell, width) in cells.into_iter().zip(widths) {
                            if ui
                                .add_sized(
                                    [width, 29.0],
                                    egui::Button::selectable(selected, cell)
                                        .frame_when_inactive(false)
                                        .truncate()
                                        .small(),
                                )
                                .clicked()
                            {
                                self.selection = Some(Selection::Finding(index));
                            }
                        }
                    });
                }
            });
    }

    fn attention_table(&mut self, ui: &mut egui::Ui, palette: Palette) {
        if self.review.visible_attention.is_empty() {
            self.empty_results(ui, true, palette);
            return;
        }
        let source = (ui.available_width() * 0.34).clamp(140.0, 300.0);
        let widths = [source, (ui.available_width() - source).max(160.0)];
        table_header(ui, widths, ["Source", "What happened"], palette);
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("attention_rows")
            .auto_shrink([false, false])
            .show_rows(ui, 29.0, self.review.visible_attention.len(), |ui, rows| {
                ui.spacing_mut().item_spacing = Vec2::ZERO;
                for row in rows {
                    let index = self.review.visible_attention[row];
                    let item = &self.review.result.attention[index];
                    let selected = self.selection == Some(Selection::Attention(index));
                    ui.horizontal(|ui| {
                        for (cell, width) in
                            [single_line(&item.resource_id), single_line(&item.message)]
                                .into_iter()
                                .zip(widths)
                        {
                            if ui
                                .add_sized(
                                    [width, 29.0],
                                    egui::Button::selectable(selected, cell)
                                        .frame_when_inactive(false)
                                        .truncate()
                                        .small(),
                                )
                                .clicked()
                            {
                                self.selection = Some(Selection::Attention(index));
                            }
                        }
                    });
                }
            });
    }

    fn empty_results(&mut self, ui: &mut egui::Ui, attention: bool, palette: Palette) {
        let has_any =
            !self.review.result.findings.is_empty() || !self.review.result.attention.is_empty();
        let filtered = has_any && (!self.filter.is_empty() || self.filter_dirty_since.is_some());
        let (heading, explanation) = if filtered {
            (
                "No matching results",
                "Clear the search and type filter to see all collected results.",
            )
        } else if self.is_scanning() {
            (
                "Scanning locally",
                "Results will appear here as files are checked.",
            )
        } else if attention {
            (
                "No attention items",
                "No extraction issues were reported. Detection is still not exhaustive.",
            )
        } else if self.has_result {
            (
                "No potential PII detected",
                "Review Needs attention for incomplete files; detection is not exhaustive.",
            )
        } else {
            (
                "See what your files contain",
                "Choose a folder and start a scan. Findings appear here as files are read.",
            )
        };
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() * 0.22).max(16.0));
            ui.label(
                RichText::new(heading)
                    .size(19.0)
                    .strong()
                    .color(palette.text),
            );
            ui.label(RichText::new(explanation).color(palette.muted));
            if filtered && ui.button("Clear filters").clicked() {
                self.search.clear();
                self.entity_filter = None;
                self.filter = FindingFilter::default();
                self.filter_dirty_since = None;
                self.review.refilter(&self.filter);
            }
        });
    }

    fn detail_contents(&self, ui: &mut egui::Ui, palette: Palette) -> Option<DetailAction> {
        match self.selection {
            Some(Selection::Finding(index)) => self
                .review
                .result
                .findings
                .get(index)
                .and_then(|finding| self.finding_detail(ui, finding, palette)),
            Some(Selection::Attention(index)) => self
                .review
                .result
                .attention
                .get(index)
                .and_then(|item| self.attention_detail(ui, item, palette)),
            None => {
                ui.heading("Evidence review");
                ui.label(
                    RichText::new("Select a finding or attention item to inspect its source, evidence, and provenance.")
                        .color(palette.muted),
                );
                None
            }
        }
    }

    fn finding_detail(
        &self,
        ui: &mut egui::Ui,
        finding: &Finding,
        palette: Palette,
    ) -> Option<DetailAction> {
        let mut action = None;
        egui::ScrollArea::vertical()
            .id_salt("finding_detail_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(finding.entity_type.as_str())
                            .heading()
                            .strong(),
                    );
                    ui.label(
                        RichText::new(format!("Confidence / score {:.3}", finding.confidence))
                            .color(palette.accent),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Copy value").clicked() {
                        action = Some(DetailAction::Copy(finding.value.clone()));
                    }
                    if ui.button("Reveal source file").clicked() {
                        action = Some(DetailAction::Reveal(finding.origin.resource_id.clone()));
                    }
                    ui.label(RichText::new(&finding.method).small().color(palette.muted));
                });
                ui.add_space(6.0);
                ui.label(RichText::new("Detected value").small().strong());
                ui.add(egui::Label::new(&finding.value).selectable(true).wrap());

                if ui.available_width() >= 650.0 {
                    ui.columns(2, |columns| {
                        finding_context(&mut columns[0], finding, palette);
                        provenance(&mut columns[1], finding, self, palette);
                    });
                } else {
                    finding_context(ui, finding, palette);
                    provenance(ui, finding, self, palette);
                }
            });
        action
    }

    fn attention_detail(
        &self,
        ui: &mut egui::Ui,
        item: &AttentionItem,
        palette: Palette,
    ) -> Option<DetailAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            ui.heading("Needs attention");
            if ui.button("Reveal source file").clicked() {
                action = Some(DetailAction::Reveal(item.resource_id.clone()));
            }
        });
        ui.label(RichText::new(&item.resource_id).strong());
        ui.add_space(6.0);
        ui.add(egui::Label::new(&item.message).selectable(true).wrap());
        if let Some(source) = self.review.source(&item.resource_id) {
            source_hash(ui, source, palette);
        }
        action
    }

    fn perform_detail_action(&mut self, action: DetailAction, context: &egui::Context) {
        match action {
            DetailAction::Copy(value) => {
                // Copying occurs only after an explicit button press.
                context.copy_text(value);
                self.status = "Value copied to the system clipboard.".into();
            }
            DetailAction::Reveal(resource) => {
                self.status = match self.scan_root.as_deref() {
                    Some(root) => match reveal_source(root, &resource) {
                        Ok(()) => "Opened the source in the system file manager.".into(),
                        Err(error) => format!("Could not reveal the source: {error}"),
                    },
                    None => "No scan folder is available for this result.".into(),
                };
            }
        }
    }
}

fn run_scan(
    root: PathBuf,
    options: ScanOptions,
    cancelled: Arc<AtomicBool>,
    sender: Sender<WorkerMessage>,
    context: egui::Context,
) {
    let event_sender = sender.clone();
    let event_cancelled = Arc::clone(&cancelled);
    let result = Scanner::new(options)
        .map_err(|error| error.to_string())
        .and_then(|scanner| {
            let worker = pii_explorer_isolation::WorkerPool::new(
                pii_explorer_isolation::default_worker().map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let scanner = scanner.with_extractor(Arc::new(worker));
            scanner
                .scan_with_events(&root, cancelled, move |event| {
                    if event_sender.send(WorkerMessage::Event(event)).is_err() {
                        event_cancelled.store(true, Ordering::Relaxed);
                    }
                })
                .map_err(|error| error.to_string())
        });
    let _ = sender.send(WorkerMessage::Finished(Box::new(result)));
    context.request_repaint();
}

fn configure_styles(context: &egui::Context) {
    context.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(11.0, 6.0);
        let dark = style.visuals.dark_mode;
        style.visuals.selection.bg_fill = if dark {
            Color32::from_rgb(0x25, 0x4a, 0x48)
        } else {
            Color32::from_rgb(0xe0, 0xf2, 0xee)
        };
        style.visuals.selection.stroke = Stroke::new(
            1.0,
            if dark {
                Color32::from_rgb(0xe4, 0xeb, 0xf1)
            } else {
                Color32::from_rgb(0x20, 0x32, 0x40)
            },
        );
        style.visuals.warn_fg_color = if dark {
            Color32::from_rgb(0xf1, 0xbe, 0x70)
        } else {
            Color32::from_rgb(0x86, 0x50, 0x10)
        };
    });
}

fn panel_frame(fill: Color32, stroke: Color32, margin: i8) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .inner_margin(egui::Margin::same(margin))
}

#[allow(clippy::too_many_arguments)]
fn stat_card(
    ui: &mut egui::Ui,
    width: f32,
    label: &str,
    value: String,
    value_color: Color32,
    palette: Palette,
) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, 72.0),
        Layout::top_down(Align::LEFT),
        |ui| {
            egui::Frame::new()
                .fill(palette.surface)
                .stroke(Stroke::new(1.0, palette.line))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width((width - 26.0).max(40.0));
                    ui.label(RichText::new(label).small().strong().color(palette.muted));
                    ui.label(RichText::new(value).size(24.0).strong().color(value_color));
                });
        },
    );
}

fn table_header<const N: usize>(
    ui: &mut egui::Ui,
    widths: [f32; N],
    labels: [&str; N],
    palette: Palette,
) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing = Vec2::ZERO;
        for (label, width) in labels.into_iter().zip(widths) {
            ui.add_sized(
                [width, 25.0],
                egui::Label::new(RichText::new(label).small().strong().color(palette.muted))
                    .truncate(),
            );
        }
    });
}

fn finding_column_widths(available: f32) -> [f32; 4] {
    let available = available.max(420.0);
    let entity = (available * 0.19).clamp(90.0, 160.0);
    let value = (available * 0.32).clamp(120.0, 300.0);
    let file = (available * 0.25).clamp(96.0, 230.0);
    [
        entity,
        value,
        file,
        (available - entity - value - file).max(90.0),
    ]
}

fn finding_context(ui: &mut egui::Ui, finding: &Finding, palette: Palette) {
    ui.label(RichText::new("Source").small().strong());
    ui.add(
        egui::Label::new(&finding.origin.resource_id)
            .selectable(true)
            .wrap(),
    );
    ui.label(
        RichText::new(format!(
            "Stream / archive member: {}",
            finding.origin.stream_id
        ))
        .small()
        .color(palette.muted),
    );
    ui.label(RichText::new("Surrounding evidence").small().strong());
    if finding.context.is_empty() {
        ui.label(RichText::new("No surrounding context was collected.").color(palette.muted));
    } else {
        ui.add(egui::Label::new(&finding.context).selectable(true).wrap());
    }
}

fn provenance(ui: &mut egui::Ui, finding: &Finding, review: &ExplorerApp, palette: Palette) {
    ui.label(RichText::new("Evidence provenance").small().strong());
    egui::Grid::new("provenance_grid")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            evidence_row(ui, "Kind", evidence_kind(finding.origin.kind));
            evidence_row(ui, "Representation", &finding.origin.representation);
            evidence_row(
                ui,
                "Coordinates",
                coordinate_unit(finding.origin.coordinate_unit),
            );
            evidence_row(
                ui,
                "Finding offset",
                &format!("{} + {}", finding.start, finding.length),
            );
            evidence_row(
                ui,
                "Detector offset",
                &format!("{} + {}", finding.detector_start, finding.detector_length),
            );
            evidence_row(ui, "Context starts at", &finding.context_start.to_string());
            evidence_row(
                ui,
                "Chunk starts at",
                &finding.origin.chunk_start.to_string(),
            );
            evidence_row(ui, "Stride", &finding.origin.stride.to_string());
            evidence_row(ui, "Method", &finding.method);
        });
    if let Some(source) = review.review.source(&finding.origin.resource_id) {
        source_hash(ui, source, palette);
    } else {
        ui.label(
            RichText::new("SHA-256 unavailable until the source is read and the scan finishes.")
                .small()
                .color(palette.muted),
        );
    }
}

fn source_hash(ui: &mut egui::Ui, source: &pii_explorer_core::SourceRecord, palette: Palette) {
    ui.label(
        RichText::new(format!("Source size: {} bytes", source.size))
            .small()
            .color(palette.muted),
    );
    ui.label(RichText::new("Source SHA-256").small().strong());
    match &source.sha256 {
        Some(hash) => {
            ui.add(
                egui::Label::new(RichText::new(hash).monospace())
                    .selectable(true)
                    .wrap(),
            );
        }
        None => {
            ui.label(
                RichText::new("Not available; the source was not fully read.").color(palette.muted),
            );
        }
    }
}

fn evidence_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(label);
    ui.add(egui::Label::new(value).selectable(true).wrap());
    ui.end_row();
}

const fn evidence_kind(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Body => "Body text",
        EvidenceKind::Filename => "Filename",
        EvidenceKind::ArchiveMemberName => "Archive member name",
        EvidenceKind::Metadata => "Metadata",
        EvidenceKind::Ocr => "OCR text",
        EvidenceKind::BinaryStrings => "Binary strings",
    }
}

const fn coordinate_unit(unit: CoordinateUnit) -> &'static str {
    match unit {
        CoordinateUnit::Utf16CodeUnits => "UTF-16 code units",
        CoordinateUnit::Bytes => "Bytes",
    }
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

impl eframe::App for ExplorerApp {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        if context.input(|input| input.viewport().close_requested()) && self.is_scanning() {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_requested = true;
            self.stop_scan();
            self.status = "Stopping before closing…".into();
        }
        self.apply_pending_filter(false);
        self.drain_worker(context);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let palette = Palette::from_ui(ui);
        egui::Panel::top("application_header")
            .exact_size(76.0)
            .frame(
                egui::Frame::NONE
                    .fill(palette.header)
                    .inner_margin(egui::Margin::symmetric(22, 10)),
            )
            .show(ui, |ui| self.header(ui, palette));
        egui::Panel::bottom("application_status")
            .exact_size(34.0)
            .frame(panel_frame(palette.surface, palette.line, 0))
            .show(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add_space(18.0);
                    ui.add(egui::Label::new(&self.status).truncate())
                        .on_hover_text(&self.status);
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(palette.canvas))
            .show(ui, |ui| {
                if ui.available_width() >= 1000.0 {
                    egui::Panel::left("scan_settings")
                        .resizable(true)
                        .default_size(296.0)
                        .size_range(260.0..=360.0)
                        .frame(panel_frame(palette.surface, palette.line, 16))
                        .show(ui, |ui| {
                            egui::Panel::bottom("scan_controls")
                                .resizable(false)
                                .exact_size(72.0)
                                .frame(egui::Frame::NONE)
                                .show(ui, |ui| self.scan_controls(ui, palette));
                            egui::ScrollArea::vertical()
                                .id_salt("settings_scroll")
                                .auto_shrink([false, false])
                                .show(ui, |ui| self.scan_settings(ui, false, palette));
                        });
                } else {
                    egui::Panel::top("compact_scan_settings")
                        .resizable(false)
                        .frame(panel_frame(palette.surface, palette.line, 12))
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .id_salt("compact_settings_scroll")
                                .max_height(290.0)
                                .auto_shrink([false, true])
                                .show(ui, |ui| self.scan_settings(ui, true, palette));
                            ui.add_space(8.0);
                            self.scan_controls(ui, palette);
                        });
                }
                self.review_area(ui, palette);
            });
    }
}

impl Drop for ExplorerApp {
    fn drop(&mut self) {
        if let Some(task) = self.scan.take() {
            let ScanTask {
                cancelled,
                receiver,
                handle,
            } = task;
            cancelled.store(true, Ordering::Relaxed);
            // Unblock a worker that is waiting to publish into a full bounded channel.
            drop(receiver);
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_columns_use_available_width_without_narrow_last_column() {
        for width in [420.0, 700.0, 1200.0, 1800.0] {
            let columns = finding_column_widths(width);
            assert!(columns.iter().all(|column| *column >= 90.0));
            assert!((columns.iter().sum::<f32>() - width.max(420.0)).abs() < 0.01);
        }
    }

    #[test]
    fn table_text_does_not_change_row_height() {
        assert_eq!(
            single_line("line one\nline two\tend"),
            "line one line two end"
        );
    }
}
