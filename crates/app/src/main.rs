#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
mod app;
mod export;
mod filter;
mod preferences;
mod settings;
mod source;
mod state;

use app::ExplorerApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("PII Explorer")
            .with_app_id("pii-explorer")
            .with_inner_size([1280.0, 840.0])
            .with_min_inner_size([760.0, 620.0])
            .with_clamp_size_to_monitor_size(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "PII Explorer",
        native_options,
        Box::new(|creation| Ok(Box::new(ExplorerApp::new(creation)))),
    )
}
