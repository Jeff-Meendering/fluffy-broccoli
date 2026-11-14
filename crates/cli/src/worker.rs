fn main() -> std::process::ExitCode {
    // Never echo parser errors or panics: parser diagnostics can contain sensitive input.
    std::panic::set_hook(Box::new(|_| {}));
    match pii_explorer_isolation::run_worker() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}
