# Contributing

rollcall is built for people who have to produce a breach notification list and defend it. Changes are judged by whether they help that person.

## Principles

1. **The unit is a person.** Features count affected people and what each of them had exposed, not matched strings.
2. **Nothing is skipped silently.** Whatever cannot be read or interpreted becomes a coverage gap that says why.
3. **Keeping people apart is the safe mistake.** A wrong merge hides someone who should be notified. When evidence is not strong, ask a reviewer.
4. **Every claim is traceable.** A value on the list leads back to a file, sheet and row; a merge has a stated reason.
5. **Evidence is hostile.** New readers get size limits and a place in the hostile-input tests before they are merged.
6. **Original work.** File-format readers, detection, linking and matching are written here. Third-party crates are for plumbing only (database, hashing, compression container, argument parsing). Propose a new dependency in an issue first.
7. **All code is Rust,** tooling included. A test fails the build if a script in another language is added.

## Working on the code

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must pass. `unsafe` is forbidden, and `unwrap`/`expect` are not used outside tests.

The milestone gates in `crates/xtask/tests/` run the whole pipeline on synthetic data and check the notification list against ground truth. A change to detection, linking or matching must keep them passing; if it changes a threshold, say why in the pull request.

Tests are named as sentences that state the behaviour (`a_merge_never_puts_two_birth_dates_or_ssns_in_one_person`). Prefer one test that explains a rule over many that repeat it.

## Test data

Never commit real personal data or real breach material, in tests, fixtures, issues or pull requests. Use `cargo xtask synth`, or invented values: `example.com` addresses and names you made up.

## Security issues

See [SECURITY.md](SECURITY.md). Report suspected vulnerabilities privately.
