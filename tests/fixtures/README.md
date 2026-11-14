`testOneNote2016.one` is the public Apache Tika 3.3.2 test fixture:

https://raw.githubusercontent.com/apache/tika/3.3.2/tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/tika-parser-microsoft-module/src/test/resources/test-documents/testOneNote2016.one

Expected text includes “This is one note 2016”. This fixture tests real OneNote parsing; the similarly named files in `corpus` deliberately contain invalid data.

`corpus` contains synthetic samples, including malformed and encrypted files. `staff-register.xlsx` contains 25,000 synthetic rows. These are test data, not real personal records. The corpus test counts the actual fixture files so adding a sample cannot leave a stale file-count assertion.

`accuracy-smoke.jsonl` contains 57 developer-authored text cases, 38 annotated entities and 19 negative controls. It covers structured identifiers and one explicitly labelled person. It is a regression suite, not a held-out accuracy benchmark. Offsets are UTF-16 code units. Package verification enables names; the Rust labelled-name rules retain the Person annotation even with ONNX inference disabled. Update annotations only to correct independently reviewed ground truth, never just to make a changed detector pass.

The source tests contain synthetic/example credentials and public checksum test vectors. They must never contain working secrets or real analyst case data. Keep locally exported reports under the ignored `reports` or `test-results` directory, not alongside fixtures.
