"""Independent, text-only accuracy benchmark. No detector tuning or model downloads at run time."""
import argparse
import ast
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import unicodedata
import urllib.request
import uuid
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCOPE = ["Email", "IP address", "Payment card", "Person", "Phone", "Social Security number"]
GOLD_MAP = {"email": "Email", "ipv4": "IP address", "ipv6": "IP address",
            "credit_card_number": "Payment card", "name": "Person", "first_name": "Person",
            "last_name": "Person", "phone_number": "Phone", "ssn": "Social Security number"}
PRESIDIO_MAP = {"EMAIL_ADDRESS": "Email", "IP_ADDRESS": "IP address", "CREDIT_CARD": "Payment card",
                "PERSON": "Person", "PHONE_NUMBER": "Phone", "US_SSN": "Social Security number"}
PHINDER_REVISION = "ab074151c4a4699dd1efff866f8c190af17490ca"
JAVA_IMAGE = "maven@sha256:31618505df21177d2baa3dc574be2d0b0b32614c8539baca1f23a9136b766eb0"
PHILTER_IMAGE = "philterd/philter@sha256:3ad701da32966af04db6e019997f1fb7d3ebb3f2931a4b737274318c83e70380"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def text_hash(text):
    return digest(text.encode("utf-8"))


def normalized_hash(text):
    return text_hash(" ".join(unicodedata.normalize("NFKC", text).casefold().split()))


def utf16(text):
    return len(text.encode("utf-16-le")) // 2


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def write_jsonl(path, rows):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n")


def align(text, annotations):
    """Frozen value-to-span projection: all literal occurrences; adjacent name parts coalesce."""
    spans, unsupported = set(), {}
    for annotation in annotations:
        value = annotation["entity"]
        labels = annotation["types"]
        if not isinstance(value, str) or not value or not labels:
            raise ValueError("Invalid source annotation")
        matches = list(re.finditer(re.escape(value), text))
        if not matches:
            raise ValueError("Unalignable source annotation")
        for label in labels:
            if label not in GOLD_MAP:
                unsupported[label] = unsupported.get(label, 0) + len(matches)
                continue
            for match in matches:
                spans.add((GOLD_MAP[label], match.start(), match.end()))
    names = sorted((start, end) for kind, start, end in spans if kind == "Person")
    merged = []
    for start, end in names:
        if merged and (start <= merged[-1][1] or text[merged[-1][1]:start].isspace()):
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    spans = {span for span in spans if span[0] != "Person"} | {("Person", s, e) for s, e in merged}
    entities = [{"Type": kind, "Start": utf16(text[:start]), "Length": utf16(text[start:end])}
                for kind, start, end in sorted(spans)]
    return entities, unsupported


def prepare(destination):
    import pyarrow.parquet as parquet
    pins = json.loads((HERE / "dataset.json").read_text())
    destination.mkdir(parents=True, exist_ok=False)
    cache = destination / "source"
    cache.mkdir()
    tables = {}
    for split, expected_hash in pins["sha256"].items():
        target = cache / (split + ".parquet")
        url = f'https://huggingface.co/datasets/{pins["dataset"]}/resolve/{pins["revision"]}/data/{split}-00000-of-00001.parquet'
        urllib.request.urlretrieve(url, target)
        if digest(target.read_bytes()) != expected_hash:
            raise ValueError("Dataset checksum mismatch")
        tables[split] = parquet.read_table(target).to_pylist()
    development = {normalized_hash(row["text"]) for split in ("train", "validation") for row in tables[split]}
    development.update(normalized_hash(row["text"]) for row in read_jsonl(ROOT / "tests/fixtures/accuracy-smoke.jsonl"))
    accepted, rejected, seen, ids, unsupported = [], {}, set(), set(), {}
    for row in sorted(tables["test"], key=lambda row: row["uid"]):
        fingerprint = normalized_hash(row["text"])
        reason = None
        if fingerprint in development:
            reason = "development_overlap"
        elif fingerprint in seen or row["uid"] in ids:
            reason = "duplicate_test_document"
        seen.add(fingerprint)
        ids.add(row["uid"])
        try:
            entities, excluded = align(row["text"], ast.literal_eval(row["entities"]))
        except (ValueError, SyntaxError, KeyError, TypeError):
            reason = reason or "invalid_source_annotation"
        if reason:
            rejected[reason] = rejected.get(reason, 0) + 1
            continue
        for kind, count in excluded.items():
            unsupported[kind] = unsupported.get(kind, 0) + count
        accepted.append({"Id": row["uid"], "Text": row["text"], "Entities": entities,
                         "Domain": row["domain"], "TextSha256": text_hash(row["text"])})
    if not accepted:
        raise ValueError("No eligible test documents")
    write_jsonl(destination / "gold.jsonl", accepted)
    write_jsonl(destination / "inputs.jsonl", ({"Id": r["Id"], "Text": r["Text"]} for r in accepted))
    manifest = {"schema": 1, "source": pins, "scope": SCOPE, "mapping": GOLD_MAP,
                "projection": "all-literal-occurrences-adjacent-person-parts-v1", "source_test_documents": len(tables["test"]),
                "documents": len(accepted), "quarantined": rejected, "excluded_source_entities": unsupported,
                "gold_sha256": digest((destination / "gold.jsonl").read_bytes()),
                "input_sha256": digest((destination / "inputs.jsonl").read_bytes()),
                "leakage_check": "NFKC/casefold/whitespace document equality against source train/validation and local smoke corpus; duplicate test documents removed",
                "limitations": ["No near-duplicate/template or pretrained-model contamination guarantee",
                                "Source provides values, not offsets: projected spans are not independently human-adjudicated",
                                "Clean means no gold entities in the declared comparison scope, not free of every PII type"]}
    write_json(destination / "manifest.json", manifest)
    print(json.dumps({"documents": len(accepted), "quarantined": rejected}))


def spans(row, text, gold=False):
    result = set()
    boundaries, offset = {0}, 0
    for character in text:
        offset += 2 if ord(character) > 0xffff else 1
        boundaries.add(offset)
    for entity in row["Entities"]:
        kind, start, length = entity["Type"], entity["Start"], entity["Length"]
        if not isinstance(kind, str) or not kind or type(start) is not int or type(length) is not int or length <= 0 or start not in boundaries or start + length not in boundaries:
            raise ValueError("Invalid entity type or UTF-16 boundary")
        span = kind, start, length
        if gold and span in result:
            raise ValueError("Duplicate gold entity")
        result.add(span)
    return result


def metrics(tp, fp, fn, clean, clean_fp):
    return {"true_positive": int(tp), "false_positive": int(fp), "false_negative": int(fn),
            "gold_entities": int(tp + fn), "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "false_negative_proportion": fn / (tp + fn) if tp + fn else None,
            "clean_documents": int(clean), "false_positives_on_clean_documents": int(clean_fp),
            "false_positives_per_clean_document": clean_fp / clean if clean else None}


def summarize(counts, samples=2000, seed=20260911):
    import numpy as np
    if not counts:
        raise ValueError("Empty corpus")
    array = np.array(counts, dtype=np.int64)
    result = metrics(*map(int, array.sum(axis=0)))
    rng = np.random.default_rng(seed)
    values = {key: [] for key in ("precision", "recall", "f1", "false_negative_proportion", "false_positives_per_clean_document")}
    for _ in range(samples):
        resampled = array[rng.integers(0, len(array), len(array))].sum(axis=0)
        point = metrics(*map(int, resampled))
        for key in values:
            if point[key] is not None:
                values[key].append(point[key])
    result["intervals_95"] = {key: {"lower": float(np.quantile(v, .025)), "upper": float(np.quantile(v, .975)),
                                    "defined_resamples": len(v)} if v else None for key, v in values.items()}
    return result


def score_rows(gold, predictions, samples=2000, scope=None):
    scope = SCOPE if scope is None else scope
    if not scope or len(set(scope)) != len(scope) or not set(scope) <= set(SCOPE):
        raise ValueError("Invalid comparison scope")
    expected_ids = [row["Id"] for row in gold]
    actual_ids = [row["Id"] for row in predictions]
    if not gold or len(set(expected_ids)) != len(gold) or len(set(actual_ids)) != len(predictions) or set(expected_ids) != set(actual_ids):
        raise ValueError("Missing, extra or duplicate documents; incomplete runs cannot be scored")
    predicted = {row["Id"]: row for row in predictions}
    counts = {kind: [] for kind in ["micro"] + scope}
    excluded, excluded_gold = {}, {}
    for row in gold:
        prediction = predicted[row["Id"]]
        if prediction["TextSha256"] != text_hash(row["Text"]):
            raise ValueError("Prediction text fingerprint mismatch")
        expected = spans(row, row["Text"], gold=True)
        if any(e[0] not in SCOPE for e in expected):
            raise ValueError("Gold label outside frozen comparison scope")
        for entity in expected:
            if entity[0] not in scope:
                excluded_gold[entity[0]] = excluded_gold.get(entity[0], 0) + 1
        expected = {entity for entity in expected if entity[0] in scope}
        actual = spans(prediction, row["Text"])
        for entity in actual:
            if entity[0] not in scope:
                excluded[entity[0]] = excluded.get(entity[0], 0) + 1
        actual = {entity for entity in actual if entity[0] in scope}
        for kind in counts:
            e = {entity for entity in expected if kind == "micro" or entity[0] == kind}
            a = {entity for entity in actual if kind == "micro" or entity[0] == kind}
            counts[kind].append((len(e & a), len(a - e), len(e - a), int(not e), len(a) if not e else 0))
    results = {kind: summarize(rows, samples) for kind, rows in counts.items()}
    macro = {}
    for key in ("precision", "recall", "f1", "false_negative_proportion"):
        values = [results[kind][key] for kind in scope if results[kind][key] is not None]
        macro[key] = sum(values) / len(values) if values else None
        macro[key + "_defined_types"] = len(values)
    return {"documents": len(gold), "micro": results.pop("micro"), "by_type": results, "macro": macro,
            "excluded_prediction_types": excluded, "excluded_gold_types": excluded_gold,
            "uncertainty": {"method": "percentile document bootstrap", "samples": samples, "seed": 20260911,
                            "level": .95, "limitations": "Conditional on corpus and projected labels. Related templates can violate independence; zero-error samples give degenerate intervals. Undefined denominators omitted, never scored as perfect."}}


def verify_corpus(folder):
    manifest = json.loads((folder / "manifest.json").read_text())
    if manifest["scope"] != SCOPE or manifest["mapping"] != GOLD_MAP:
        raise ValueError("Incompatible benchmark mapping")
    for name, key in (("inputs.jsonl", "input_sha256"), ("gold.jsonl", "gold_sha256")):
        if digest((folder / name).read_bytes()) != manifest[key]:
            raise ValueError("Corpus changed since preparation")
    return manifest


def imported_report(folder, predictions, configuration, output):
    manifest = verify_corpus(folder)
    if not configuration.get("engine") or not configuration.get("version"):
        raise ValueError("External predictions need engine/version/configuration provenance")
    scope = configuration.get("scope", SCOPE)
    report = score_rows(read_jsonl(folder / "gold.jsonl"), read_jsonl(predictions), scope=scope)
    report.update({"schema": 1, "engine": configuration["engine"], "configuration": configuration,
                   "scope": scope, "corpus_sha256": manifest["gold_sha256"], "input_sha256": manifest["input_sha256"],
                   "prediction_sha256": digest(predictions.read_bytes()),
                   "matching": "Exact type and UTF-16 span, duplicate predictions counted once. Text only; excludes extraction/OCR."})
    write_json(output, report)


def phinder_run(folder, destination, checkout):
    verify_corpus(folder)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    if revision != PHINDER_REVISION:
        raise ValueError("Phinder checkout is not the pinned revision")
    subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=checkout, check=True)
    jar = checkout / "target/phinder-1.0.0-SNAPSHOT.jar"
    if not jar.is_file():
        raise ValueError("Build the pinned Phinder checkout first; see README.md")
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(HERE / "PhinderAccuracy.java", destination / "PhinderAccuracy.java")
    # Only the text-only input file is mounted; the prediction container cannot access gold labels.
    mounts = [(jar, "/engine.jar", True), (folder / "inputs.jsonl", "/inputs.jsonl", True),
              (HERE / "identifier-policy.json", "/policy.json", True), (destination, "/output", False)]
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--memory", "2g", "--cpus", "2"]
    for source, target, readonly in mounts:
        command.extend(["--mount", f'type=bind,source={source.resolve()},target={target}' + (",readonly" if readonly else "")])
    command.append(JAVA_IMAGE)
    subprocess.run(command + ["javac", "-cp", "/engine.jar", "/output/PhinderAccuracy.java"], check=True)
    with (destination / "phinder.log").open("x", encoding="utf-8") as log:
        subprocess.run(command + ["java", "-cp", "/output:/engine.jar", "PhinderAccuracy", "/inputs.jsonl", "/policy.json",
                                  "/output/phinder.predictions.jsonl"], check=True, stdout=log, stderr=log)
    configuration = {"engine": "phinder", "version": "1.0.0-SNAPSHOT", "source_revision": revision,
                     "jar_sha256": digest(jar.read_bytes()), "runtime_image": JAVA_IMAGE, "phileas_version": "4.2.0",
                     "adapter_sha256": digest((HERE / "PhinderAccuracy.java").read_bytes()),
                     "policy_sha256": digest((HERE / "identifier-policy.json").read_bytes()), "names_enabled": False,
                     "scope": [kind for kind in SCOPE if kind != "Person"],
                     "execution": "Local Java method Phinder.findPii(text, policy), effective applied spans; container networking disabled",
                     "container_memory": "2g", "container_cpus": 2}
    imported_report(folder, destination / "phinder.predictions.jsonl", configuration, destination / "phinder.report.json")


def philter_run(folder, destination, checkout):
    verify_corpus(folder)
    # The existing shaded Phinder jar supplies only Gson to this small Java HTTP client.
    # Philter itself runs its separately pinned image/Phileas version.
    gson_jar = checkout / "target/phinder-1.0.0-SNAPSHOT.jar"
    if not gson_jar.is_file():
        raise ValueError("Build the pinned Phinder checkout for the local Java adapter dependencies first")
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(HERE / "PhilterAccuracy.java", destination / "PhilterAccuracy.java")
    policies = destination / "policies"
    policies.mkdir()
    shutil.copyfile(HERE / "identifier-policy.json", policies / "default.json")
    mounts = [(gson_jar, "/client-deps.jar", True), (destination, "/output", False),
              (folder / "inputs.jsonl", "/inputs.jsonl", True), (policies, "/opt/philter/policies", True),
              (HERE / "philter.properties", "/opt/philter/philter.properties", True)]
    options = ["--rm", "--pull", "never", "--network", "none", "--memory", "2g", "--cpus", "2"]
    for source, target, readonly in mounts:
        options.extend(["--mount", f'type=bind,source={source.resolve()},target={target}' + (",readonly" if readonly else "")])
    subprocess.run(["docker", "run"] + options + [JAVA_IMAGE, "javac", "--release", "17", "-cp", "/client-deps.jar",
                                                    "/output/PhilterAccuracy.java"], check=True)
    name = "pii-accuracy-philter-" + uuid.uuid4().hex
    try:
        subprocess.run(["docker", "run", "-d", "--name", name] + options + [PHILTER_IMAGE], check=True, stdout=subprocess.DEVNULL)
        with (destination / "philter-client.log").open("x", encoding="utf-8") as log:
            subprocess.run(["docker", "exec", name, "java", "-cp", "/output:/client-deps.jar", "PhilterAccuracy",
                            "/inputs.jsonl", "/output/philter.predictions.jsonl"], check=True, stdout=log, stderr=log)
    finally:
        subprocess.run(["docker", "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    configuration = {"engine": "philter", "version": "3.4.2", "runtime_image": PHILTER_IMAGE,
                     "compiler_image": JAVA_IMAGE, "client_dependencies_sha256": digest(gson_jar.read_bytes()),
                     "adapter_sha256": digest((HERE / "PhilterAccuracy.java").read_bytes()), "phileas_version": "3.3.0",
                     "policy_sha256": digest((HERE / "identifier-policy.json").read_bytes()), "names_enabled": False,
                     "scope": [kind for kind in SCOPE if kind != "Person"],
                     "execution": "HTTP only on loopback inside one network-disabled container; no host port, proxy, redirects, or outside requests",
                     "container_memory": "2g", "container_cpus": 2}
    imported_report(folder, destination / "philter.predictions.jsonl", configuration, destination / "philter.report.json")


@contextmanager
def offline_prediction():
    """Fail Python network operations during prediction, including local HTTP services."""
    with ExitStack() as stack:
        for target, names in ((socket.socket, ("connect", "connect_ex", "sendto")),
                              (socket, ("getaddrinfo", "gethostbyname", "gethostbyname_ex"))):
            for name in names:
                stack.enter_context(patch.object(target, name, side_effect=PermissionError("Networking is disabled during prediction")))
        yield


@offline_prediction()
def predict_presidio(inputs, output):
    import spacy
    import tldextract
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    # Require the pinned installed model: do not let Presidio fetch a missing model.
    if not spacy.util.is_package("en_core_web_lg"):
        raise ValueError("Install the pinned en_core_web_lg model before prediction")
    # Use the package's pinned suffix snapshot, never its online refresh or a mutable user cache.
    local_suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]})
    analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
    results = []
    for row in inputs:
        started = time.perf_counter()
        with patch.object(tldextract, "extract", local_suffixes):
            detected = analyzer.analyze(text=row["Text"], language="en", entities=list(PRESIDIO_MAP), score_threshold=0.0)
        results.append({"Id": row["Id"], "TextSha256": text_hash(row["Text"]),
                        "Entities": [{"Type": PRESIDIO_MAP[e.entity_type], "Start": utf16(row["Text"][:e.start]),
                                      "Length": utf16(row["Text"][e.start:e.end])} for e in detected],
                        "Seconds": time.perf_counter() - started})
    write_jsonl(output, results)
    return {"engine": "Presidio", "version": importlib.metadata.version("presidio-analyzer"),
            "spacy": spacy.__version__, "model": "en_core_web_lg", "model_version": importlib.metadata.version("en-core-web-lg"),
            "language": "en", "score_threshold": 0.0, "mapping": PRESIDIO_MAP,
            "networking": "Python socket operations disabled", "suffix_list": "bundled tldextract snapshot; no cache or download"}


def run(folder, destination, engines):
    manifest = verify_corpus(folder)
    destination.mkdir(parents=True, exist_ok=False)
    inputs = read_jsonl(folder / "inputs.jsonl")
    for engine in engines:
        prediction_path = destination / (engine + ".predictions.jsonl")
        started = time.perf_counter()
        if engine == "piiexplorer":
            command = ["dotnet", str(ROOT / "tools/PiiExplorer.Benchmarks/bin/Release/net10.0/PiiExplorer.Benchmarks.dll"),
                       "--accuracy-predict", str(ROOT / "assets"), str(folder / "inputs.jsonl"), str(prediction_path)]
            process = subprocess.run(command, check=True, capture_output=True, text=True, timeout=1800)
            configuration = json.loads(process.stdout.strip().splitlines()[-1])
        else:
            configuration = predict_presidio(inputs, prediction_path)
        seconds = time.perf_counter() - started
        # Only after prediction has finished are the held-out labels loaded.
        report = score_rows(read_jsonl(folder / "gold.jsonl"), read_jsonl(prediction_path))
        report.update({"schema": 1, "engine": engine, "configuration": configuration, "scope": SCOPE,
                       "corpus_sha256": manifest["gold_sha256"], "input_sha256": manifest["input_sha256"],
                       "prediction_sha256": digest(prediction_path.read_bytes()), "seconds_including_startup": seconds,
                       "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                       "source_diff_sha256": digest(subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL)),
                       "benchmark_files": {str(p.relative_to(ROOT)).replace("\\", "/"): digest(p.read_bytes())
                                           for p in sorted(HERE.iterdir()) if p.is_file()},
                       "python_packages": {d.metadata["Name"]: d.version for d in importlib.metadata.distributions()},
                       "environment": {"python": platform.python_version(), "os": platform.platform()},
                       "matching": "Exact type and UTF-16 span, duplicate predictions counted once. Text only; excludes extraction/OCR."})
        write_json(destination / (engine + ".report.json"), report)
        print(json.dumps({"engine": engine, "documents": report["documents"], "micro": report["micro"]}))


def agreement(first, second):
    """Symmetric entity F1 for two independently produced annotation files; not chance-adjusted kappa."""
    a, b = read_jsonl(first), read_jsonl(second)
    predictions = [{"Id": row["Id"], "TextSha256": text_hash(row["Text"]), "Entities": row["Entities"]} for row in b]
    result = score_rows(a, predictions, samples=200)
    return {"annotation_a_sha256": digest(Path(first).read_bytes()), "annotation_b_sha256": digest(Path(second).read_bytes()),
            "exact_entity_agreement_f1": result["micro"]["f1"], "by_type": result["by_type"],
            "note": "A treated as reference only for accounting. F1 is symmetric. Files must cover the same documents and scope; independent authorship must be established externally."}


def regression(baseline, candidate):
    for key in ("schema", "scope", "corpus_sha256", "input_sha256", "engine", "matching"):
        if baseline[key] != candidate[key]:
            raise ValueError("Incomparable baseline and candidate reports")
    failures, unassessed = [], []
    for kind in ["micro"] + baseline["scope"]:
        a = baseline["micro"] if kind == "micro" else baseline["by_type"][kind]
        b = candidate["micro"] if kind == "micro" else candidate["by_type"][kind]
        if a["gold_entities"] < 50:
            unassessed.append(kind + ": fewer than 50 gold entities")
        else:
            for key in ("precision", "recall", "f1"):
                if a[key] is not None and (b[key] is None or b[key] < a[key] - .02):
                    failures.append(kind + ": " + key + " fell by more than 0.02 or became undefined")
        if a["clean_documents"] < 50:
            unassessed.append(kind + ": fewer than 50 clean documents")
        elif b["false_positives_per_clean_document"] > a["false_positives_per_clean_document"] + .05:
            failures.append(kind + ": false positives per clean document rose by more than 0.05")
    return {"passed": not failures, "failures": failures, "unassessed": unassessed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare"); p.add_argument("destination", type=Path)
    p = sub.add_parser("run"); p.add_argument("corpus", type=Path); p.add_argument("destination", type=Path)
    p.add_argument("--engines", nargs="+", choices=["piiexplorer", "presidio"], default=["piiexplorer", "presidio"])
    p = sub.add_parser("agreement"); p.add_argument("first", type=Path); p.add_argument("second", type=Path); p.add_argument("output", type=Path)
    p = sub.add_parser("compare"); p.add_argument("baseline", type=Path); p.add_argument("candidate", type=Path)
    p = sub.add_parser("score"); p.add_argument("corpus", type=Path); p.add_argument("predictions", type=Path)
    p.add_argument("configuration", type=Path); p.add_argument("output", type=Path)
    p = sub.add_parser("phinder"); p.add_argument("corpus", type=Path); p.add_argument("destination", type=Path)
    p.add_argument("checkout", type=Path)
    p = sub.add_parser("philter"); p.add_argument("corpus", type=Path); p.add_argument("destination", type=Path)
    p.add_argument("checkout", type=Path)
    args = parser.parse_args()
    if args.command == "prepare": prepare(args.destination)
    elif args.command == "run": run(args.corpus, args.destination, args.engines)
    elif args.command == "agreement": write_json(args.output, agreement(args.first, args.second))
    elif args.command == "score": imported_report(args.corpus, args.predictions, json.loads(args.configuration.read_text()), args.output)
    elif args.command == "phinder": phinder_run(args.corpus, args.destination, args.checkout)
    elif args.command == "philter": philter_run(args.corpus, args.destination, args.checkout)
    else:
        result = regression(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()))
        print(json.dumps(result)); return 0 if result["passed"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
