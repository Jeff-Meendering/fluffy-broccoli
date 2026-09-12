import copy
import unittest
import socket
from pathlib import Path
import tempfile

import benchmark as b


def row(text, entities, identity="one"):
    return {"Id": identity, "Text": text, "TextSha256": b.text_hash(text), "Entities": entities}


def entity(kind, start, length):
    return {"Type": kind, "Start": start, "Length": length}


class ScorerTests(unittest.TestCase):
    def test_exact_counts_wrong_type_boundary_duplicates_and_clean_documents(self):
        gold = [row("a@b.co x@y.co", [entity("Email", 0, 6)]), row("clean", [], "two"),
                row("Tom", [entity("Person", 0, 3)], "three")]
        predicted = [row("a@b.co x@y.co", [entity("Email", 0, 6), entity("Email", 0, 6), entity("Email", 7, 6)]),
                     row("clean", [entity("Person", 0, 5)], "two"), row("Tom", [entity("Person", 0, 2)], "three")]
        result = b.score_rows(gold, predicted, 50)
        m = result["micro"]
        self.assertEqual((m["true_positive"], m["false_positive"], m["false_negative"]), (1, 3, 1))
        self.assertEqual(m["false_negative_proportion"], .5)
        self.assertEqual(m["false_positives_per_clean_document"], 1)
        self.assertEqual(result["by_type"]["Email"]["false_positives_per_clean_document"], 0)
        swapped = row("Tom", [entity("Email", 0, 3)])
        m = b.score_rows([row("Tom", [entity("Person", 0, 3)])], [swapped], 10)["micro"]
        self.assertEqual((m["true_positive"], m["false_positive"], m["false_negative"]), (0, 1, 1))

    def test_empty_denominators_are_undefined(self):
        result = b.score_rows([row("clean", [])], [row("clean", [])], 10)["micro"]
        for key in ("precision", "recall", "f1", "false_negative_proportion"):
            self.assertIsNone(result[key])
            self.assertIsNone(result["intervals_95"][key])
        self.assertEqual(result["false_positives_per_clean_document"], 0)

    def test_capability_subset_excludes_gold_and_predictions_explicitly(self):
        gold = [row("Tom a@b.co", [entity("Person", 0, 3), entity("Email", 4, 6)])]
        result = b.score_rows(gold, gold, 10, scope=["Email"])
        self.assertEqual(result["micro"]["true_positive"], 1)
        self.assertEqual(result["excluded_gold_types"], {"Person": 1})
        self.assertEqual(result["excluded_prediction_types"], {"Person": 1})
        self.assertEqual(list(result["by_type"]), ["Email"])
        with self.assertRaises(ValueError): b.score_rows(gold, gold, 10, scope=[])

    def test_missing_extra_duplicate_and_wrong_document_fail(self):
        gold = [row("Tom", [])]
        for predicted in ([], gold + gold, [row("Tom", [], "extra")], [row("Tim", [])]):
            with self.assertRaises(ValueError): b.score_rows(gold, predicted, 10)

    def test_utf16_non_bmp_and_invalid_spans(self):
        text = "😀 Tom"
        good = row(text, [entity("Person", 3, 3)])
        self.assertEqual(b.score_rows([good], [good], 10)["micro"]["true_positive"], 1)
        for start, length in ((1, 1), (-1, 1), (3, 4), (0, 0), (True, 1)):
            with self.assertRaises(ValueError):
                b.score_rows([good], [row(text, [entity("Person", start, length)])], 10)

    def test_duplicate_gold_rejected_and_unknown_prediction_visible(self):
        gold = row("Tom", [entity("Person", 0, 3)] * 2)
        with self.assertRaises(ValueError): b.score_rows([gold], [row("Tom", [])], 10)
        result = b.score_rows([row("Tom", [])], [row("Tom", [entity("Other", 0, 3)])], 10)
        self.assertEqual(result["excluded_prediction_types"], {"Other": 1})

    def test_projection_repetitions_name_parts_unicode_and_missing_labels(self):
        text = "😀 Tom Jones met Tom Jones"
        entities, excluded = b.align(text, [{"entity": "Tom", "types": ["first_name"]},
                                           {"entity": "Jones", "types": ["last_name"]},
                                           {"entity": "met", "types": ["unknown"]}])
        self.assertEqual(entities, [entity("Person", 3, 9), entity("Person", 17, 9)])
        self.assertEqual(excluded, {"unknown": 1})
        with self.assertRaises(ValueError): b.align(text, [{"entity": "absent", "types": ["name"]}])

    def test_leakage_normalizes_unicode_case_and_whitespace(self):
        self.assertEqual(b.normalized_hash("Ａlice\nSMITH"), b.normalized_hash("alice  smith"))
        self.assertNotEqual(b.normalized_hash("Alice Smith"), b.normalized_hash("Alice Jones"))

    def test_intervals_are_deterministic_document_level_and_nontrivial(self):
        rows = [(2, 0, 0, 0, 0), (0, 2, 3, 0, 0), (0, 1, 0, 1, 1)]
        first = b.summarize(rows, 100)
        self.assertEqual(first, b.summarize(rows, 100))
        self.assertLess(first["intervals_95"]["f1"]["lower"], first["intervals_95"]["f1"]["upper"])
        self.assertEqual(first["true_positive"], 2)

    def test_annotation_disagreement_counts_both_sides(self):
        a = [row("Tom Jones", [entity("Person", 0, 3)])]
        c = [row("Tom Jones", [entity("Person", 0, 9)])]
        self.assertEqual(b.score_rows(a, c, 10)["micro"]["f1"], 0)
        self.assertEqual(b.score_rows(a, c, 10)["micro"]["f1"], b.score_rows(c, a, 10)["micro"]["f1"])

    def test_regression_gates_and_incompatible_corpora(self):
        m = b.metrics(100, 0, 0, 100, 0)
        baseline = {"schema": 1, "scope": b.SCOPE, "corpus_sha256": "gold", "input_sha256": "inputs",
                    "engine": "same", "matching": "exact", "micro": m, "by_type": {k: m for k in b.SCOPE}}
        candidate = copy.deepcopy(baseline)
        self.assertTrue(b.regression(baseline, candidate)["passed"])
        candidate["micro"]["recall"] = .97
        self.assertFalse(b.regression(baseline, candidate)["passed"])
        candidate["corpus_sha256"] = "different"
        with self.assertRaises(ValueError): b.regression(baseline, candidate)

    def test_corpus_tampering_and_annotation_agreement_files(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            data = [row("Tom", [entity("Person", 0, 3)])]
            b.write_jsonl(folder / "gold.jsonl", data)
            b.write_jsonl(folder / "inputs.jsonl", [{"Id": "one", "Text": "Tom"}])
            manifest = {"scope": b.SCOPE, "mapping": b.GOLD_MAP,
                        "gold_sha256": b.digest((folder / "gold.jsonl").read_bytes()),
                        "input_sha256": b.digest((folder / "inputs.jsonl").read_bytes())}
            b.write_json(folder / "manifest.json", manifest)
            b.verify_corpus(folder)
            b.write_jsonl(folder / "second.jsonl", data)
            agreement = b.agreement(folder / "gold.jsonl", folder / "second.jsonl")
            self.assertEqual(agreement["exact_entity_agreement_f1"], 1)
            (folder / "gold.jsonl").write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError): b.verify_corpus(folder)

    def test_prediction_disables_network_and_restores_socket_functions(self):
        connect = socket.socket.connect
        with b.offline_prediction():
            with self.assertRaises(PermissionError): socket.getaddrinfo("localhost", 80)
            with socket.socket() as client:
                with self.assertRaises(PermissionError): client.connect(("127.0.0.1", 80))
        self.assertIs(socket.socket.connect, connect)


if __name__ == "__main__":
    unittest.main()
