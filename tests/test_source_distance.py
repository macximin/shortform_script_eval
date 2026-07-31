from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import hashlib
import sys
import unittest
import unicodedata


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from shortform_script_eval.canonical import canonical_sha256  # noqa: E402
from shortform_script_eval.source_distance import (  # noqa: E402
    CandidateProjection,
    DistanceDecision,
    ReferenceComparisonInput,
    ReferenceExcerptInput,
    SourceDistanceEvaluator,
    SourceDistancePolicy,
)


def normalized_hash(text: str) -> str:
    normalized = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def make_references() -> ReferenceComparisonInput:
    text = "A fictional operator stops the unsafe queue and reveals a hidden badge."
    events = ("warning", "queue_stop", "badge_reveal")
    excerpt = ReferenceExcerptInput(
        source_id="synthetic-source-01",
        rights_status="cleared_for_distance_eval",
        content_sha256=normalized_hash(text),
        event_sequence_sha256=canonical_sha256(events),
        rights_receipt_sha256="a" * 64,
        text=text,
        event_sequence=events,
        protected_phrases=("hidden badge",),
    )
    manifest = {
        "packet_id": "synthetic-packet",
        "packet_version": "fixture-v1",
        "created_at": "2026-07-30T14:05:00+09:00",
        "excerpts": (
            {
                "source_id": excerpt.source_id,
                "rights_status": excerpt.rights_status,
                "content_sha256": excerpt.content_sha256,
                "event_sequence_sha256": excerpt.event_sequence_sha256,
                "rights_receipt_sha256": excerpt.rights_receipt_sha256,
                "protected_phrase_hashes": excerpt.protected_phrase_hashes,
            },
        ),
    }
    return ReferenceComparisonInput(
        packet_id="synthetic-packet",
        packet_version="fixture-v1",
        created_at="2026-07-30T14:05:00+09:00",
        excerpts=(excerpt,),
        manifest_sha256=canonical_sha256(manifest),
    )


def make_policy() -> SourceDistancePolicy:
    return SourceDistancePolicy(
        policy_id="synthetic-calibrated-policy",
        policy_version="fixture-v1",
        calibration_receipt_sha256="b" * 64,
        char_ngram_size=5,
        word_shingle_size=3,
        longest_span_review_chars=24,
        char_jaccard_review=0.45,
        word_jaccard_review=0.40,
        event_lcs_review=0.75,
    )


class SourceDistanceTests(unittest.TestCase):
    def test_distinct_candidate_passes_and_receipt_has_no_raw_source(self) -> None:
        candidate = CandidateProjection(
            candidate_id="original-work:ep001:variant-a",
            text=(
                "An analyst freezes a risky handoff, lets a timer expire, "
                "and earns provisional console authority."
            ),
            event_sequence=("public_test", "risk_choice", "provisional_authority"),
        )

        receipt = SourceDistanceEvaluator().evaluate(
            candidate,
            make_references(),
            make_policy(),
            evaluated_at="2026-07-30T15:00:00+09:00",
        )

        self.assertEqual(DistanceDecision.PASS, receipt.decision)
        self.assertNotIn("hidden badge", repr(receipt.receipt_payload))
        self.assertEqual(
            canonical_sha256(receipt.receipt_payload),
            receipt.receipt_sha256,
        )

    def test_protected_phrase_overlap_hard_fails(self) -> None:
        candidate = CandidateProjection(
            candidate_id="original-work:ep001:variant-b",
            text="The analyst wins trust by showing the hidden badge.",
            event_sequence=("challenge", "badge_reveal"),
        )

        receipt = SourceDistanceEvaluator().evaluate(
            candidate,
            make_references(),
            make_policy(),
            evaluated_at="2026-07-30T15:00:00+09:00",
        )

        self.assertEqual(DistanceDecision.FAIL, receipt.decision)
        self.assertIn(
            "PROTECTED_PHRASE_OVERLAP",
            receipt.metrics[0].review_trigger_codes,
        )
        self.assertNotIn("hidden badge", repr(receipt.receipt_payload))

    def test_high_event_similarity_requires_review_not_automatic_failure(
        self,
    ) -> None:
        candidate = CandidateProjection(
            candidate_id="original-work:ep001:variant-c",
            text="A manager checks a process and changes the assignment.",
            event_sequence=("warning", "queue_stop", "badge_reveal"),
        )

        receipt = SourceDistanceEvaluator().evaluate(
            candidate,
            make_references(),
            make_policy(),
            evaluated_at="2026-07-30T15:00:00+09:00",
        )

        self.assertEqual(DistanceDecision.REVIEW_REQUIRED, receipt.decision)
        self.assertIn(
            "EVENT_SEQUENCE_SIMILARITY",
            receipt.metrics[0].review_trigger_codes,
        )

    def test_policy_requires_calibration_receipt(self) -> None:
        with self.assertRaisesRegex(ValueError, "calibration"):
            SourceDistancePolicy(
                policy_id="bad-policy",
                policy_version="v1",
                calibration_receipt_sha256="not-a-hash",
                char_ngram_size=5,
                word_shingle_size=3,
                longest_span_review_chars=24,
                char_jaccard_review=0.45,
                word_jaccard_review=0.40,
                event_lcs_review=0.75,
            )

    def test_eval_rejects_source_without_cleared_rights_status(self) -> None:
        excerpt = make_references().excerpts[0]

        with self.assertRaisesRegex(ValueError, "not cleared"):
            replace(excerpt, rights_status="unverified")


if __name__ == "__main__":
    unittest.main()
