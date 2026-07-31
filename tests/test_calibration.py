from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from test_source_distance import make_references  # noqa: E402
from shortform_script_eval.calibration import (  # noqa: E402
    CalibrationApprovalDecision,
    CalibrationApprovalReceipt,
    CalibrationCase,
    CalibrationDataset,
    CalibrationDatasetTier,
    CalibrationRunner,
    TrialDistancePolicy,
    promote_trial_policy,
)
from shortform_script_eval.source_distance import (  # noqa: E402
    CandidateProjection,
    DistanceDecision,
    PolicyTier,
)


def make_trial() -> TrialDistancePolicy:
    return TrialDistancePolicy(
        policy_id="fixture-trial",
        policy_version="v1",
        char_ngram_size=5,
        word_shingle_size=3,
        longest_span_review_chars=24,
        char_jaccard_review=0.45,
        word_jaccard_review=0.40,
        event_lcs_review=0.75,
    )


def make_dataset(
    *,
    tier: CalibrationDatasetTier = CalibrationDatasetTier.SYNTHETIC,
) -> CalibrationDataset:
    references = make_references()
    return CalibrationDataset(
        dataset_id="fixture-calibration-set",
        dataset_version="v1",
        tier=tier,
        reference_manifest_sha256=references.manifest_sha256,
        cases=(
            CalibrationCase(
                case_id="original",
                candidate=CandidateProjection(
                    candidate_id="fixture-original",
                    text=(
                        "An analyst freezes a risky handoff and earns "
                        "provisional console authority."
                    ),
                    event_sequence=(
                        "public_test",
                        "risk_choice",
                        "provisional_authority",
                    ),
                ),
                expected_decision=DistanceDecision.PASS,
            ),
            CalibrationCase(
                case_id="borderline",
                candidate=CandidateProjection(
                    candidate_id="fixture-borderline",
                    text="A manager checks a process and changes the assignment.",
                    event_sequence=("warning", "queue_stop", "badge_reveal"),
                ),
                expected_decision=DistanceDecision.REVIEW_REQUIRED,
            ),
            CalibrationCase(
                case_id="copy",
                candidate=CandidateProjection(
                    candidate_id="fixture-copy",
                    text="The analyst wins trust by showing the hidden badge.",
                    event_sequence=("challenge", "badge_reveal"),
                ),
                expected_decision=DistanceDecision.FAIL,
            ),
        ),
        dataset_rights_receipt_sha256=(
            "d" * 64
            if tier is CalibrationDatasetTier.RIGHTS_CLEARED
            else None
        ),
    )


def run_calibration(dataset: CalibrationDataset):
    return CalibrationRunner().run(
        run_id="fixture-run",
        dataset=dataset,
        references=make_references(),
        trial_policy=make_trial(),
        evaluated_at="2026-07-31T10:00:00+09:00",
    )


class CalibrationTests(unittest.TestCase):
    def test_synthetic_run_measures_all_three_expected_decisions(self) -> None:
        run = run_calibration(make_dataset())

        self.assertTrue(run.passed_all)
        self.assertEqual(3, run.matched_count)

    def test_synthetic_run_cannot_promote_production_policy(self) -> None:
        dataset = make_dataset()
        run = run_calibration(dataset)
        approval = CalibrationApprovalReceipt.issue(
            run=run,
            decision=CalibrationApprovalDecision.APPROVE,
            reviewer_id="fixture-owner",
            reviewer_role="owner",
            decided_at="2026-07-31T10:05:00+09:00",
        )

        with self.assertRaisesRegex(ValueError, "synthetic"):
            promote_trial_policy(
                trial_policy=make_trial(),
                dataset=dataset,
                run=run,
                approval=approval,
            )

    def test_rights_cleared_exact_owner_approval_promotes_policy(self) -> None:
        dataset = make_dataset(tier=CalibrationDatasetTier.RIGHTS_CLEARED)
        run = run_calibration(dataset)
        approval = CalibrationApprovalReceipt.issue(
            run=run,
            decision=CalibrationApprovalDecision.APPROVE,
            reviewer_id="fixture-owner",
            reviewer_role="owner",
            decided_at="2026-07-31T10:05:00+09:00",
        )

        policy = promote_trial_policy(
            trial_policy=make_trial(),
            dataset=dataset,
            run=run,
            approval=approval,
        )

        self.assertIs(PolicyTier.PRODUCTION_APPROVED, policy.policy_tier)
        self.assertEqual(
            approval.receipt_sha256,
            policy.calibration_receipt_sha256,
        )

    def test_mismatched_run_cannot_be_approved_for_policy(self) -> None:
        dataset = make_dataset(tier=CalibrationDatasetTier.RIGHTS_CLEARED)
        run = run_calibration(dataset)
        mismatched = replace(run, trial_policy_content_sha256="e" * 64)
        approval = CalibrationApprovalReceipt.issue(
            run=mismatched,
            decision=CalibrationApprovalDecision.APPROVE,
            reviewer_id="fixture-owner",
            reviewer_role="owner",
            decided_at="2026-07-31T10:05:00+09:00",
        )

        with self.assertRaisesRegex(ValueError, "trial policy"):
            promote_trial_policy(
                trial_policy=make_trial(),
                dataset=dataset,
                run=mismatched,
                approval=approval,
            )


if __name__ == "__main__":
    unittest.main()
