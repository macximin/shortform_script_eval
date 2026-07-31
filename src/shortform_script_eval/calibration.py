"""Calibration runs and owner-approved production policy promotion."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import re

from .canonical import canonical_sha256
from .source_distance import (
    CandidateProjection,
    DistanceDecision,
    PolicyTier,
    ReferenceComparisonInput,
    SourceDistanceEvaluator,
    SourceDistancePolicy,
)


_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _require_sha256(value: str, field_name: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256")


class CalibrationDatasetTier(StrEnum):
    SYNTHETIC = "synthetic"
    RIGHTS_CLEARED = "rights_cleared"


@dataclass(frozen=True, slots=True)
class CalibrationCase:
    case_id: str
    candidate: CandidateProjection
    expected_decision: DistanceDecision

    def __post_init__(self) -> None:
        if not self.case_id.strip():
            raise ValueError("case_id must not be empty")
        if not isinstance(self.expected_decision, DistanceDecision):
            raise TypeError("expected_decision must be a DistanceDecision")


@dataclass(frozen=True, slots=True)
class CalibrationDataset:
    dataset_id: str
    dataset_version: str
    tier: CalibrationDatasetTier
    reference_manifest_sha256: str
    cases: tuple[CalibrationCase, ...]
    dataset_rights_receipt_sha256: str | None = None

    def __post_init__(self) -> None:
        if not self.dataset_id.strip() or not self.dataset_version.strip():
            raise ValueError("dataset id and version must not be empty")
        if not isinstance(self.tier, CalibrationDatasetTier):
            raise TypeError("tier must be a CalibrationDatasetTier")
        _require_sha256(
            self.reference_manifest_sha256,
            "reference_manifest_sha256",
        )
        if not self.cases:
            raise ValueError("calibration dataset requires cases")
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("calibration case ids must be unique")
        represented = {case.expected_decision for case in self.cases}
        if represented != set(DistanceDecision):
            raise ValueError(
                "calibration dataset must represent pass, review_required and fail"
            )
        if self.tier is CalibrationDatasetTier.RIGHTS_CLEARED:
            if self.dataset_rights_receipt_sha256 is None:
                raise ValueError(
                    "rights-cleared dataset requires a rights receipt"
                )
            _require_sha256(
                self.dataset_rights_receipt_sha256,
                "dataset_rights_receipt_sha256",
            )
        elif self.dataset_rights_receipt_sha256 is not None:
            raise ValueError(
                "synthetic dataset must not claim a rights receipt"
            )

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self)


@dataclass(frozen=True, slots=True)
class TrialDistancePolicy:
    policy_id: str
    policy_version: str
    char_ngram_size: int
    word_shingle_size: int
    longest_span_review_chars: int
    char_jaccard_review: float
    word_jaccard_review: float
    event_lcs_review: float

    def __post_init__(self) -> None:
        if not self.policy_id.strip() or not self.policy_version.strip():
            raise ValueError("policy id and version must not be empty")
        self.as_canary_policy()

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self)

    def as_canary_policy(self) -> SourceDistancePolicy:
        return SourceDistancePolicy(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            calibration_receipt_sha256="0" * 64,
            char_ngram_size=self.char_ngram_size,
            word_shingle_size=self.word_shingle_size,
            longest_span_review_chars=self.longest_span_review_chars,
            char_jaccard_review=self.char_jaccard_review,
            word_jaccard_review=self.word_jaccard_review,
            event_lcs_review=self.event_lcs_review,
            policy_tier=PolicyTier.SYNTHETIC_CANARY,
        )


@dataclass(frozen=True, slots=True)
class CalibrationCaseResult:
    case_id: str
    expected_decision: DistanceDecision
    observed_decision: DistanceDecision
    source_distance_receipt_sha256: str

    @property
    def matched(self) -> bool:
        return self.expected_decision is self.observed_decision


@dataclass(frozen=True, slots=True)
class CalibrationRun:
    run_id: str
    dataset_content_sha256: str
    dataset_tier: CalibrationDatasetTier
    trial_policy_content_sha256: str
    reference_manifest_sha256: str
    results: tuple[CalibrationCaseResult, ...]
    evaluated_at: str

    def __post_init__(self) -> None:
        if not self.run_id.strip() or not self.evaluated_at.strip():
            raise ValueError("run_id and evaluated_at must not be empty")
        for field_name in (
            "dataset_content_sha256",
            "trial_policy_content_sha256",
            "reference_manifest_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        if not isinstance(self.dataset_tier, CalibrationDatasetTier):
            raise TypeError("dataset_tier must be a CalibrationDatasetTier")
        if not self.results:
            raise ValueError("calibration run requires results")
        try:
            evaluated_at = datetime.fromisoformat(self.evaluated_at)
        except ValueError as error:
            raise ValueError("evaluated_at must be ISO-8601") from error
        if evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must include a timezone")

    @property
    def matched_count(self) -> int:
        return sum(result.matched for result in self.results)

    @property
    def passed_all(self) -> bool:
        return self.matched_count == len(self.results)

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self)


class CalibrationRunner:
    def run(
        self,
        *,
        run_id: str,
        dataset: CalibrationDataset,
        references: ReferenceComparisonInput,
        trial_policy: TrialDistancePolicy,
        evaluated_at: str,
    ) -> CalibrationRun:
        if dataset.reference_manifest_sha256 != references.manifest_sha256:
            raise ValueError(
                "calibration dataset does not bind the reference manifest"
            )
        runtime_policy = trial_policy.as_canary_policy()
        evaluator = SourceDistanceEvaluator()
        results = tuple(
            CalibrationCaseResult(
                case_id=case.case_id,
                expected_decision=case.expected_decision,
                observed_decision=receipt.decision,
                source_distance_receipt_sha256=receipt.receipt_sha256,
            )
            for case in dataset.cases
            for receipt in (
                evaluator.evaluate(
                    case.candidate,
                    references,
                    runtime_policy,
                    evaluated_at=evaluated_at,
                ),
            )
        )
        return CalibrationRun(
            run_id=run_id,
            dataset_content_sha256=dataset.content_sha256,
            dataset_tier=dataset.tier,
            trial_policy_content_sha256=trial_policy.content_sha256,
            reference_manifest_sha256=references.manifest_sha256,
            results=results,
            evaluated_at=evaluated_at,
        )


class CalibrationApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


@dataclass(frozen=True, slots=True)
class CalibrationApprovalReceipt:
    calibration_run_sha256: str
    decision: CalibrationApprovalDecision
    reviewer_id: str
    reviewer_role: str
    decided_at: str
    receipt_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.calibration_run_sha256,
            "calibration_run_sha256",
        )
        _require_sha256(self.receipt_sha256, "receipt_sha256")
        if not isinstance(self.decision, CalibrationApprovalDecision):
            raise TypeError("decision must be a CalibrationApprovalDecision")
        if not self.reviewer_id.strip() or not self.reviewer_role.strip():
            raise ValueError("reviewer identity and role must not be empty")
        try:
            decided_at = datetime.fromisoformat(self.decided_at)
        except ValueError as error:
            raise ValueError("decided_at must be ISO-8601") from error
        if decided_at.tzinfo is None:
            raise ValueError("decided_at must include a timezone")
        if self.receipt_sha256 != canonical_sha256(self.receipt_payload):
            raise ValueError("approval receipt hash does not bind payload")

    @property
    def receipt_payload(self) -> dict[str, object]:
        return {
            "calibration_run_sha256": self.calibration_run_sha256,
            "decision": self.decision,
            "reviewer_id": self.reviewer_id,
            "reviewer_role": self.reviewer_role,
            "decided_at": self.decided_at,
        }

    @classmethod
    def issue(
        cls,
        *,
        run: CalibrationRun,
        decision: CalibrationApprovalDecision,
        reviewer_id: str,
        reviewer_role: str,
        decided_at: str,
    ) -> "CalibrationApprovalReceipt":
        payload = {
            "calibration_run_sha256": run.content_sha256,
            "decision": decision,
            "reviewer_id": reviewer_id,
            "reviewer_role": reviewer_role,
            "decided_at": decided_at,
        }
        return cls(
            calibration_run_sha256=run.content_sha256,
            decision=decision,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            decided_at=decided_at,
            receipt_sha256=canonical_sha256(payload),
        )


def promote_trial_policy(
    *,
    trial_policy: TrialDistancePolicy,
    dataset: CalibrationDataset,
    run: CalibrationRun,
    approval: CalibrationApprovalReceipt,
) -> SourceDistancePolicy:
    if dataset.tier is not CalibrationDatasetTier.RIGHTS_CLEARED:
        raise ValueError("synthetic calibration cannot produce a production policy")
    if run.dataset_tier is not dataset.tier:
        raise ValueError("calibration run tier does not match dataset")
    if run.dataset_content_sha256 != dataset.content_sha256:
        raise ValueError("calibration run does not bind the exact dataset")
    if run.trial_policy_content_sha256 != trial_policy.content_sha256:
        raise ValueError("calibration run does not bind the exact trial policy")
    if not run.passed_all:
        raise ValueError("calibration run has mismatched expected decisions")
    if (
        approval.calibration_run_sha256 != run.content_sha256
        or approval.decision is not CalibrationApprovalDecision.APPROVE
        or approval.reviewer_role != "owner"
    ):
        raise ValueError("production policy requires exact owner approval")
    return SourceDistancePolicy(
        policy_id=trial_policy.policy_id,
        policy_version=trial_policy.policy_version,
        calibration_receipt_sha256=approval.receipt_sha256,
        char_ngram_size=trial_policy.char_ngram_size,
        word_shingle_size=trial_policy.word_shingle_size,
        longest_span_review_chars=trial_policy.longest_span_review_chars,
        char_jaccard_review=trial_policy.char_jaccard_review,
        word_jaccard_review=trial_policy.word_jaccard_review,
        event_lcs_review=trial_policy.event_lcs_review,
        policy_tier=PolicyTier.PRODUCTION_APPROVED,
    )
