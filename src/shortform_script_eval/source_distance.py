"""Calibrated lexical, protected-phrase, and event-distance evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from difflib import SequenceMatcher
from enum import StrEnum
import hashlib
import re
import unicodedata

from .canonical import canonical_sha256


EVALUATOR_VERSION = "source-distance-v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def normalize_text(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _text_sha256(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def _require_sha256(value: str, field_name: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256")


def _ngrams(text: str, size: int) -> set[str]:
    if len(text) < size:
        return {text} if text else set()
    return {text[index : index + size] for index in range(len(text) - size + 1)}


def _word_shingles(text: str, size: int) -> set[tuple[str, ...]]:
    words = text.split()
    if len(words) < size:
        return {tuple(words)} if words else set()
    return {
        tuple(words[index : index + size])
        for index in range(len(words) - size + 1)
    }


def _jaccard[T](left: set[T], right: set[T]) -> float:
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _event_lcs_ratio(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left or not right:
        return 0.0
    previous = [0] * (len(right) + 1)
    for left_item in left:
        current = [0]
        for index, right_item in enumerate(right, start=1):
            if left_item == right_item:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(current[-1], previous[index]))
        previous = current
    return previous[-1] / min(len(left), len(right))


@dataclass(frozen=True, slots=True)
class ReferenceExcerptInput:
    source_id: str
    rights_status: str
    content_sha256: str
    event_sequence_sha256: str
    rights_receipt_sha256: str
    text: str
    event_sequence: tuple[str, ...]
    protected_phrases: tuple[str, ...]
    allowed_overlap_phrases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_id.strip() or not self.text.strip():
            raise ValueError("source_id and text must not be empty")
        if self.rights_status != "cleared_for_distance_eval":
            raise ValueError("source is not cleared for distance evaluation")
        for field_name in (
            "content_sha256",
            "event_sequence_sha256",
            "rights_receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        if self.content_sha256 != _text_sha256(self.text):
            raise ValueError("content_sha256 does not match normalized source text")
        if self.event_sequence_sha256 != canonical_sha256(self.event_sequence):
            raise ValueError("event_sequence_sha256 does not match event_sequence")
        if not self.event_sequence:
            raise ValueError("event_sequence must not be empty")
        for field_name in ("protected_phrases", "allowed_overlap_phrases"):
            values = getattr(self, field_name)
            if any(not value.strip() for value in values):
                raise ValueError(f"{field_name} values must not be empty")
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} values must be unique")
        if set(self.allowed_overlap_phrases) - set(self.protected_phrases):
            raise ValueError(
                "allowed_overlap_phrases must be a subset of protected_phrases"
            )

    @property
    def protected_phrase_hashes(self) -> tuple[str, ...]:
        return tuple(_text_sha256(phrase) for phrase in self.protected_phrases)


@dataclass(frozen=True, slots=True)
class ReferenceComparisonInput:
    packet_id: str
    packet_version: str
    created_at: str
    excerpts: tuple[ReferenceExcerptInput, ...]
    manifest_sha256: str

    def __post_init__(self) -> None:
        for field_name in ("packet_id", "packet_version", "created_at"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be empty")
        _require_sha256(self.manifest_sha256, "manifest_sha256")
        if not self.excerpts:
            raise ValueError("comparison input requires at least one excerpt")
        if len({excerpt.source_id for excerpt in self.excerpts}) != len(
            self.excerpts
        ):
            raise ValueError("source ids must be unique")
        if canonical_sha256(self.manifest) != self.manifest_sha256:
            raise ValueError("manifest_sha256 does not match comparison manifest")

    @property
    def manifest(self) -> dict[str, object]:
        return {
            "packet_id": self.packet_id,
            "packet_version": self.packet_version,
            "created_at": self.created_at,
            "excerpts": tuple(
                {
                    "source_id": excerpt.source_id,
                    "rights_status": excerpt.rights_status,
                    "content_sha256": excerpt.content_sha256,
                    "event_sequence_sha256": excerpt.event_sequence_sha256,
                    "rights_receipt_sha256": excerpt.rights_receipt_sha256,
                    "protected_phrase_hashes": excerpt.protected_phrase_hashes,
                }
                for excerpt in self.excerpts
            ),
        }


@dataclass(frozen=True, slots=True)
class CandidateProjection:
    candidate_id: str
    text: str
    event_sequence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.candidate_id.strip() or not self.text.strip():
            raise ValueError("candidate_id and text must not be empty")
        if not self.event_sequence:
            raise ValueError("candidate event_sequence must not be empty")
        if any(not event.strip() for event in self.event_sequence):
            raise ValueError("candidate events must not be empty")

    @property
    def projection_payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "text": normalize_text(self.text),
            "event_sequence": self.event_sequence,
        }

    @property
    def projection_sha256(self) -> str:
        return canonical_sha256(self.projection_payload)


class PolicyTier(StrEnum):
    SYNTHETIC_CANARY = "synthetic_canary"
    PRODUCTION_APPROVED = "production_approved"


@dataclass(frozen=True, slots=True)
class SourceDistancePolicy:
    policy_id: str
    policy_version: str
    calibration_receipt_sha256: str
    char_ngram_size: int
    word_shingle_size: int
    longest_span_review_chars: int
    char_jaccard_review: float
    word_jaccard_review: float
    event_lcs_review: float
    policy_tier: PolicyTier = PolicyTier.SYNTHETIC_CANARY

    def __post_init__(self) -> None:
        if not isinstance(self.policy_tier, PolicyTier):
            raise TypeError("policy_tier must be a PolicyTier")
        if not self.policy_id.strip() or not self.policy_version.strip():
            raise ValueError("policy id and version must not be empty")
        _require_sha256(
            self.calibration_receipt_sha256,
            "calibration_receipt_sha256",
        )
        if (
            self.policy_tier is PolicyTier.PRODUCTION_APPROVED
            and self.calibration_receipt_sha256 == "0" * 64
        ):
            raise ValueError(
                "production policy requires a non-placeholder calibration receipt"
            )
        if self.char_ngram_size < 2 or self.word_shingle_size < 2:
            raise ValueError("ngram and shingle sizes must be at least two")
        if self.longest_span_review_chars < self.char_ngram_size:
            raise ValueError("longest span threshold must cover an ngram")
        for field_name in (
            "char_jaccard_review",
            "word_jaccard_review",
            "event_lcs_review",
        ):
            value = getattr(self, field_name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{field_name} must be between zero and one")

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self)


class DistanceDecision(StrEnum):
    PASS = "pass"
    REVIEW_REQUIRED = "review_required"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class SourceDistanceMetric:
    source_id: str
    longest_common_span_chars: int
    char_ngram_jaccard: float
    word_shingle_jaccard: float
    event_lcs_ratio: float
    forbidden_phrase_hashes: tuple[str, ...]
    allowed_phrase_hashes: tuple[str, ...]
    review_trigger_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceDistanceReceipt:
    receipt_version: str
    evaluator_version: str
    candidate_id: str
    candidate_projection_sha256: str
    reference_manifest_sha256: str
    policy_id: str
    policy_version: str
    policy_tier: PolicyTier
    policy_content_sha256: str
    calibration_receipt_sha256: str
    decision: DistanceDecision
    metrics: tuple[SourceDistanceMetric, ...]
    evaluated_at: str
    receipt_sha256: str

    def __post_init__(self) -> None:
        for field_name in (
            "receipt_version",
            "evaluator_version",
            "candidate_id",
            "policy_id",
            "policy_version",
            "evaluated_at",
        ):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be empty")
        for field_name in (
            "candidate_projection_sha256",
            "reference_manifest_sha256",
            "policy_content_sha256",
            "calibration_receipt_sha256",
            "receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        if not isinstance(self.decision, DistanceDecision):
            raise TypeError("decision must be a DistanceDecision")
        if not isinstance(self.policy_tier, PolicyTier):
            raise TypeError("policy_tier must be a PolicyTier")
        try:
            evaluated_at = datetime.fromisoformat(self.evaluated_at)
        except ValueError as error:
            raise ValueError("evaluated_at must be ISO-8601") from error
        if evaluated_at.tzinfo is None:
            raise ValueError("evaluated_at must include a timezone")
        if self.receipt_sha256 != canonical_sha256(self.receipt_payload):
            raise ValueError("receipt_sha256 does not bind receipt payload")

    @property
    def receipt_payload(self) -> dict[str, object]:
        return {
            "receipt_version": self.receipt_version,
            "evaluator_version": self.evaluator_version,
            "candidate_id": self.candidate_id,
            "candidate_projection_sha256": self.candidate_projection_sha256,
            "reference_manifest_sha256": self.reference_manifest_sha256,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_tier": self.policy_tier,
            "policy_content_sha256": self.policy_content_sha256,
            "calibration_receipt_sha256": self.calibration_receipt_sha256,
            "decision": self.decision,
            "metrics": self.metrics,
            "evaluated_at": self.evaluated_at,
        }


class SourceDistanceEvaluator:
    def evaluate(
        self,
        candidate: CandidateProjection,
        references: ReferenceComparisonInput,
        policy: SourceDistancePolicy,
        *,
        evaluated_at: str,
    ) -> SourceDistanceReceipt:
        candidate_text = normalize_text(candidate.text)
        metrics: list[SourceDistanceMetric] = []
        has_forbidden_overlap = False
        has_review_trigger = False

        for excerpt in references.excerpts:
            source_text = normalize_text(excerpt.text)
            match = SequenceMatcher(
                None,
                candidate_text,
                source_text,
                autojunk=False,
            ).find_longest_match()
            char_jaccard = _jaccard(
                _ngrams(candidate_text, policy.char_ngram_size),
                _ngrams(source_text, policy.char_ngram_size),
            )
            word_jaccard = _jaccard(
                _word_shingles(candidate_text, policy.word_shingle_size),
                _word_shingles(source_text, policy.word_shingle_size),
            )
            event_ratio = _event_lcs_ratio(
                candidate.event_sequence,
                excerpt.event_sequence,
            )
            allowed_normalized = {
                normalize_text(phrase) for phrase in excerpt.allowed_overlap_phrases
            }
            matched = tuple(
                phrase
                for phrase in excerpt.protected_phrases
                if normalize_text(phrase) in candidate_text
            )
            forbidden_hashes = tuple(
                _text_sha256(phrase)
                for phrase in matched
                if normalize_text(phrase) not in allowed_normalized
            )
            allowed_hashes = tuple(
                _text_sha256(phrase)
                for phrase in matched
                if normalize_text(phrase) in allowed_normalized
            )
            triggers: list[str] = []
            if match.size >= policy.longest_span_review_chars:
                triggers.append("LONG_EXACT_SPAN")
            if char_jaccard >= policy.char_jaccard_review:
                triggers.append("CHAR_NGRAM_SIMILARITY")
            if word_jaccard >= policy.word_jaccard_review:
                triggers.append("WORD_SHINGLE_SIMILARITY")
            if event_ratio >= policy.event_lcs_review:
                triggers.append("EVENT_SEQUENCE_SIMILARITY")
            if forbidden_hashes:
                triggers.append("PROTECTED_PHRASE_OVERLAP")
                has_forbidden_overlap = True
            if triggers:
                has_review_trigger = True
            metrics.append(
                SourceDistanceMetric(
                    source_id=excerpt.source_id,
                    longest_common_span_chars=match.size,
                    char_ngram_jaccard=round(char_jaccard, 6),
                    word_shingle_jaccard=round(word_jaccard, 6),
                    event_lcs_ratio=round(event_ratio, 6),
                    forbidden_phrase_hashes=forbidden_hashes,
                    allowed_phrase_hashes=allowed_hashes,
                    review_trigger_codes=tuple(triggers),
                )
            )

        if has_forbidden_overlap:
            decision = DistanceDecision.FAIL
        elif has_review_trigger:
            decision = DistanceDecision.REVIEW_REQUIRED
        else:
            decision = DistanceDecision.PASS
        metric_tuple = tuple(metrics)
        payload = {
            "receipt_version": "1",
            "evaluator_version": EVALUATOR_VERSION,
            "candidate_id": candidate.candidate_id,
            "candidate_projection_sha256": candidate.projection_sha256,
            "reference_manifest_sha256": references.manifest_sha256,
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_tier": policy.policy_tier,
            "policy_content_sha256": policy.content_sha256,
            "calibration_receipt_sha256": policy.calibration_receipt_sha256,
            "decision": decision,
            "metrics": metric_tuple,
            "evaluated_at": evaluated_at,
        }
        return SourceDistanceReceipt(
            receipt_version="1",
            evaluator_version=EVALUATOR_VERSION,
            candidate_id=candidate.candidate_id,
            candidate_projection_sha256=candidate.projection_sha256,
            reference_manifest_sha256=references.manifest_sha256,
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_tier=policy.policy_tier,
            policy_content_sha256=policy.content_sha256,
            calibration_receipt_sha256=policy.calibration_receipt_sha256,
            decision=decision,
            metrics=metric_tuple,
            evaluated_at=evaluated_at,
            receipt_sha256=canonical_sha256(payload),
        )
