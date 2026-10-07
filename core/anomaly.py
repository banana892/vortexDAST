"""
VortexDAST – core/anomaly.py
────────────────────────────────────────────────────────────────────────────
Statistical anomaly detection (Phase 4 §5.3).

A full ML model is overkill for flagging odd HTTP responses; robust statistics
catch the same outliers without training data or a heavyweight dependency. This
module builds a per-feature baseline from "normal" responses and flags responses
that deviate strongly — unusual body size, latency, header count, or status —
for manual review.

Two detectors are provided:

*   :class:`AnomalyDetector` — single numeric feature, modified **z-score** based
    on the median and MAD (median absolute deviation), which is far more robust
    to a few extreme values than mean/stddev.
*   :class:`ResponseAnomalyDetector` — several response features at once, each
    with its own baseline; a response is anomalous if any feature is an outlier.

numpy does the number-crunching; everything else is plain Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

# 0.6745 scales MAD to be a consistent estimator of stddev for normal data;
# |modified z| > 3.5 is the common Iglewicz–Hoaglin outlier threshold.
_MAD_SCALE = 0.6745
DEFAULT_THRESHOLD = 3.5
_MIN_SAMPLES = 5
# When the baseline has no spread (MAD == 0, e.g. near-identical responses),
# the z-score is undefined; flag a value only if it differs from the median by
# more than this fraction, which stays robust to a lone outlier in the baseline.
_ZERO_SPREAD_REL_TOLERANCE = 0.5

RESPONSE_FEATURES = ("body_length", "latency_ms", "header_count")


@dataclass
class AnomalyDetector:
    """Robust single-feature outlier detector (median/MAD modified z-score)."""

    threshold: float = DEFAULT_THRESHOLD
    _samples: List[float] = field(default_factory=list)

    def fit(self, values: List[float]) -> "AnomalyDetector":
        """Replace the baseline with ``values``."""
        self._samples = [float(v) for v in values]
        return self

    def observe(self, value: float) -> None:
        """Add one observation to the baseline."""
        self._samples.append(float(value))

    @property
    def ready(self) -> bool:
        """True once enough samples exist to judge outliers meaningfully."""
        return len(self._samples) >= _MIN_SAMPLES

    def score(self, value: float) -> float:
        """
        Modified z-score of ``value`` against the baseline. Returns 0.0 when the
        baseline is too small or has zero spread (every sample identical).
        """
        if not self.ready:
            return 0.0
        arr = np.asarray(self._samples, dtype=float)
        median = float(np.median(arr))
        mad = float(np.median(np.abs(arr - median)))
        if mad == 0.0:
            # No robust spread: the z-score is undefined. Compare to the median
            # (robust to a lone outlier) with a relative tolerance instead of
            # mean/stddev, which a single outlier would inflate (masking).
            denom = max(abs(median), 1.0)
            rel = abs(float(value) - median) / denom
            return float("inf") if rel > _ZERO_SPREAD_REL_TOLERANCE else 0.0
        return _MAD_SCALE * abs(float(value) - median) / mad

    def is_outlier(self, value: float) -> bool:
        """True if ``value``'s modified z-score exceeds the threshold."""
        return self.score(value) > self.threshold


@dataclass
class AnomalyResult:
    """One anomalous observation."""

    index: int
    features: Dict[str, float]
    reasons: Dict[str, float]  # feature → score that tripped the threshold

    @property
    def is_anomalous(self) -> bool:
        return bool(self.reasons)


class ResponseAnomalyDetector:
    """
    Multi-feature response anomaly detector.

    Fit on a set of "normal" response feature dicts, then test new responses.
    A response is anomalous if *any* tracked feature is an outlier.
    """

    def __init__(
        self,
        features: tuple = RESPONSE_FEATURES,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        self.features = features
        self._detectors: Dict[str, AnomalyDetector] = {
            name: AnomalyDetector(threshold=threshold) for name in features
        }

    def fit(self, observations: List[Dict[str, float]]) -> "ResponseAnomalyDetector":
        for name, detector in self._detectors.items():
            values = [float(obs[name]) for obs in observations if name in obs]
            detector.fit(values)
        return self

    @property
    def ready(self) -> bool:
        return any(d.ready for d in self._detectors.values())

    def check(self, observation: Dict[str, float]) -> Dict[str, float]:
        """Return a {feature: score} map of features that are outliers."""
        reasons: Dict[str, float] = {}
        for name, detector in self._detectors.items():
            if name in observation and detector.is_outlier(observation[name]):
                reasons[name] = round(detector.score(observation[name]), 2)
        return reasons

    def detect(self, observations: List[Dict[str, float]]) -> List[AnomalyResult]:
        """
        Fit on all observations, then flag the outliers among them.

        Useful for a one-shot pass over a scan's responses: the bulk defines
        "normal" and the detector surfaces the few that stand out.
        """
        self.fit(observations)
        results: List[AnomalyResult] = []
        for idx, obs in enumerate(observations):
            reasons = self.check(obs)
            if reasons:
                results.append(AnomalyResult(index=idx, features=dict(obs), reasons=reasons))
        return results
