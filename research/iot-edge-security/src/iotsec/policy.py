"""Policy-based mitigation engine (objective 1 & 4).

Maps a detection verdict (attack family, anomaly score, classifier confidence) to a
mitigation action and produces a human-readable policy report entry for the dashboard.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict

# ordered most-severe-first
ACTIONS = ["QUARANTINE_DEVICE", "BLOCK", "RATE_LIMIT", "ALERT", "ALLOW"]

# severity ranking per attack family (used to pick the mitigation tier)
FAMILY_SEVERITY = {
    "DDoS": 5, "Mirai": 5, "DoS": 4, "Spoofing": 4,
    "Brute_Force": 3, "Web-based": 3, "Recon": 2,
    "BenignTraffic": 0, "Unknown": 3,
}


@dataclass
class PolicyDecision:
    action: str
    reason: str
    family: str
    anomaly_score: float
    confidence: float
    zero_day: bool

    def as_dict(self):
        return asdict(self)

    def report_line(self) -> str:
        zd = " [ZERO-DAY]" if self.zero_day else ""
        return (f"{self.action:<18} family={self.family:<12} conf={self.confidence:.2f} "
                f"anom={self.anomaly_score:.4f}{zd} :: {self.reason}")


def decide(family: str, confidence: float, anomaly_score: float,
           anom_threshold: float, conf_threshold: float,
           family_severity: dict | None = None) -> PolicyDecision:
    """Policy decision for a single flow.

    Rules (evaluated top-down):
      1. zero-day: anomaly above threshold AND confidence below threshold -> ALERT + flag,
         escalated to BLOCK if the anomaly score is extreme (>2x threshold).
      2. known attack: severity>=4 -> BLOCK, 3 -> RATE_LIMIT, 2 -> ALERT.
      3. benign but anomalous (score > threshold) -> ALERT (possible novel benign behavior).
      4. otherwise ALLOW.
    """
    sev = (family_severity or FAMILY_SEVERITY).get(family, 3)
    zero_day = (anomaly_score > anom_threshold) and (confidence < conf_threshold) and family != "BenignTraffic"
    if zero_day:
        if anomaly_score > 2 * anom_threshold:
            return PolicyDecision("BLOCK", "zero-day anomaly, extreme reconstruction error",
                                  family, anomaly_score, confidence, True)
        return PolicyDecision("ALERT", "zero-day: anomalous flow with low classifier confidence",
                              family, anomaly_score, confidence, True)
    if family not in ("BenignTraffic", "Unknown") and confidence >= conf_threshold:
        if sev >= 4:
            return PolicyDecision("BLOCK", f"confirmed {family} attack (severity {sev})",
                                  family, anomaly_score, confidence, False)
        if sev == 3:
            return PolicyDecision("RATE_LIMIT", f"{family} attack (severity 3): throttle source",
                                  family, anomaly_score, confidence, False)
        return PolicyDecision("ALERT", f"{family} activity (severity {sev}): alert SOC",
                              family, anomaly_score, confidence, False)
    if anomaly_score > anom_threshold:
        return PolicyDecision("ALERT", "anomalous flow below confidence threshold",
                              family, anomaly_score, confidence, False)
    return PolicyDecision("ALLOW", "normal traffic", family, anomaly_score, confidence, False)
