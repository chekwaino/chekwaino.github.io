"""Models: the proposed edge security framework + baseline detectors (objectives 1 & 3).

Proposed `EdgeSecurityFramework` (edge-friendly, pure sklearn/numpy):
  stage 1  compact autoencoder (MLPRegressor bottleneck) trained on BENIGN flows only
           -> reconstruction error = anomaly score
  stage 2  attack-family classifier (HistGB / XGBoost / LightGBM) trained on labeled flows
           -> family + class probabilities
  stage 3  zero-day rule + policy engine (policy.py)

Baselines: XGBoost, Extra Trees, LightGBM, CatBoost classifiers, and a standalone
compact-autoencoder anomaly detector (binary via reconstruction-error threshold).
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import LabelEncoder, StandardScaler

from .policy import decide


# ----------------------------------------------------------------------------- framework
class CompactAutoencoder:
    """Compact bottleneck autoencoder implemented with MLPRegressor (edge-deployable)."""

    def __init__(self, hidden=(32, 8, 32), max_iter=60, random_state=42):
        self.hidden = tuple(hidden)
        self.max_iter = max_iter
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.ae = None
        self.threshold = None

    def fit(self, X_benign: np.ndarray, threshold_quantile: float = 0.99):
        Xs = self.scaler.fit_transform(np.asarray(X_benign, dtype=np.float64))
        n_in = Xs.shape[1]
        self.ae = MLPRegressor(
            hidden_layer_sizes=self.hidden,
            activation="relu",
            solver="adam",
            max_iter=self.max_iter,
            random_state=self.random_state,
            early_stopping=True,
            n_iter_no_change=10,
        )
        self.ae.fit(Xs, Xs)
        err = self.reconstruction_error(X_benign)
        self.threshold = float(np.quantile(err, threshold_quantile))
        return self

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        Xs = self.scaler.transform(np.asarray(X, dtype=np.float64))
        rec = self.ae.predict(Xs)
        return np.mean((Xs - rec) ** 2, axis=1)

    def predict_anomaly(self, X: np.ndarray) -> np.ndarray:
        return (self.reconstruction_error(X) > self.threshold).astype(int)


def make_classifier(kind: str = "histgb", params: dict | None = None, seed: int = 42):
    params = dict(params or {})
    if kind == "histgb":
        return HistGradientBoostingClassifier(random_state=seed, **params)
    if kind == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(random_state=seed, eval_metric="mlogloss", **params)
    if kind == "lightgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(random_state=seed, verbose=-1, **params)
    if kind == "catboost":
        from catboost import CatBoostClassifier
        return CatBoostClassifier(random_state=seed, verbose=0, **params)
    if kind == "extratrees":
        return ExtraTreesClassifier(random_state=seed, n_jobs=2, **params)
    raise ValueError(f"unknown classifier kind: {kind}")


class EdgeSecurityFramework:
    """Two-stage intelligent edge security framework with zero-day detection + policy engine."""

    def __init__(self, ae_hidden=(32, 8, 32), ae_max_iter=60,
                 ae_threshold_quantile=0.99, conf_threshold=0.60,
                 classifier_kind="histgb", classifier_params=None, seed=42):
        self.ae = CompactAutoencoder(hidden=ae_hidden, max_iter=ae_max_iter, random_state=seed)
        self.ae_threshold_quantile = ae_threshold_quantile
        self.conf_threshold = conf_threshold
        self.classifier_kind = classifier_kind
        self.classifier_params = classifier_params or {}
        self.seed = seed
        self.classifier = None
        self.classes_ = None
        self.feature_scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

    def fit(self, X, y_family, benign_label="BenignTraffic"):
        X = np.asarray(X, dtype=np.float64)
        y_family = np.asarray(y_family)
        Xs = self.feature_scaler.fit_transform(X)
        benign_mask = y_family == benign_label
        # stage 1: autoencoder on benign traffic only
        self.ae.fit(Xs[benign_mask], threshold_quantile=self.ae_threshold_quantile)
        # stage 2: family classifier on all labeled data (integer-encoded for XGB/LGBM/CatBoost)
        self.classifier = make_classifier(self.classifier_kind, self.classifier_params, self.seed)
        y_enc = self.label_encoder.fit_transform(y_family)
        self.classifier.fit(Xs, y_enc)
        self.classes_ = list(self.label_encoder.classes_)
        return self

    def _scores(self, X):
        Xs = self.feature_scaler.transform(np.asarray(X, dtype=np.float64))
        anom = self.ae.reconstruction_error(Xs)
        proba = self.classifier.predict_proba(Xs)
        return anom, proba

    def predict_family(self, X):
        _, proba = self._scores(X)
        return self.label_encoder.inverse_transform(proba.argmax(axis=1))

    def predict(self, X):
        """Full verdict per flow: dict of arrays."""
        anom, proba = self._scores(X)
        fam = np.array(self.classes_)[proba.argmax(axis=1)]
        conf = proba.max(axis=1)
        zero_day = (anom > self.ae.threshold) & (conf < self.conf_threshold) & (fam != "BenignTraffic")
        return {
            "family": fam,
            "confidence": conf,
            "anomaly_score": anom,
            "zero_day": zero_day,
            "is_attack": (fam != "BenignTraffic") | (anom > self.ae.threshold),
            "proba": proba,
        }

    def decide_policy(self, X):
        v = self.predict(X)
        decisions = [
            decide(f, c, a, self.ae.threshold, self.conf_threshold)
            for f, c, a in zip(v["family"], v["confidence"], v["anomaly_score"])
        ]
        return v, decisions

    # convenience for benchmark_predictor
    def predict_scores(self, X):
        return self.predict(X)["family"]


# ----------------------------------------------------------------------------- baselines
def make_baseline(name: str, params: dict | None = None, seed: int = 42):
    """One of: xgboost, extratrees, lightgbm, catboost (family classifiers)."""
    p = dict(params or {})
    if name == "xgboost":
        from xgboost import XGBClassifier
        return XGBClassifier(random_state=seed, eval_metric="mlogloss", n_jobs=2, **p)
    if name == "extratrees":
        return ExtraTreesClassifier(random_state=seed, n_jobs=2, **p)
    if name == "lightgbm":
        from lightgbm import LGBMClassifier
        return LGBMClassifier(random_state=seed, verbose=-1, n_jobs=2, **p)
    if name == "catboost":
        from catboost import CatBoostClassifier
        return CatBoostClassifier(random_state=seed, verbose=0, **p)
    raise ValueError(f"unknown baseline: {name}")


class BaselineClassifier:
    """Uniform wrapper: scaler + baseline classifier with predict/predict_proba."""

    def __init__(self, name: str, params: dict | None = None, seed: int = 42):
        self.name = name
        self.model = make_baseline(name, params, seed)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.classes_ = None

    def fit(self, X, y):
        Xs = self.scaler.fit_transform(np.asarray(X, dtype=np.float64))
        y_enc = self.label_encoder.fit_transform(np.asarray(y))
        self.model.fit(Xs, y_enc)
        self.classes_ = list(self.label_encoder.classes_)
        return self

    def predict(self, X):
        Xs = self.scaler.transform(np.asarray(X, dtype=np.float64))
        return self.label_encoder.inverse_transform(self.model.predict(Xs))

    def predict_proba(self, X):
        return self.model.predict_proba(self.scaler.transform(np.asarray(X, dtype=np.float64)))


class AutoencoderAnomalyDetector:
    """Standalone compact-autoencoder anomaly detector (binary: benign vs attack)."""

    def __init__(self, hidden=(32, 8, 32), max_iter=60, threshold_quantile=0.99, seed=42):
        self.ae = CompactAutoencoder(hidden=hidden, max_iter=max_iter, random_state=seed)
        self.threshold_quantile = threshold_quantile
        self.classes_ = np.array(["BenignTraffic", "Attack"])

    def fit(self, X, y, benign_label="BenignTraffic"):
        y = np.asarray(y)
        self.ae.fit(np.asarray(X, dtype=np.float64)[y == benign_label],
                    threshold_quantile=self.threshold_quantile)
        return self

    def predict(self, X):
        a = self.ae.predict_anomaly(np.asarray(X, dtype=np.float64))
        return np.where(a == 1, "Attack", "BenignTraffic")

    def predict_proba(self, X):
        err = self.ae.reconstruction_error(np.asarray(X, dtype=np.float64))
        # squash reconstruction error into a pseudo-probability of attack
        p = 1.0 - np.exp(-err / max(self.ae.threshold, 1e-12))
        return np.column_stack([1 - p, p])
