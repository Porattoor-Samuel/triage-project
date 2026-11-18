"""Local logistic-regression URL phishing model trained from URL feature CSV data."""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np

from .config import URL_SHORTENERS

_CHARACTERS = (
    ("dot", "."),
    ("hyphen", "-"),
    ("underline", "_"),
    ("slash", "/"),
    ("questionmark", "?"),
    ("equal", "="),
    ("at", "@"),
    ("and", "&"),
    ("exclamation", "!"),
    ("space", " "),
    ("tilde", "~"),
    ("comma", ","),
    ("plus", "+"),
    ("asterisk", "*"),
    ("hashtag", "#"),
    ("dollar", "$"),
    ("percent", "%"),
)
_SYMBOL_FEATURE_NAMES = tuple(f"qty_{name}" for name, _ in _CHARACTERS)
_URL_FEATURES = tuple(f"{name}_url" for name in (*_SYMBOL_FEATURE_NAMES, "qty_tld", "length"))
_DOMAIN_FEATURES = tuple(
    f"{name}_domain" for name in (*_SYMBOL_FEATURE_NAMES, "qty_vowels")
) + ("domain_length", "domain_in_ip", "server_client_domain")
_DIRECTORY_FEATURES = tuple(f"{name}_directory" for name in _SYMBOL_FEATURE_NAMES) + ("directory_length",)
_FILE_FEATURES = tuple(f"{name}_file" for name in _SYMBOL_FEATURE_NAMES) + ("file_length",)
_PARAMETER_FEATURES = tuple(f"{name}_params" for name in _SYMBOL_FEATURE_NAMES) + (
    "params_length",
    "tld_present_params",
    "qty_params",
)
FEATURE_NAMES = (
    *_URL_FEATURES,
    *_DOMAIN_FEATURES,
    *_DIRECTORY_FEATURES,
    *_FILE_FEATURES,
    *_PARAMETER_FEATURES,
    "email_in_url",
    "url_shortened",
)
_LABEL = "phishing"
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_KNOWN_TLDS = (
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "in", "uk", "de",
    "fr", "au", "ca", "info", "biz", "xyz", "online", "site", "top", "ru", "cn",
)
_FEATURE_LABELS = {
    "qty_dot_url": "dots in URL",
    "qty_hyphen_url": "hyphens in URL",
    "qty_at_url": "@ symbols in URL",
    "qty_questionmark_url": "question marks in URL",
    "qty_equal_url": "equals signs in URL",
    "length_url": "URL length",
    "qty_dot_domain": "dots in domain",
    "qty_hyphen_domain": "hyphens in domain",
    "qty_vowels_domain": "vowels in domain",
    "domain_length": "domain length",
    "domain_in_ip": "IP-address domain",
    "server_client_domain": "server/client wording in domain",
    "directory_length": "path length",
    "file_length": "file-name length",
    "params_length": "query-string length",
    "qty_params": "query parameter count",
    "email_in_url": "email address embedded in URL",
    "url_shortened": "known URL shortener",
}


@dataclass(frozen=True)
class URLPrediction:
    url: str
    score: float | None
    threat: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class URLPhishingModel:
    means: np.ndarray
    scales: np.ndarray
    coefficients: np.ndarray
    intercept: float
    dataset_rows: int
    training_rows: int
    phishing_rows: int
    accuracy: float
    precision: float
    recall: float
    f1: float

    def assess(self, urls: list[str]) -> list[URLPrediction]:
        predictions = []
        for url in urls:
            try:
                features = url_features(url)
            except ValueError:
                predictions.append(URLPrediction(url, None, "Could not assess", ("Invalid URL structure",)))
                continue
            standardized_row = (features - self.means) / self.scales
            logit = float(standardized_row @ self.coefficients + self.intercept)
            score = 1.0 / (1.0 + np.exp(-np.clip(logit, -35, 35)))
            value = float(score)
            threat = (
                "Suspicious" if value >= 0.7
                else "Needs caution" if value >= 0.35
                else "No warning signs found"
            )
            contributions = standardized_row * self.coefficients
            strongest = np.argsort(contributions)[::-1]
            evidence = tuple(
                f"{_FEATURE_LABELS.get(FEATURE_NAMES[index], FEATURE_NAMES[index].replace('_', ' '))} "
                f"({features[index]:g})"
                for index in strongest
                if contributions[index] > 0.05
            )[:3]
            predictions.append(URLPrediction(url, value, threat, evidence))
        return predictions


def _count_symbols(text: str, section: str) -> dict[str, float]:
    return {f"qty_{name}_{section}": text.count(char) for name, char in _CHARACTERS}


def url_features(url: str) -> np.ndarray:
    """Extract the URL-structure fields available without network lookups."""
    candidate = url.strip()
    if not candidate:
        raise ValueError("URL must not be empty.")
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    domain = (parsed.hostname or "").lower()
    if not domain:
        raise ValueError(f"Could not identify a domain in URL: {url!r}")

    path = parsed.path or ""
    directory, separator, filename = path.rpartition("/")
    if separator:
        directory += "/"
    else:
        filename = path
    query = parsed.query
    values: dict[str, float] = {}
    values.update(_count_symbols(candidate, "url"))
    suffix = domain.rsplit(".", 1)[-1]
    values["qty_tld_url"] = candidate.lower().count(f".{suffix}") if "." in domain else 0
    values["length_url"] = len(candidate)

    values.update(_count_symbols(domain, "domain"))
    values["qty_vowels_domain"] = sum(domain.count(vowel) for vowel in "aeiou")
    values["domain_length"] = len(domain)
    try:
        ipaddress.ip_address(domain)
        values["domain_in_ip"] = 1
    except ValueError:
        values["domain_in_ip"] = 0
    values["server_client_domain"] = int("server" in domain or "client" in domain)

    values.update(_count_symbols(directory, "directory"))
    values["directory_length"] = len(directory)
    values.update(_count_symbols(filename, "file"))
    values["file_length"] = len(filename)

    if query:
        values.update(_count_symbols(query, "params"))
        values["params_length"] = len(query)
        values["tld_present_params"] = int(
            any(re.search(rf"(?:^|[^a-z]){re.escape(tld)}(?:$|[^a-z])", query, re.I) for tld in _KNOWN_TLDS)
        )
        values["qty_params"] = query.count("&") + 1
    else:
        values.update({f"qty_{name}_params": -1 for name, _ in _CHARACTERS})
        values["params_length"] = -1
        values["tld_present_params"] = -1
        values["qty_params"] = -1
    values["email_in_url"] = int(_EMAIL_RE.search(candidate) is not None)
    values["url_shortened"] = int(domain in URL_SHORTENERS)

    return np.asarray([values[name] for name in FEATURE_NAMES], dtype=np.float64)


def _read_dataset(path: Path) -> tuple[np.ndarray, np.ndarray]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or ())
        required = set(FEATURE_NAMES) | {_LABEL}
        missing = sorted(required - fields)
        if missing:
            raise ValueError(f"URL dataset is missing required columns: {', '.join(missing)}")
        rows = sum(1 for _ in reader)

    if rows < 10:
        raise ValueError(f"URL dataset needs at least 10 rows; found {rows}.")
    features = np.empty((rows, len(FEATURE_NAMES)), dtype=np.float64)
    labels = np.empty(rows, dtype=np.float64)
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        for index, row in enumerate(reader):
            try:
                labels[index] = float(row[_LABEL])
                features[index] = [float(row[name]) for name in FEATURE_NAMES]
            except (TypeError, ValueError) as error:
                raise ValueError(f"Invalid numeric value in URL dataset row {index + 2}.") from error
    if not np.isin(labels, (0, 1)).all():
        raise ValueError("The URL dataset's 'phishing' column must contain only 0 and 1.")
    if len(np.unique(labels)) != 2:
        raise ValueError("The URL dataset must contain both phishing labels (0 and 1).")
    return features, labels


def _metrics(expected: np.ndarray, predicted: np.ndarray) -> tuple[float, float, float, float]:
    true_positive = int(np.sum((expected == 1) & (predicted == 1)))
    false_positive = int(np.sum((expected == 0) & (predicted == 1)))
    false_negative = int(np.sum((expected == 1) & (predicted == 0)))
    accuracy = float(np.mean(expected == predicted))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return accuracy, precision, recall, f1


def train_url_model(dataset_path: str | Path) -> URLPhishingModel:
    """Fit a regularized logistic model with a deterministic stratified holdout."""
    features, labels = _read_dataset(Path(dataset_path))
    random = np.random.default_rng(42)
    training_parts = []
    testing_parts = []
    for label in (0.0, 1.0):
        indexes = np.flatnonzero(labels == label)
        random.shuffle(indexes)
        test_size = max(1, int(round(len(indexes) * 0.2)))
        testing_parts.append(indexes[:test_size])
        training_parts.append(indexes[test_size:])
    training_indexes = np.concatenate(training_parts)
    testing_indexes = np.concatenate(testing_parts)

    training_x = features[training_indexes]
    training_y = labels[training_indexes]
    means = training_x.mean(axis=0)
    scales = training_x.std(axis=0)
    scales[scales == 0] = 1.0
    standardized_x = (training_x - means) / scales
    positive_rate = float(training_y.mean())
    coefficients = np.zeros(standardized_x.shape[1], dtype=np.float64)
    intercept = float(np.log(positive_rate / (1.0 - positive_rate)))
    learning_rate = 0.2
    regularization = 0.01

    for _ in range(120):
        logits = standardized_x @ coefficients + intercept
        probabilities = 1.0 / (1.0 + np.exp(-np.clip(logits, -35, 35)))
        residual = probabilities - training_y
        coefficients -= learning_rate * (
            standardized_x.T @ residual / len(training_y) + regularization * coefficients
        )
        intercept -= learning_rate * float(residual.mean())

    testing_x = (features[testing_indexes] - means) / scales
    test_logits = testing_x @ coefficients + intercept
    test_scores = 1.0 / (1.0 + np.exp(-np.clip(test_logits, -35, 35)))
    accuracy, precision, recall, f1 = _metrics(labels[testing_indexes], (test_scores >= 0.5).astype(float))
    return URLPhishingModel(
        means=means,
        scales=scales,
        coefficients=coefficients,
        intercept=intercept,
        dataset_rows=len(labels),
        training_rows=len(training_indexes),
        phishing_rows=int(labels.sum()),
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
    )
