import csv

import numpy as np
import pytest

from triage.url_model import FEATURE_NAMES, train_url_model, url_features


def test_url_features_match_dataset_schema():
    features = url_features("http://192.0.2.10/login?user=student")
    values = dict(zip(FEATURE_NAMES, features, strict=True))

    assert len(features) == len(FEATURE_NAMES)
    assert values["domain_in_ip"] == 1
    assert values["qty_questionmark_url"] == 1
    assert values["qty_params"] == 1
    assert values["url_shortened"] == 0


def test_url_features_mark_missing_query_features():
    values = dict(zip(FEATURE_NAMES, url_features("https://example.edu/path"), strict=True))

    assert values["qty_params"] == -1
    assert values["params_length"] == -1


def test_url_feature_extraction_rejects_missing_domain():
    with pytest.raises(ValueError, match="Could not identify a domain"):
        url_features("https:///path")


def test_model_training_scores_synthetic_phishing_urls_higher(tmp_path):
    dataset = tmp_path / "url_features.csv"
    legitimate = [f"https://campus{i}.edu.in/academics" for i in range(30)]
    phishing = [f"http://192.0.2.{i + 1}/verify?account={i}" for i in range(30)]
    with dataset.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=[*FEATURE_NAMES, "phishing"])
        writer.writeheader()
        for label, urls in ((0, legitimate), (1, phishing)):
            for url in urls:
                writer.writerow(dict(zip(FEATURE_NAMES, url_features(url), strict=True)) | {"phishing": label})

    model = train_url_model(dataset)
    predictions = model.assess([legitimate[0], phishing[0], "https:///invalid"])

    assert model.dataset_rows == 60
    assert model.training_rows == 48
    assert np.isfinite(model.accuracy)
    assert predictions[1].score is not None
    assert predictions[0].score is not None
    assert predictions[1].score > predictions[0].score
    assert predictions[2].threat == "Could not assess"
