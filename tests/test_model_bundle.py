"""M08 / F09 R3, R4, R6: the age-gate release gate."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from t1.sealed.bundle import (
    BOUNDARY_BAND,
    REMEDY,
    ModelBundle,
    ModelCard,
    ModelStore,
    Refusal,
    SuppressionBaseline,
    digest_of,
    sign,
)

WEIGHTS = b"weights"
KEY = b"model-bundle-test-key"
OTHER_KEY = b"release-key-not-the-model-key"


def _card(with_boundary: bool = True) -> ModelCard:
    return ModelCard(
        coverage="retail, 4 sectors, 61k frames",
        known_gaps=("low light below 30 lux",),
        boundary_error_rate={BOUNDARY_BAND: 0.071} if with_boundary else {"all": 0.019},
    )


def _bundle(version: int = 2, with_boundary: bool = True) -> ModelBundle:
    return ModelBundle(
        bundle_id="det-age-trunk",
        version=version,
        age_gate_version="1.2",
        digest=digest_of(WEIGHTS),
        card=_card(with_boundary),
    )


def test_a_valid_bundle_activates_and_raises_the_floor() -> None:
    store = ModelStore(key=KEY)
    bundle = _bundle(version=2)
    assert store.activate(bundle, sign(bundle, KEY), WEIGHTS) is None
    assert store.active is bundle
    assert store.version_floor == 2


def test_a_card_without_the_boundary_error_rate_is_refused() -> None:
    store = ModelStore(key=KEY)
    good = _bundle(version=2)
    store.activate(good, sign(good, KEY), WEIGHTS)

    incomplete = _bundle(version=3, with_boundary=False)
    assert (
        store.activate(incomplete, sign(incomplete, KEY), WEIGHTS) is Refusal.MODEL_CARD_INCOMPLETE
    )
    # The previous bundle stays active: a refusal never leaves the device without a gate.
    assert store.active is good
    assert store.refusals[Refusal.MODEL_CARD_INCOMPLETE] == 1


def test_a_bundle_signed_with_another_key_is_refused() -> None:
    store = ModelStore(key=KEY)
    bundle = _bundle()
    assert store.activate(bundle, sign(bundle, OTHER_KEY), WEIGHTS) is Refusal.SIGNATURE_INVALID
    assert store.active is None


def test_a_bundle_signed_in_another_domain_is_refused_before_the_signature_is_checked() -> None:
    store = ModelStore(key=KEY)
    bundle = replace(_bundle(), signing_domain="privacy-policy")
    assert store.activate(bundle, sign(bundle, KEY), WEIGHTS) is Refusal.WRONG_SIGNING_DOMAIN


def test_the_signature_binds_the_card_not_just_the_version() -> None:
    store = ModelStore(key=KEY)
    honest = _bundle(version=2)
    signature = sign(honest, KEY)
    forged = replace(honest, card=replace(_card(), boundary_error_rate={BOUNDARY_BAND: 0.001}))
    assert store.activate(forged, signature, WEIGHTS) is Refusal.SIGNATURE_INVALID


def test_an_older_bundle_cannot_be_reinstated() -> None:
    store = ModelStore(key=KEY)
    new = _bundle(version=5)
    store.activate(new, sign(new, KEY), WEIGHTS)
    old = _bundle(version=4)
    assert store.activate(old, sign(old, KEY), WEIGHTS) is Refusal.BUNDLE_DOWNGRADE
    assert store.active is new


def test_substituted_weights_cannot_run_under_a_valid_bundle_identity() -> None:
    store = ModelStore(key=KEY)
    bundle = _bundle()
    refusal = store.activate(bundle, sign(bundle, KEY), b"other weights")
    assert refusal is Refusal.PAYLOAD_DIGEST_MISMATCH
    assert store.active is None


def test_the_downgrade_floor_survives_a_restart(tmp_path: Path) -> None:
    floor = tmp_path / "model-floor"
    store = ModelStore(key=KEY, floor_path=floor)
    new = _bundle(version=5)
    store.activate(new, sign(new, KEY), WEIGHTS)

    restarted = ModelStore(key=KEY, floor_path=floor)
    assert restarted.version_floor == 5
    old = _bundle(version=4)
    assert restarted.activate(old, sign(old, KEY), WEIGHTS) is Refusal.BUNDLE_DOWNGRADE


def test_attestation_carries_the_age_gate_version_and_the_measured_boundary_error() -> None:
    store = ModelStore(key=KEY)
    assert store.attestation()["age_gate_ver"] is None
    bundle = _bundle()
    store.activate(bundle, sign(bundle, KEY), WEIGHTS)
    assert store.attestation() == {
        "model_bundle": bundle.digest,
        "age_gate_ver": "1.2",
        "boundary_error_16_24": 0.071,
    }


def test_a_suppression_collapse_halts_the_rollout() -> None:
    store = ModelStore(key=KEY)
    baseline = SuppressionBaseline(mean=0.08, sigma=0.01)
    assert store.rollout_halts(0.075, baseline) is False
    # 8% to 2% is six sigma at this site: a compliance event, not a metric wobble.
    assert store.rollout_halts(0.02, baseline) is True


def test_a_site_with_no_variance_treats_any_change_as_anomalous() -> None:
    baseline = SuppressionBaseline(mean=0.05, sigma=0.0)
    assert baseline.anomalous(0.05) is False
    assert baseline.anomalous(0.051) is True


def test_every_refusal_has_a_remedy() -> None:
    assert set(REMEDY) == set(Refusal)
    assert all(REMEDY[r].strip() for r in Refusal)
