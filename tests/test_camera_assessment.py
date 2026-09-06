"""F02: scores are closed-set evidence, and a bad stream cannot drift into the commitment."""

from __future__ import annotations

import json
from dataclasses import replace

from t1.devices.assessment import (
    COUNTING_THRESHOLD,
    REMEDY,
    AccuracyCommitment,
    CommitmentRefusal,
    Issue,
    Stream,
    assess,
    commit,
)

KEY = b"assessment-key"


def _good(stream_id: str = "cam1") -> Stream:
    return Stream(
        stream_id,
        depression_degrees=35.0,
        height_px=1080,
        achieved_fps=10.0,
        occlusion_fraction=0.02,
        lens_clarity=0.95,
    )


def test_a_well_mounted_camera_scores_above_the_threshold_with_no_issues() -> None:
    score = assess(_good())

    assert score.issues == ()
    assert score.counting_score >= COUNTING_THRESHOLD
    assert score.suitable


def test_a_shallow_backlit_camera_is_named_not_guessed() -> None:
    score = assess(
        Stream(
            "cam3",
            depression_degrees=8.0,
            height_px=1080,
            achieved_fps=10.0,
            occlusion_fraction=0.05,
            lens_clarity=0.9,
            backlit=True,
        )
    )

    assert Issue.ANGLE_TOO_SHALLOW in score.issues
    assert Issue.BACKLIT in score.issues
    assert score.counting_score < COUNTING_THRESHOLD
    assert not score.suitable


def test_each_measured_defect_raises_its_own_issue() -> None:
    score = assess(
        Stream(
            "cam4",
            depression_degrees=10.0,
            height_px=480,
            achieved_fps=2.0,
            occlusion_fraction=0.6,
            lens_clarity=0.4,
            backlit=True,
            ir_glare=True,
        )
    )

    assert set(score.issues) == set(Issue)
    assert score.counting_score < COUNTING_THRESHOLD


def test_a_stream_that_only_drops_frames_is_still_flagged() -> None:
    score = assess(
        Stream(
            "cam5",
            depression_degrees=35.0,
            height_px=1080,
            achieved_fps=3.0,
            occlusion_fraction=0.02,
            lens_clarity=0.95,
        )
    )

    assert score.issues == (Issue.FPS_BELOW_MIN,)


def test_the_record_is_the_json_the_spec_shows() -> None:
    obj = assess(_good()).to_json_obj()

    assert json.loads(json.dumps(obj))["stream"] == "cam1"
    assert obj["issues"] == []
    assert obj["not_suitable_for_counting"] is False


def test_commissioning_refuses_a_low_score_stream_left_unresolved() -> None:
    scores = (assess(_good()), assess(replace(_good("cam2"), depression_degrees=5.0)))

    assert commit(scores, frozenset()) is CommitmentRefusal.UNRESOLVED_LOW_SCORE


def test_an_excluded_stream_leaves_the_commitment_and_the_record() -> None:
    scores = (assess(_good()), assess(replace(_good("cam2"), depression_degrees=5.0)))

    commitment = commit(scores, frozenset({"cam2"}))

    assert isinstance(commitment, AccuracyCommitment)
    assert commitment.covered == ("cam1",)
    assert b"cam2" in commitment.to_bytes()


def test_excluding_a_stream_nobody_assessed_is_refused() -> None:
    scores = (assess(_good()),)

    assert commit(scores, frozenset({"cam9"})) is (CommitmentRefusal.EXCLUDED_STREAM_UNKNOWN)


def test_the_signed_record_changes_when_a_score_changes() -> None:
    first = commit((assess(_good()),), frozenset())
    rescored = commit((assess(replace(_good(), depression_degrees=25.0)),), frozenset())

    assert isinstance(first, AccuracyCommitment)
    assert isinstance(rescored, AccuracyCommitment)
    assert first.sign(KEY) != rescored.sign(KEY)


def test_every_issue_carries_a_remedy_the_engineer_can_act_on() -> None:
    assert set(REMEDY) == set(Issue)
    assert all(REMEDY[issue].strip() for issue in Issue)
