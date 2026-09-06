"""F01 acceptance criteria, one test per criterion, plus the structural refusals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from t1.canon import PREFLIGHT_BUDGET_S, Profile, TrustLevel
from t1.platform.probe import (
    BootMode,
    HostObservation,
    SiteObservation,
    SleepPolicy,
    probe_host,
)
from t1.platform.qualification import (
    ADVISORY,
    MIN_T1_MEDIA_MB,
    REMEDIES,
    Finding,
    Result,
    qualify_host,
    qualify_site,
)
from t1.tools import preflight

KEY = b"test-key"


def host(**overrides: object) -> HostObservation:
    base: dict[str, object] = {
        "arch": "x86_64",
        "avx2": True,
        "cores": 4,
        "usable_ram_mb": 3500,
        "nic_present": True,
        "usb3_port_present": True,
        "accelerator_present": True,
        "t1_media_mb": 256_000,
        "boot_mode": BootMode.UEFI,
        "virtualised": False,
        "virtualisation_enabled": True,
        "sleep_policy": SleepPolicy.DISABLED,
        "t1_media_link_mbps": 5000.0,
        "internal_os_last_boot_days": 400.0,
    }
    base.update(overrides)
    return HostObservation(**base)  # type: ignore[arg-type]


def site(**overrides: object) -> SiteObservation:
    base: dict[str, object] = {
        "power_stable": True,
        "network_reachable": True,
        "cameras_expected": ("cam-1",),
        "cameras_reachable": ("cam-1",),
        "mounting_suitable": True,
    }
    base.update(overrides)
    return SiteObservation(**base)  # type: ignore[arg-type]


def test_sleep_enabled_is_a_named_hard_fail() -> None:
    profile = qualify_host(host(sleep_policy=SleepPolicy.ENABLED))
    assert profile.result is Result.FAIL
    remedy = next(r for r in profile.remedies if r.finding is Finding.SLEEP_ENABLED)
    assert remedy.hard and "BIOS" in remedy.remedy


def test_unverified_sleep_policy_is_refused_rather_than_read_as_disabled() -> None:
    profile = qualify_host(host(sleep_policy=SleepPolicy.UNVERIFIED))
    assert profile.result is Result.FAIL
    assert Finding.SLEEP_POLICY_UNVERIFIED in profile.findings
    assert Finding.SLEEP_ENABLED not in profile.findings


def test_qualified_host_emits_a_signed_profile_with_derived_caps() -> None:
    profile = qualify_host(host(usable_ram_mb=3532), elapsed_s=12.0)
    assert profile.result is Result.PASS
    assert (profile.adapter_cap, profile.stream_cap) == (3, 2)
    assert profile.trust_level is TrustLevel.SOFTWARE_BOUND
    assert profile.elapsed_s < PREFLIGHT_BUDGET_S
    assert profile.sign(KEY) == profile.sign(KEY)
    assert profile.sign(KEY) != profile.sign(b"other-key")


def test_two_adapter_host_passes_with_an_advisory_rather_than_failing_the_install() -> None:
    profile = qualify_host(host(usable_ram_mb=3380))
    assert profile.result is Result.PASS
    assert profile.adapter_cap == 2
    advisory = next(r for r in profile.remedies if r.finding is Finding.ADD_RAM_FOR_THIRD_ADAPTER)
    assert not advisory.hard


def test_ram_below_the_canon_floor_is_refused_and_carries_no_capability() -> None:
    profile = qualify_host(host(usable_ram_mb=3000))
    assert profile.result is Result.FAIL
    assert Finding.RAM_INSUFFICIENT in profile.findings
    assert profile.adapter_cap == 0
    assert profile.capability() is None


def test_spec_minimum_cores_and_media_capacity_are_enforced() -> None:
    profile = qualify_host(host(cores=2, t1_media_mb=MIN_T1_MEDIA_MB - 1))
    assert profile.result is Result.FAIL
    assert {Finding.CORES_INSUFFICIENT, Finding.T1_MEDIA_TOO_SMALL} <= set(profile.findings)


def test_disabled_cpu_virtualisation_is_a_named_hard_fail() -> None:
    profile = qualify_host(host(virtualisation_enabled=False))
    assert profile.result is Result.FAIL
    assert Finding.VIRTUALISATION_DISABLED in profile.findings


def test_t1_media_on_a_usb2_link_is_refused_even_when_the_pc_has_a_usb3_port() -> None:
    profile = qualify_host(host(usb3_port_present=True, t1_media_link_mbps=480.0))
    assert profile.result is Result.FAIL
    assert Finding.T1_MEDIA_LINK_DEGRADED in profile.findings


def test_unmeasured_t1_media_link_is_refused() -> None:
    profile = qualify_host(host(t1_media_link_mbps=None))
    assert profile.result is Result.FAIL
    assert Finding.T1_MEDIA_LINK_UNVERIFIED in profile.findings


def test_site_qualification_names_no_host_property_and_cannot_refuse_a_pc() -> None:
    profile = qualify_site(site(), profile=Profile.L2)
    assert profile.result is Result.PASS
    body = json.dumps(profile.to_dict())
    for token in ("host_not_dedicated", "usable_ram_mb", "adapter_cap", "avx2", "boot_mode"):
        assert token not in body


def test_site_without_a_surveyed_camera_inventory_cannot_pass() -> None:
    profile = qualify_site(site(cameras_expected=(), cameras_reachable=()), profile=Profile.L2)
    assert profile.result is Result.FAIL
    assert Finding.SITE_CAMERAS_UNVERIFIED in profile.findings


def test_expected_camera_that_did_not_answer_is_reported_unreachable() -> None:
    observation = site(cameras_expected=("cam-1", "cam-2"), cameras_reachable=("cam-1",))
    assert observation.cameras_unreachable == ("cam-2",)
    profile = qualify_site(observation, profile=Profile.L3)
    assert profile.result is Result.FAIL
    assert Finding.SITE_CAMERA_UNREACHABLE in profile.findings


def test_site_qualification_refuses_the_l1_profile() -> None:
    with pytest.raises(ValueError, match="site_qualification_not_applicable_to_l1"):
        qualify_site(site(), profile=Profile.L1)


def test_recently_booted_internal_os_is_a_hard_fail() -> None:
    profile = qualify_host(host(internal_os_last_boot_days=2.0))
    assert profile.result is Result.FAIL
    assert Finding.HOST_NOT_DEDICATED in profile.findings


def test_unmeasured_dedication_is_refused_rather_than_assumed() -> None:
    profile = qualify_host(host(internal_os_last_boot_days=None))
    assert profile.result is Result.FAIL
    assert Finding.HOST_DEDICATION_UNVERIFIED in profile.findings


def test_exceeding_the_five_minute_budget_is_itself_a_finding() -> None:
    profile = qualify_host(host(), elapsed_s=PREFLIGHT_BUDGET_S + 1)
    assert profile.result is Result.FAIL
    assert Finding.PREFLIGHT_TIMEOUT in profile.findings


def test_every_finding_has_a_remedy() -> None:
    assert set(REMEDIES) == set(Finding)
    assert all(REMEDIES[f].strip() for f in Finding)
    assert set(Finding) >= ADVISORY


def _fixture_sysroot(
    root: Path, *, usb_speed: str, ram_kb: int, sleep_states: str = "freeze mem disk\n"
) -> Path:
    (root / "proc").mkdir(parents=True)
    (root / "proc/cpuinfo").write_text("processor\t: 0\nflags\t\t: fpu avx2 vmx\nprocessor\t: 1\n")
    (root / "proc/meminfo").write_text(f"MemTotal:  8000000 kB\nMemAvailable: {ram_kb} kB\n")
    (root / "sys/class/net/eth0").mkdir(parents=True)
    (root / "sys/class/drm/card0").mkdir(parents=True)
    (root / "sys/firmware/efi").mkdir(parents=True)
    (root / "sys/bus/usb/devices/usb1").mkdir(parents=True)
    (root / "sys/bus/usb/devices/usb1/speed").write_text(usb_speed)
    (root / "sys/class/dmi/id").mkdir(parents=True)
    (root / "sys/class/dmi/id/product_name").write_text("OptiPlex 3080\n")
    (root / "sys/power").mkdir(parents=True)
    (root / "sys/power/state").write_text(sleep_states)
    (root / "etc/systemd/system").mkdir(parents=True)
    return root


def _mask_sleep_units(root: Path) -> None:
    for unit in ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target"):
        (root / "etc/systemd/system" / unit).symlink_to("/dev/null")


def test_probe_reads_a_sysroot_without_writing_to_it(tmp_path: Path) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000)
    before = {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}

    observation = probe_host(root, t1_media_mb=256_000, internal_os_last_boot_days=400.0)

    assert {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()} == before
    assert observation.avx2 and observation.cores == 2
    assert observation.usable_ram_mb == 3535
    assert observation.nic_present and observation.usb3_port_present
    assert observation.accelerator_present and observation.boot_mode is BootMode.UEFI
    assert observation.virtualisation_enabled and not observation.virtualised


def test_supported_sleep_states_alone_are_unverified_not_enabled(tmp_path: Path) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000)
    assert probe_host(root, t1_media_mb=256_000).sleep_policy is SleepPolicy.UNVERIFIED

    _mask_sleep_units(root)
    assert probe_host(root, t1_media_mb=256_000).sleep_policy is SleepPolicy.DISABLED


def test_kernel_offering_no_sleep_state_is_disabled(tmp_path: Path) -> None:
    root = _fixture_sysroot(
        tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000, sleep_states="freeze\n"
    )
    assert probe_host(root, t1_media_mb=256_000).sleep_policy is SleepPolicy.DISABLED


def test_probe_reports_usb2_only_and_missing_hardware(tmp_path: Path) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="480", ram_kb=1_000_000)
    observation = probe_host(root, t1_media_mb=256_000, internal_os_last_boot_days=400.0)
    assert not observation.usb3_port_present
    profile = qualify_host(observation)
    assert profile.result is Result.FAIL
    assert {Finding.USB3_MISSING, Finding.RAM_INSUFFICIENT} <= set(profile.findings)


def test_cli_exits_non_zero_on_refusal_and_leaves_the_profile_unsigned_without_a_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000)
    code = preflight.main(["--json", "--sysroot", str(root), "--t1-media-mb", "256000"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["result"] == "FAIL"
    assert "host_dedication_unverified" in payload["findings"]
    assert payload["signature"] is None


def test_cli_signs_with_the_operator_supplied_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000)
    key_file = tmp_path / "preflight.key"
    key_file.write_bytes(b"an-operator-key")

    preflight.main(
        ["--json", "--sysroot", str(root), "--t1-media-mb", "256000", "--key-file", str(key_file)]
    )
    payload = json.loads(capsys.readouterr().out)

    observation = probe_host(root, t1_media_mb=256_000)
    expected = qualify_host(observation, elapsed_s=payload["elapsed_s"]).sign(b"an-operator-key")
    assert payload["signature"] == expected


def test_cli_requires_the_media_capacity_rather_than_defaulting_to_a_refusal() -> None:
    with pytest.raises(SystemExit) as exit_info:
        preflight.main(["--json"])
    assert exit_info.value.code == 2


def test_cli_site_mode_passes_a_clean_site(capsys: pytest.CaptureFixture[str]) -> None:
    code = preflight.main(
        [
            "--profile",
            Profile.L2.value,
            "--json",
            "--power-stable",
            "--network-reachable",
            "--mounting-suitable",
            "--camera",
            "cam-1",
            "--camera-reachable",
            "cam-1",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["result"] == "PASS"
    assert payload["cameras_reachable"] == ["cam-1"]
