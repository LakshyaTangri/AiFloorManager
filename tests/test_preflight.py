"""F01 acceptance criteria, one test per criterion, plus the structural refusals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from t1.canon import PREFLIGHT_BUDGET_S, Profile, TrustLevel
from t1.platform.probe import BootMode, HostObservation, SiteObservation, probe_host
from t1.platform.qualification import (
    ADVISORY,
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
        "usb3_present": True,
        "accelerator_present": True,
        "t1_media_mb": 128_000,
        "boot_mode": BootMode.UEFI,
        "virtualised": False,
        "sleep_enabled": False,
        "internal_os_last_boot_days": 400.0,
    }
    base.update(overrides)
    return HostObservation(**base)  # type: ignore[arg-type]


def test_sleep_enabled_is_a_named_hard_fail() -> None:
    profile = qualify_host(host(sleep_enabled=True))
    assert profile.result is Result.FAIL
    remedy = next(r for r in profile.remedies if r.finding is Finding.SLEEP_ENABLED)
    assert remedy.hard and "BIOS" in remedy.remedy


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


def test_site_qualification_names_no_host_property_and_cannot_refuse_a_pc() -> None:
    profile = qualify_site(
        SiteObservation(
            power_stable=True,
            network_reachable=True,
            cameras_reachable=("cam-1",),
            cameras_unreachable=(),
            mounting_suitable=True,
        ),
        profile=Profile.L2,
    )
    assert profile.result is Result.PASS
    body = json.dumps(profile.to_dict())
    for token in ("host_not_dedicated", "usable_ram_mb", "adapter_cap", "avx2", "boot_mode"):
        assert token not in body


def test_site_qualification_refuses_the_l1_profile() -> None:
    observation = SiteObservation(True, True, (), (), True)
    with pytest.raises(ValueError, match="site_qualification_not_applicable_to_l1"):
        qualify_site(observation, profile=Profile.L1)


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


def _fixture_sysroot(root: Path, *, usb_speed: str, ram_kb: int) -> Path:
    (root / "proc").mkdir(parents=True)
    (root / "proc/cpuinfo").write_text("processor\t: 0\nflags\t\t: fpu avx2\nprocessor\t: 1\n")
    (root / "proc/meminfo").write_text(f"MemTotal:  8000000 kB\nMemAvailable: {ram_kb} kB\n")
    (root / "sys/class/net/eth0").mkdir(parents=True)
    (root / "sys/class/drm/card0").mkdir(parents=True)
    (root / "sys/firmware/efi").mkdir(parents=True)
    (root / "sys/bus/usb/devices/usb1").mkdir(parents=True)
    (root / "sys/bus/usb/devices/usb1/speed").write_text(usb_speed)
    (root / "sys/class/dmi/id").mkdir(parents=True)
    (root / "sys/class/dmi/id/product_name").write_text("OptiPlex 3080\n")
    (root / "sys/power").mkdir(parents=True)
    (root / "sys/power/state").write_text("freeze mem disk\n")
    return root


def test_probe_reads_a_sysroot_without_writing_to_it(tmp_path: Path) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000)
    before = {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()}

    observation = probe_host(root, t1_media_mb=128_000, internal_os_last_boot_days=400.0)

    assert {p: p.stat().st_mtime_ns for p in root.rglob("*") if p.is_file()} == before
    assert observation.avx2 and observation.cores == 2
    assert observation.usable_ram_mb == 3535
    assert observation.nic_present and observation.usb3_present
    assert observation.accelerator_present and observation.boot_mode is BootMode.UEFI
    assert observation.sleep_enabled and not observation.virtualised


def test_probe_reports_usb2_only_and_missing_hardware(tmp_path: Path) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="480", ram_kb=1_000_000)
    observation = probe_host(root, t1_media_mb=128_000, internal_os_last_boot_days=400.0)
    assert not observation.usb3_present
    profile = qualify_host(observation)
    assert profile.result is Result.FAIL
    assert {Finding.USB3_MISSING, Finding.RAM_INSUFFICIENT} <= set(profile.findings)


def test_cli_exits_non_zero_on_refusal_and_prints_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _fixture_sysroot(tmp_path / "sysroot", usb_speed="5000", ram_kb=3_620_000)
    code = preflight.main(["--json", "--sysroot", str(root), "--t1-media-mb", "128000"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["result"] == "FAIL"
    assert "host_dedication_unverified" in payload["findings"]
    assert payload["signature"]


def test_cli_site_mode_passes_a_clean_site(capsys: pytest.CaptureFixture[str]) -> None:
    code = preflight.main(
        [
            "--profile",
            Profile.L2.value,
            "--json",
            "--power-stable",
            "--network-reachable",
            "--mounting-suitable",
            "--camera-reachable",
            "cam-1",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["result"] == "PASS"
    assert payload["cameras_reachable"] == ["cam-1"]
