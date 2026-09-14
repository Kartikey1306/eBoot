# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""Every release-shaped CMake configure in the workflows carries a trust
anchor, and the release scans what it built for the development key.

The gate in CMakeLists.txt is what makes a Release board build refuse the
development key. This pins the other half: that release.yml actually passes
EBLDR_PRODUCTION_KEY on every board configure (so an unset secret fails
closed instead of being worked around), never passes EBLDR_ALLOW_DEV_KEY, and
scans every firmware build for the development key's bytes -- and that the
bytes it scans for are the ones core/keystore.c and cmake/ProductionKey.cmake
name.
"""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCAN_STEP = "Refuse an artifact that embeds the development anchor"


def load(name):
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def run_steps(job):
    return [s for s in job.get("steps", []) if isinstance(s.get("run"), str)]


def configure_lines(run):
    """Each `cmake -B` configure in a run block, with its backslash
    continuation lines. A continuation that itself starts another
    `cmake -B` (the esp32 jobs chain two with `||`) is its own configure."""
    lines = run.splitlines()
    blocks, i = [], 0
    while i < len(lines):
        if "cmake -B" in lines[i]:
            block = lines[i]
            while block.rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                block += "\n" + lines[i]
            blocks.append(block)
        i += 1
    out = []
    for block in blocks:
        out.extend(part for part in re.split(r"(?=cmake -B)", block) if "cmake -B" in part)
    return out


def board_of(block):
    m = re.search(r"-DEBLDR_BOARD=(\S+)", block)
    return m.group(1) if m else None


def is_release_shaped(block):
    return "-DCMAKE_BUILD_TYPE=Release" in block or "$BUILD_TYPE" in block


def dev_key_from_keystore():
    src = (REPO_ROOT / "core" / "keystore.c").read_text(encoding="utf-8")
    m = re.search(r"default_dev_key\[EOS_ED25519_PUB_KEY_SIZE\]\s*=\s*\{([^}]*)\}", src)
    assert m, "default_dev_key[] not found in core/keystore.c"
    return "".join(f"{int(x, 16):02x}" for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))


def dev_key_from_cmake():
    src = (REPO_ROOT / "cmake" / "ProductionKey.cmake").read_text(encoding="utf-8")
    m = re.search(r'set\(EBLDR_DEV_KEY_HEX\s*"([0-9a-f]{64})"\)', src)
    assert m, "EBLDR_DEV_KEY_HEX not found in cmake/ProductionKey.cmake"
    return m.group(1)


def test_every_release_board_configure_passes_the_production_key():
    doc = load("release.yml")
    seen = 0
    for job_id, job in doc["jobs"].items():
        for step in run_steps(job):
            for block in configure_lines(step["run"]):
                if board_of(block) in (None, "none"):
                    continue
                seen += 1
                assert "-DEBLDR_PRODUCTION_KEY=" in block, (
                    f"release.yml job {job_id!r}: a board configure without "
                    f"EBLDR_PRODUCTION_KEY would ship the development key:\n{block}")
                assert "secrets.EBLDR_PRODUCTION_KEY_HEX" in block, (
                    f"release.yml job {job_id!r}: the key must come from the "
                    f"EBLDR_PRODUCTION_KEY_HEX secret, not a literal:\n{block}")
                assert "EBLDR_ALLOW_DEV_KEY" not in block, (
                    f"release.yml job {job_id!r} opts into the development key")
    assert seen == 8, f"expected the 8 board configures release.yml had, found {seen}"


def test_every_release_firmware_job_scans_for_the_development_key():
    doc = load("release.yml")
    firmware_jobs = [
        (job_id, job) for job_id, job in doc["jobs"].items()
        if any(board_of(b) not in (None, "none")
               for s in run_steps(job) for b in configure_lines(s["run"]))]
    assert len(firmware_jobs) == 6, [j for j, _ in firmware_jobs]
    for job_id, job in firmware_jobs:
        names = [s.get("name") for s in job["steps"]]
        assert SCAN_STEP in names, f"release.yml job {job_id!r} has no scan step"
        build = next(i for i, s in enumerate(job["steps"])
                     if isinstance(s.get("run"), str) and "cmake --build" in s["run"])
        scan = names.index(SCAN_STEP)
        collect = names.index("Collect artifacts")
        assert build < scan < collect, (
            f"release.yml job {job_id!r}: the scan must run after the build and "
            f"before artifacts are collected")


def test_the_scan_looks_for_the_key_keystore_actually_compiles_in():
    doc = load("release.yml")
    scans = [s["run"] for job in doc["jobs"].values() for s in run_steps(job)
             if s.get("name") == SCAN_STEP]
    assert scans
    keystore = dev_key_from_keystore()
    cmake = dev_key_from_cmake()
    assert keystore == cmake, "core/keystore.c and cmake/ProductionKey.cmake disagree on the development key"
    for run in scans:
        assert keystore in run.replace("\n", "").replace(" ", "").replace('"', ""), (
            "the scan step does not name the development key core/keystore.c compiles in")


def test_no_ci_workflow_cross_compiles_a_release_board_without_saying_so():
    """A Release build of a real board must either carry a key or opt into
    the development key explicitly; otherwise its configure fails, and a CI
    job that hits the gate is a job that stops testing the tree."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or "jobs" not in doc:
            continue
        for job_id, job in doc["jobs"].items():
            if not isinstance(job, dict):
                continue
            for step in run_steps(job):
                for block in configure_lines(step["run"]):
                    if board_of(block) in (None, "none") or not is_release_shaped(block):
                        continue
                    assert ("-DEBLDR_PRODUCTION_KEY=" in block
                            or "-DEBLDR_ALLOW_DEV_KEY=ON" in block), (
                        f"{path.name} job {job_id!r}: a Release build of "
                        f"{board_of(block)} with no key and no opt-out cannot "
                        f"configure:\n{block}")
