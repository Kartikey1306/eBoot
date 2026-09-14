# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""tests/vectors/fw_update_test_sigs.h must be what its generator emits.

tools/gen_fw_update_test_sigs.py signs the header prefixes that
tests/unit/test_fw_update.c build_image() and tests/unit/test_fw_transport.c
build_container() assemble, and the C suites include the committed header.
If the generator changes and the header is not regenerated, the C suites
verify against stale signatures and fail with EOS_ERR_SIGNATURE, and nothing
says why. This pins the committed header to the generator's output, byte for
byte, so line endings count too.
"""

import difflib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "tools"

# A skip is right for a developer without the signing dependency installed and
# wrong for CI, where "collected 19 tests, ran 0" is a green run that checked
# nothing -- the failure .ai/security.md names directly. EOS_REQUIRE_SIGNING_TESTS
# is set in the workflow, so there a missing dependency is a hard error; locally
# the skip still applies.
if os.environ.get("EOS_REQUIRE_SIGNING_TESTS"):
    import cryptography  # noqa: F401  -- ImportError here must fail the job
else:
    pytest.importorskip(
        "cryptography", reason="signing tools require 'cryptography'")

GENERATOR = TOOLS / "gen_fw_update_test_sigs.py"
HEADER = REPO_ROOT / "tests" / "vectors" / "fw_update_test_sigs.h"
REGENERATE = ("python3 tools/gen_fw_update_test_sigs.py "
              "> tests/vectors/fw_update_test_sigs.h")


def test_committed_header_is_the_generator_output():
    result = subprocess.run(
        [sys.executable, str(GENERATOR)],
        cwd=REPO_ROOT, capture_output=True, check=True,
    )
    expected = result.stdout
    actual = HEADER.read_bytes()

    if actual != expected:
        diff = "".join(difflib.unified_diff(
            expected.decode("ascii", "replace").splitlines(keepends=True),
            actual.decode("ascii", "replace").splitlines(keepends=True),
            fromfile="tools/gen_fw_update_test_sigs.py (stdout)",
            tofile="tests/vectors/fw_update_test_sigs.h (committed)",
        ))
        pytest.fail(
            "tests/vectors/fw_update_test_sigs.h differs from what "
            "tools/gen_fw_update_test_sigs.py emits; regenerate it with\n"
            "  " + REGENERATE + "\n" + diff)
