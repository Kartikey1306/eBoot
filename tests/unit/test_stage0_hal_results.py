# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""Every HAL read in stage-0 checks its result.

stage0/jump_stage1.c hashed stage-1 with a loop that discarded the return
value of eos_hal_flash_read(): a read that failed left the buffer holding
the previous chunk, or whatever the stack held, and that was hashed as if
it were stage-1. The mismatch that followed sent the device to recovery
with the wrong reason (0xBAD1, "hash mismatch") -- and only by luck; the
loop in core/crypto_boot.c that does the same job refuses a failed read.

stage0/ is only compiled by a cross build, so this is a source-level guard
in the style of test_stage0_reset_entry.py: every call to a HAL read or
write function in stage0/*.c must have its result examined -- assigned, or
tested in the same statement.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGE0 = sorted((REPO_ROOT / "stage0").glob("*.c"))

# HAL calls whose failure means the bytes are not what they claim to be.
CHECKED_CALLS = ("eos_hal_flash_read", "eos_hal_flash_write", "eos_hal_flash_erase",
                 "eos_hal_otp_read", "eos_hal_otp_write", "eos_hal_monotonic_read")


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def _statements_calling(text, name):
    """Each statement (up to its ';') that contains a call to *name*."""
    out = []
    for m in re.finditer(re.escape(name) + r"\s*\(", text):
        start = max(text.rfind(";", 0, m.start()), text.rfind("{", 0, m.start()))
        end = text.find(";", m.end())
        out.append(text[start + 1:end].strip())
    return out


def _result_is_examined(statement, name):
    """True when the call's value is assigned or tested, not discarded."""
    head = statement[:statement.index(name)]
    return "=" in head or "if" in head or "return" in head or "while" in head


def test_stage0_files_exist():
    assert STAGE0, "no stage0/*.c found"
    assert any(p.name == "jump_stage1.c" for p in STAGE0)


def test_every_hal_read_and_write_in_stage0_examines_its_result():
    discarded = []
    for path in STAGE0:
        text = _strip_comments(path.read_text(encoding="utf-8"))
        for name in CHECKED_CALLS:
            for stmt in _statements_calling(text, name):
                if not _result_is_examined(stmt, name):
                    discarded.append(f"{path.name}: {stmt}")
    assert not discarded, (
        "these stage-0 statements discard a HAL result, so a failed read or "
        "write is treated as data:\n  " + "\n  ".join(discarded))


def test_the_stage1_hash_loop_refuses_a_failed_read():
    """The specific regression: a failed read in the stage-1 hash loop must
    leave the loop for recovery, with a reason distinct from a bad hash."""
    text = _strip_comments((REPO_ROOT / "stage0" / "jump_stage1.c").read_text(encoding="utf-8"))
    loop = text[text.index("while (off < stage1_expected_size)"):]
    loop = loop[:loop.index("eos_sha256_final")]
    assert re.search(r"if\s*\(\s*eos_hal_flash_read\([^;]*\)\s*!=\s*EOS_OK\s*\)", loop), \
        "the stage-1 hash loop does not test eos_hal_flash_read()'s result"
    assert "eos_recovery_enter" in loop, "a failed read must enter recovery"
    assert "0xBAD2" in loop, "a failed read must be logged with its own reason, not the hash-mismatch one"
    assert "return;" in loop, "after recovery the loop must not fall through to the jump"
