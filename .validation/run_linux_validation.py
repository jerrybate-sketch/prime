"""Run bounded, credential-free baseline/patch validation on an ephemeral Linux runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

BASE_COMMIT = "8ea64a7e97f10bb13001a9a785d1b236da4d881a"
# Git/Linux LF bytes; the historical Windows lock records CRLF bytes instead.
EXPECTED_SOURCE = "a6356d0b16adb03300c145eccc05dc557fb813e53928cd199393578b0f6a40ae"
UPSTREAM_310_CASES = [
    "test_batch_status.py::test_async_cancellation_before_dispatch_removes_lookup",
    "test_batch_status.py::test_async_close_joins_fetch_before_transports_even_when_cancelled",
    "test_checkpoints.py::test_checkpoint_batch_close_cancels_inflight_fetch",
]
HERE = Path(__file__).resolve().parent
PARSER = argparse.ArgumentParser()
PARSER.add_argument("--repo", type=Path, default=Path.cwd())
PARSER.add_argument("--output", type=Path, required=True)
ARGS = PARSER.parse_args()
REPO = ARGS.repo.resolve()
OUTPUT = ARGS.output.resolve()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    command: list[str],
    name: str,
    *,
    cwd: Path = REPO,
    expected: int = 0,
    timeout: int = 180,
    env: dict[str, str] | None = None,
) -> str:
    started = time.monotonic()
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )
    text = result.stdout + result.stderr
    (OUTPUT / f"{name}.txt").write_text(text, encoding="utf-8")
    print(f"{name}: exit={result.returncode}; seconds={time.monotonic() - started:.2f}", flush=True)
    if result.returncode != expected:
        print(text[-16000:], flush=True)
        raise AssertionError(f"{name}: expected exit {expected}, got {result.returncode}")
    return text


def pytest_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    return {
        key: sum(int(suite.attrib.get(key, 0)) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }


def compatibility_failures(path: Path) -> dict[str, str]:
    failures = {}
    for case in ET.parse(path).findall(".//testcase"):
        failure = case.find("failure")
        if failure is not None:
            failures[case.attrib["name"]] = failure.attrib.get("message", "")
    assert set(failures) == {case.split("::")[1] for case in UPSTREAM_310_CASES}, failures
    assert all(
        "AttributeError" in message and "has no attribute 'cancelling'" in message
        for message in failures.values()
    ), failures
    return failures


def main() -> None:
    if platform.system() != "Linux" or not Path("/proc/self/cmdline").is_file():
        raise SystemExit("A Linux runner with procfs is required")
    # Refuse any accidentally supplied provider credentials or live-test opt-in.
    forbidden = [
        name for name in ("PRIME_API_KEY", "PRIME_TEAM_ID", "PRIME_CONTEXT") if os.environ.get(name)
    ]
    if forbidden or os.environ.get("PRIME_LIVE_VM_SMOKE") == "1":
        raise SystemExit("Prime credentials/live-test flags must not be supplied")
    if (Path.home() / ".prime" / "config.json").exists():
        raise SystemExit("Use a fresh runner without a Prime account configuration")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    source = REPO / "packages/prime-sandboxes/src/prime_sandboxes/sandbox.py"
    if sha(source) != EXPECTED_SOURCE:
        raise SystemExit("Implementation hash differs from the reviewed patch")
    report = {
        "state": "running",
        "platform": platform.platform(),
        "python": sys.version,
        "kernel": platform.release(),
        "base_commit": BASE_COMMIT,
        "patched_source_sha256": sha(source),
        "linux_acceptance_sha256": sha(HERE / "linux_acceptance.py"),
        "validation_runner_sha256": sha(Path(__file__)),
        "provider_calls": False,
        "credentials_supplied": False,
        "limitations": [
            "Platform batch response is simulated from real exit files",
            "No Prime gateway, provider VM, billing, or production throughput test",
        ],
    }
    try:
        report["patched_commit"] = run(["git", "rev-parse", "HEAD"], "commit").strip()
        run([sys.executable, "-m", "pip", "freeze"], "dependencies")
        # Isolated, disposable public source checkout. Never reset the patched tree.
        baseline = Path(tempfile.mkdtemp(prefix="prime-batch-baseline-")) / "repo"
        run(["git", "worktree", "add", "--detach", str(baseline), BASE_COMMIT], "baseline_checkout")
        baseline_source = baseline / "packages/prime-sandboxes/src"
        report["baseline_source_sha256"] = sha(baseline_source / "prime_sandboxes/sandbox.py")
        test_relative = Path("packages/prime-sandboxes/tests/test_batch_liveness.py")
        shutil.copy2(REPO / test_relative, baseline / test_relative)
        baseline_env = dict(
            os.environ,
            PYTHONPATH=str(baseline_source),
            PRIME_LIVE_VM_SMOKE="0",
            PYTHONDONTWRITEBYTECODE="1",
        )
        run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(test_relative),
                "-q",
                "-p",
                "no:cacheprovider",
                "-k",
                "lost_job_is_terminal or live_and_lost_jobs_are_isolated",
                f"--junitxml={OUTPUT / 'BEFORE.xml'}",
            ],
            "BEFORE",
            cwd=baseline,
            expected=1,
            env=baseline_env,
        )
        before = pytest_counts(OUTPUT / "BEFORE.xml")
        assert before == {"tests": 5, "failures": 5, "errors": 0, "skipped": 0}, before
        failures = ET.parse(OUTPUT / "BEFORE.xml").findall(".//testcase/failure")
        assert sum("DID NOT RAISE" in item.attrib.get("message", "") for item in failures) == 4
        assert any("isinstance" in item.attrib.get("message", "") for item in failures)
        report["before"] = before

        if sys.version_info[:2] == (3, 10):
            run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    *("packages/prime-sandboxes/tests/" + case for case in UPSTREAM_310_CASES),
                    f"--junitxml={OUTPUT / 'BASELINE_COMPATIBILITY.xml'}",
                ],
                "BASELINE_COMPATIBILITY",
                cwd=baseline,
                expected=1,
                timeout=120,
                env=baseline_env,
            )
            compatibility = pytest_counts(OUTPUT / "BASELINE_COMPATIBILITY.xml")
            assert compatibility == {"tests": 3, "failures": 3, "errors": 0, "skipped": 0}
            report["baseline_python310_failures"] = compatibility_failures(
                OUTPUT / "BASELINE_COMPATIBILITY.xml"
            )

        for expectation, sdk_source in (
            ("baseline", baseline_source),
            ("fixed", REPO / "packages/prime-sandboxes/src"),
        ):
            destination = OUTPUT / f"SHELL_{expectation.upper()}.json"
            run(
                [
                    sys.executable,
                    str(HERE / "linux_acceptance.py"),
                    "--sdk-source",
                    str(sdk_source),
                    "--output",
                    str(destination),
                    "--expect",
                    expectation,
                ],
                f"SHELL_{expectation.upper()}",
                timeout=45,
            )
            report[f"shell_{expectation}"] = json.loads(destination.read_text(encoding="utf-8"))

        fixed_env = dict(
            os.environ,
            PYTHONPATH=str(REPO / "packages/prime-sandboxes/src"),
            PRIME_LIVE_VM_SMOKE="0",
            PYTHONDONTWRITEBYTECODE="1",
        )
        run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(test_relative),
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={OUTPUT / 'LIVENESS.xml'}",
            ],
            "LIVENESS",
            timeout=120,
            env=fixed_env,
        )
        liveness = pytest_counts(OUTPUT / "LIVENESS.xml")
        assert liveness == {"tests": 25, "failures": 0, "errors": 0, "skipped": 0}, liveness
        report["liveness"] = liveness
        run(
            [
                sys.executable,
                "-m",
                "pytest",
                "packages/prime-sandboxes/tests",
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={OUTPUT / 'SDK_SUITE.xml'}",
            ],
            "SDK_SUITE",
            timeout=240,
            env=fixed_env,
            expected=1 if sys.version_info[:2] == (3, 10) else 0,
        )
        after = pytest_counts(OUTPUT / "SDK_SUITE.xml")
        assert after["tests"] >= 393 and after["errors"] == 0, after
        if sys.version_info[:2] == (3, 10):
            assert after["failures"] == 3 and after["tests"] - after["skipped"] - 3 >= 347, after
            report["patched_python310_failures"] = compatibility_failures(OUTPUT / "SDK_SUITE.xml")
            assert report["patched_python310_failures"] == report["baseline_python310_failures"]
        else:
            assert after["failures"] == 0 and after["tests"] - after["skipped"] >= 350, after
        report["after"] = after
        run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--isolated",
                "--select",
                "E,F,I",
                "--line-length",
                "100",
                "--target-version",
                "py310",
                "packages/prime-sandboxes/src/prime_sandboxes/sandbox.py",
                "packages/prime-sandboxes/tests/test_batch_status.py",
                str(test_relative),
            ],
            "LINT",
        )
        run(["git", "diff", "--check", BASE_COMMIT, "--", "packages/prime-sandboxes"], "DIFF_CHECK")
        report["state"] = (
            "known_upstream_python310_failures" if sys.version_info[:2] == (3, 10) else "passed"
        )
    except BaseException as exc:
        report["state"] = "failed"
        report["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        (OUTPUT / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            summary = f"### Python {platform.python_version()}: {report['state']}\n\n"
            if report["state"] == "known_upstream_python310_failures":
                summary += (
                    "The full SDK suite does **not** pass Python 3.10: three existing "
                    "Task.cancelling() failures reproduce unchanged on pinned upstream. "
                    "All 25 new liveness cases and Linux shell acceptance pass.\n\n"
                )
            summary += "```json\n" + json.dumps(report.get("after", {}), indent=2) + "\n```\n"
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
                stream.write(summary)
        print(json.dumps({k: v for k, v in report.items() if not k.startswith("shell_")}, indent=2))


if __name__ == "__main__":
    main()
