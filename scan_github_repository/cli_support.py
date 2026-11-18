"""両方のCLIで共通のスキャン引数、タイムアウト、JSON出力を扱う。"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from .policy import DEFAULT_DIRECTORY


def positive_seconds(value: str) -> int:
    seconds = int(value)
    if seconds < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return seconds


def nonnegative_depth(value: str) -> int:
    depth = int(value)
    if depth < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return depth


def add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config-dir", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument("--scan-timeout", type=positive_seconds, default=120)
    parser.add_argument("--intel-csv", type=Path, help="Add a trusted local package intelligence CSV.")
    parser.add_argument("--data-dir", type=Path, help="Directory populated by sync-package.")
    parser.add_argument(
        "--max-depth", type=nonnegative_depth,
        help="Maximum directory depth below the scan root (0 scans root files only).",
    )


def run_scan(directory: Path, config_dir: Path, timeout: int, intel_csv: Path | None = None,
             data_dir: Path | None = None, *, max_depth: int | None = None) -> dict:
    command = [
        sys.executable, "-m", "scan_github_repository.scanner",
        str(directory.absolute()), str(config_dir.resolve()),
    ]
    if intel_csv is not None:
        command.extend(["--intel-csv", str(intel_csv.resolve())])
    if max_depth is not None:
        command.extend(["--max-depth", str(max_depth)])
    # 子プロセスは作業ディレクトリが異なるため、相対パスは呼び出し側で解決する。
    from .intelligence import default_data_directory
    command.extend(["--data-dir", str((data_dir or default_data_directory()).resolve())])
    process = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parent.parent,
        check=True,
        timeout=timeout,
        text=True,
        encoding="utf-8",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return json.loads(process.stdout)


def evaluate_scan(report: dict) -> int:
    if report["incomplete"]:
        report.setdefault("reason", "scan_incomplete")
        return 2
    if report["blocked"]:
        report["status"] = "findings"
        return 1
    return 0


def print_report(report: dict, started: float) -> None:
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    print(json.dumps(report, ensure_ascii=True))


def record_error(report: dict, error: Exception) -> None:
    if isinstance(error, subprocess.TimeoutExpired):
        report["reason"] = "timeout"
    elif isinstance(error, subprocess.CalledProcessError):
        report.update(reason="command_failed", command_exit_code=error.returncode)
    elif isinstance(error, FileExistsError):
        report["reason"] = "destination_exists"
    else:
        report["reason"] = type(error).__name__

