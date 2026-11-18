"""リポジトリを取得し、検査ポリシーを通過した成果物を配置する。"""

import argparse
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from .cli_support import (
    add_scan_options,
    evaluate_scan,
    positive_seconds,
    print_report,
    record_error,
    run_scan,
)
from .intelligence import DATABASE_NAME, default_data_directory


def git_environment() -> dict[str, str]:
    # ユーザーやシステムの Git 設定による取得時の処理を抑止する。
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_ALLOW_PROTOCOL="https:ssh:file",
    )
    return env


def run_git(args: list[str], timeout: int) -> str:
    command = ["git", *args]
    with subprocess.Popen(
        command,
        env=git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        start_new_session=os.name == "posix",
    ) as process:
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Linuxでは ssh や upload-pack などの子プロセスも停止する。
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait()
            raise
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
        return output.strip()


def publish(source: Path, destination: Path) -> None:
    if os.name == "nt":
        source.rename(destination)
        return
    if not sys.platform.startswith("linux"):
        raise OSError("atomic publication requires Linux or Windows")

    # 検査中に別プロセスが配置先を作っていても、上書きしない。
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    if rename(at_fdcwd, os.fsencode(source), at_fdcwd, os.fsencode(destination), rename_noreplace):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def clone_and_scan(args: argparse.Namespace, report: dict) -> int:
    destination = args.destination.absolute()
    if os.path.lexists(destination):
        raise FileExistsError("destination already exists")
    database = (args.data_dir or default_data_directory()) / DATABASE_NAME
    if not database.exists():
        report.update(reason="missing_intelligence", incomplete=True,
                      detail=f"{database}: run sync-package before the first scan")
        return 2

    # 配置先と同じファイルシステムの一時領域に取得する。
    with tempfile.TemporaryDirectory(prefix=".scan-github-repository-", dir=destination.parent) as temporary:
        checkout = Path(temporary) / "repository"
        empty = Path(temporary) / "empty"
        empty.mkdir()
        report["stage"] = "clone"
        run_git(
            ["-c", f"core.hooksPath={empty}", "clone", "--no-local",
             f"--template={empty}", "--", args.repository, str(checkout)],
            args.clone_timeout,
        )
        report["commit"] = run_git(
            ["-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"], 15,
        )

        # Windowsでリンクが通常ファイルに展開される場合も、Gitのモードで確認する。
        index = run_git(
            ["-C", str(checkout), "-c", "core.quotePath=true", "ls-files", "--stage"], 15,
        )
        unsupported = {"symlinks": 0, "submodules": 0}
        for entry in index.splitlines():
            mode = entry.partition(" ")[0]
            if mode == "120000":
                unsupported["symlinks"] += 1
            elif mode == "160000":
                unsupported["submodules"] += 1
        if any(unsupported.values()):
            report.update(reason="unsupported_git_entries", unsupported=unsupported, incomplete=True)
            return 2

        report["stage"] = "scan"
        report.update(run_scan(
            checkout, args.config_dir, args.scan_timeout, args.intel_csv,
            args.data_dir, max_depth=args.max_depth,
        ))
        exit_code = evaluate_scan(report)
        if exit_code != 0:
            return exit_code

        report["stage"] = "publish"
        publish(checkout, destination)
        report.update(status="passed", stage="complete")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Clone, scan and publish a Git repository.")
    parser.add_argument("repository")
    parser.add_argument("destination", type=Path)
    parser.add_argument("--clone-timeout", type=positive_seconds, default=300)
    add_scan_options(parser)
    args = parser.parse_args()

    started = time.monotonic()
    report = {"status": "error", "stage": "prepare"}
    try:
        exit_code = clone_and_scan(args, report)
    except (subprocess.SubprocessError, OSError, ValueError, AttributeError) as error:
        record_error(report, error)
        exit_code = 2
    print_report(report, started)
    return exit_code

