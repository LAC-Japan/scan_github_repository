"""既存ディレクトリを検査する scan-directory のエントリーポイント。"""

import argparse
from pathlib import Path
import subprocess
import time

from .cli_support import add_scan_options, evaluate_scan, print_report, record_error, run_scan


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan an existing directory.")
    parser.add_argument("directory", type=Path)
    add_scan_options(parser)
    args = parser.parse_args()

    started = time.monotonic()
    report = {"status": "error", "stage": "scan"}
    exit_code = 2
    try:
        if not args.directory.is_dir():
            raise NotADirectoryError(args.directory)
        report.update(run_scan(
            args.directory, args.config_dir, args.scan_timeout, args.intel_csv,
            args.data_dir, max_depth=args.max_depth,
        ))
        exit_code = evaluate_scan(report)
        if exit_code == 0:
            report.update(status="passed", stage="complete")
    except (subprocess.SubprocessError, OSError, ValueError) as error:
        record_error(report, error)
    print_report(report, started)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

