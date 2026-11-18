"""取得済みディレクトリを静的検査し、設定に従って結果を分類する。"""

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from .cli_support import nonnegative_depth
from .intelligence import IntelligenceError, MissingIntelligence, load_intelligence
from .policy import DEFAULT_DIRECTORY, PolicyError, SEVERITIES, load_policy
from .source_checks import ProjectScanner
from .vendor import scanner_config as config


VENDOR = Path(__file__).with_name("vendor")


def scan(root: Path, config_directory: Path = DEFAULT_DIRECTORY, intel_csv: Path | None = None,
         data_dir: Path | None = None, *, max_depth: int | None = None) -> dict:
    """ファイルを実行せず、検出箇所と設定適用後の判定を返す。"""
    policy = load_policy(config_directory)
    intel, intel_digest = load_intelligence(intel_csv, data_dir)

    scanner = ProjectScanner(
        root=root,
        intel=intel,
        max_file_size=config.MAX_FILE_SIZE,
        max_files_per_repository=0,
        scan_archives=False,
        max_archive_members=0,
        max_archive_total_size=0,
        privacy_mail_as_suspicious=False,
        repository_mode="root",
        max_depth=max_depth,
    )
    if not scanner.root.is_dir():
        raise NotADirectoryError(scanner.root)
    result = scanner.scan_repository(scanner.root, {scanner.root})

    # 検出エンジンの既定重要度を、設定ファイルで選んだ重要度へ置き換える。
    findings = []
    for item in result.findings:
        rule = policy.rules.get(item.category)
        if rule is None:
            raise PolicyError(f"unassigned rule: {item.category}")
        if rule.enabled:
            finding = {
                "severity": rule.severity,
                "category": item.category,
                "file": item.file,
                "line": item.line_number,
                "blocking": rule.block,
            }
            if item.category in config.KNOWN_BAD_PACKAGE_CATEGORIES or item.category == "possible_compromised_package_version":
                finding["dependency"] = item.value
            findings.append(finding)
    severities = {item["severity"] for item in findings}
    verdict = next(
        (severity for severity in reversed(SEVERITIES) if severity in severities),
        config.VERDICT_NO_FINDINGS,
    )

    # ポリシーの変更も、レポートのハッシュに反映する。
    digest = hashlib.sha256(bytes.fromhex(policy.digest))
    digest.update(intel_digest)
    for path in (Path(__file__), Path(__file__).with_name("policy.py"),
                 Path(__file__).with_name("intelligence.py"),
                 Path(__file__).with_name("source_checks.py"),
                 VENDOR / "repository_scanner.py", VENDOR / "scanner_config.py"):
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    stats = result.stats
    incomplete = any((
        stats.files_skipped_error, stats.files_skipped_size, stats.files_skipped_limit,
        stats.files_skipped_unreadable_text, stats.files_skipped_link,
        stats.files_skipped_elf, stats.files_skipped_pe, stats.files_skipped_macho,
        stats.files_skipped_special, stats.files_skipped_archive, stats.files_skipped_lfs,
        stats.unresolved_requirement_includes, stats.directories_skipped_depth,
        stats.requirement_includes_skipped_depth,
    ))
    return {
        "rules_sha256": digest.hexdigest(),
        "verdict": verdict,
        "blocked": any(item["blocking"] for item in findings),
        "incomplete": incomplete,
        "max_depth": max_depth,
        "intel_scope_conflicts": sorted(
            {ref.normalized_name for ref in result.packages} & intel.scope_conflicts
        ),
        "stats": asdict(stats),
        "findings": findings,
    }


if __name__ == "__main__":
    # CLI はこの処理を子プロセスで実行し、時間超過時に停止できるようにする。
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("config_directory", type=Path)
    parser.add_argument("--intel-csv", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--max-depth", type=nonnegative_depth)
    args = parser.parse_args()
    try:
        result = scan(args.directory, args.config_directory, args.intel_csv, args.data_dir,
                      max_depth=args.max_depth)
    except PolicyError as error:
        result = {"incomplete": True, "reason": "invalid_policy", "detail": str(error)}
    except MissingIntelligence as error:
        result = {"incomplete": True, "reason": "missing_intelligence", "detail": str(error)}
    except IntelligenceError as error:
        result = {"incomplete": True, "reason": "invalid_intelligence", "detail": str(error)}
    print(json.dumps(result, ensure_ascii=True))

