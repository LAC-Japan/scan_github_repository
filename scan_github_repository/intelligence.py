"""同期済みのローカルCSVと、運用者が指定した追加CSVを読み込む。"""

import csv
import hashlib
import io
import os
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import InvalidName, canonicalize_name

from .vendor import scanner_config as config
from .vendor.repository_scanner import PackageIntelDB


DATABASE_NAME = "malicious_packages.csv"
REQUIRED_COLUMNS = {"package", "policy", "versions", "ranges", "sources"}
MAX_CSV_BYTES = 32 * 1024 * 1024


class IntelligenceError(ValueError):
    """判定データを安全に読み込めない。"""


class MissingIntelligence(IntelligenceError):
    """初回同期が済んでいない。"""


def default_data_directory() -> Path:
    override = os.environ.get("SCAN_GITHUB_REPOSITORY_DATA_DIR") or os.environ.get("SCAN_CLONE_DATA_DIR")
    if override:
        return Path(override).expanduser()
    storage = os.environ.get("XDG_DATA_HOME")
    if not storage and os.name == "nt":
        storage = os.environ.get("LOCALAPPDATA")
    root = Path(storage) if storage else Path.home() / ".local" / "share"
    current = root / "scan_github_repository"
    legacy = root / "scan-clone"
    # 改名前に同期した利用者は、移行先のデータがない間も既存CSVを使える。
    if not (current / DATABASE_NAME).exists() and (legacy / DATABASE_NAME).is_file():
        return legacy
    return current

def add_csv(intel: PackageIntelDB, path: Path, *, preserve_scope: bool = False) -> bytes:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_CSV_BYTES + 1)
        if len(data) > MAX_CSV_BYTES:
            raise IntelligenceError(f"{path.name}: CSV exceeds the size limit")
        rows = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
        columns = rows.fieldnames or []
        if len(set(columns)) != len(columns) or not REQUIRED_COLUMNS.issubset(columns):
            raise IntelligenceError(f"{path.name}: invalid CSV columns")
        entries = []
        for row in rows:
            if None in row or any(row[column] is None for column in columns):
                raise IntelligenceError(f"{path.name}:{rows.line_num}: invalid column count")
            package = row["package"].strip()
            policy = row["policy"].strip()
            if policy not in {config.POLICY_ALL_VERSIONS, config.POLICY_VERSIONS_ONLY}:
                raise IntelligenceError(f"{path.name}:{rows.line_num}: unknown package policy")
            versions = [value.strip() for value in row["versions"].split(";") if value.strip()]
            ranges = [value.strip() for value in row["ranges"].split(";") if value.strip()]
            try:
                normalized = canonicalize_name(package, validate=True)
                for specifier in ranges:
                    SpecifierSet(specifier)
            except (InvalidName, InvalidSpecifier) as error:
                raise IntelligenceError(f"{path.name}:{rows.line_num}: invalid package or range") from error
            entries.append((normalized, policy, versions, ranges, row["sources"]))
        if not entries:
            raise IntelligenceError(f"{path.name}: CSV has no records")
        if preserve_scope:
            # 追加CSV内でも、具体的な影響範囲を先に取り込む。
            entries.sort(key=lambda entry: entry[1] == config.POLICY_ALL_VERSIONS)
        for package, policy, versions, ranges, source in entries:
            existing = intel.rules.get(package)
            if (preserve_scope and policy == config.POLICY_ALL_VERSIONS
                    and existing is not None and existing.policy == config.POLICY_VERSIONS_ONLY):
                intel.scope_conflicts.add(package)
                continue
            intel.add_rule(package, policy, versions, ranges, source=source)
    except (OSError, UnicodeError, csv.Error) as error:
        raise IntelligenceError(f"{path.name}: {error}") from error
    # 実際に読み込んだバイト列を識別し、後からファイルを読み直さない。
    return hashlib.sha256(data).digest()


def load_intelligence(extra_csv: Path | None, data_dir: Path | None = None) -> tuple[PackageIntelDB, bytes]:
    database = (data_dir or default_data_directory()) / DATABASE_NAME
    if not database.exists():
        raise MissingIntelligence(f"{database}: run sync-package before the first scan")
    intel = PackageIntelDB()
    digest = hashlib.sha256(add_csv(intel, database, preserve_scope=True))
    if extra_csv is not None:
        digest.update(add_csv(intel, extra_csv, preserve_scope=True))
    return intel, digest.digest()
