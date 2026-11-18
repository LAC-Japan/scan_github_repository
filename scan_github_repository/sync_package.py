"""公開アドバイザリーのメタデータをローカルCSVに同期する。"""

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.request import Request, urlopen
from zipfile import BadZipFile, ZipFile

from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from .intelligence import DATABASE_NAME, IntelligenceError, add_csv, default_data_directory
from .vendor.repository_scanner import PackageIntelDB


OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"
DATADOG_URL = (
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset"
    "/main/samples/pypi/manifest.json"
)
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
REPORT_ID = re.compile(r"MAL-\d{4}-\d+")


class SyncError(ValueError):
    """同期元の内容を検証できなかった。"""


@dataclass(frozen=True, order=True)
class Entry:
    package: str
    policy: str
    versions: str
    ranges: str
    source: str


def fetch(url: str, target: Path, limit: int) -> str:
    deadline = time.monotonic() + 300
    digest = hashlib.sha256()
    size = 0
    request = Request(url, headers={"User-Agent": "scan_github_repository/0.4"})
    with urlopen(request, timeout=30) as response, target.open("xb") as stream:
        if response.geturl().split("/", 3)[:3] != url.split("/", 3)[:3]:
            raise SyncError("unexpected download origin")
        while chunk := response.read(256 * 1024):
            size += len(chunk)
            if size > limit or time.monotonic() > deadline:
                raise SyncError("feed exceeded the download limit")
            digest.update(chunk)
            stream.write(chunk)
    return digest.hexdigest()


def normalize_versions(values: list, counts: Counter) -> set[str]:
    result = set()
    for value in values:
        try:
            result.add(str(Version(value)))
        except (InvalidVersion, TypeError):
            counts["unsupported_versions"] += 1
    return result


def bounds_from_events(events: list) -> tuple[set[str], bool]:
    """OSVの順序境界を、プレリリースを落とさないPEP 440条件に写す。"""
    timeline = []
    limits = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise SyncError("invalid range event")
        kind, value = next(iter(event.items()))
        if kind not in {"introduced", "fixed", "last_affected", "limit"} or not isinstance(value, str):
            raise SyncError("invalid range boundary")
        if kind == "limit":
            limits.append(None if value == "*" else Version(value))
        elif kind == "introduced" and value == "0":
            timeline.append((None, kind))
        else:
            timeline.append((Version(value), kind))
    if not any(kind == "introduced" for _, kind in timeline):
        raise SyncError("range has no introduction")
    if {"fixed", "last_affected"}.issubset({kind for _, kind in timeline}):
        raise SyncError("mixed closing range events")
    timeline.sort(key=lambda item: (
        item[0] is not None, item[0] or Version("0"), item[1] != "introduced",
    ))
    limit = max(limits) if limits and None not in limits else None
    ranges = set()
    start = None
    active = False
    for version, kind in [*timeline, (None, "end")]:
        if kind == "introduced":
            if not active:
                start = version
                active = True
            continue
        if not active:
            continue
        upper = version
        inclusive = kind == "last_affected"
        if limit is not None and (upper is None or limit <= upper):
            upper, inclusive = limit, False
        if upper is not None and start is not None and (start > upper or (start == upper and not inclusive)):
            active = False
            continue
        clauses = [f">={start}"] if start is not None else []
        if upper is not None:
            clauses.append(f"<={upper}")
            if not inclusive:
                # 「<公開版」は同系列のRCも除外するため、順序比較を分ける。
                clauses.append(f"!={upper}")
        if not clauses:
            return set(), True
        ranges.add(",".join(clauses))
        active = False
    return ranges, False


def matches_from_osv(report: dict, counts: Counter):
    identifier = report.get("id", "")
    if not isinstance(identifier, str) or not REPORT_ID.fullmatch(identifier):
        raise SyncError("invalid malware advisory ID")
    if report.get("withdrawn"):
        counts["withdrawn_reports"] += 1
        return
    for item in report.get("affected", []):
        package = item.get("package", {})
        if package.get("ecosystem") != "PyPI":
            continue
        try:
            name = canonicalize_name(package["name"], validate=True)
        except (KeyError, InvalidName, TypeError):
            counts["unsupported_names"] += 1
            continue
        versions = normalize_versions(item.get("versions", []), counts)
        ranges = set()
        all_versions = False
        for specification in item.get("ranges", []):
            if specification.get("type") != "ECOSYSTEM":
                counts["unsupported_ranges"] += 1
                continue
            try:
                intervals, entire_package = bounds_from_events(specification.get("events", []))
                ranges.update(intervals)
                all_versions |= entire_package
            except (InvalidVersion, SyncError):
                counts["unsupported_ranges"] += 1
        if not versions and not ranges and not all_versions:
            counts["reports_without_version_evidence"] += 1
            continue
        yield Entry(name, "all_versions" if all_versions else "versions_only",
                    ";".join(sorted(versions)), ";".join(sorted(ranges)), f"OpenSSF:{identifier}")


def read_osv(path: Path, counts: Counter) -> set[Entry]:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise SyncError("OSV archive exceeds the size limit")
    entries = set()
    with ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > 300_000:
            raise SyncError("OSV archive has too many members")
        for member in members:
            name = Path(member.filename).name
            if not name.endswith(".json") or not REPORT_ID.fullmatch(name[:-5]):
                continue
            if member.file_size > MAX_REPORT_BYTES:
                raise SyncError(f"oversized advisory: {name}")
            with archive.open(member) as stream:
                report = json.loads(stream.read(MAX_REPORT_BYTES + 1))
            if report.get("id") != name[:-5]:
                raise SyncError(f"advisory ID mismatch: {name}")
            entries.update(matches_from_osv(report, counts))
    if not entries:
        raise SyncError("OSV archive contains no usable PyPI malware advisories")
    return entries


def read_datadog(path: Path, counts: Counter) -> set[Entry]:
    with path.open("rb") as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise SyncError("Datadog manifest exceeds the size limit")
    manifest = json.loads(data)
    if not isinstance(manifest, dict) or not manifest:
        raise SyncError("invalid Datadog manifest")
    entries = set()
    for package, versions in manifest.items():
        name = canonicalize_name(package, validate=True)
        if versions is not None and not isinstance(versions, list):
            raise SyncError("invalid Datadog package versions")
        normalized = normalize_versions(versions or [], counts)
        if versions is not None and not normalized:
            counts["reports_without_version_evidence"] += 1
            continue
        entries.add(Entry(name, "all_versions" if versions is None else "versions_only",
                          ";".join(sorted(normalized)), "", "Datadog:PyPI manifest"))
    return entries


def sync(data_dir: Path, *, osv_archive: Path | None = None, datadog: bool = False,
         datadog_manifest: Path | None = None) -> dict:
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    counts = Counter()
    hashes = {}
    destination = data_dir / DATABASE_NAME
    # 最終ファイルと同じファイルシステムで検証し、成功時だけ一度に差し替える。
    with tempfile.TemporaryDirectory(prefix=".sync-package-", dir=data_dir) as folder:
        stage = Path(folder)
        archive = osv_archive or stage / "osv.zip"
        if osv_archive is None:
            hashes["osv"] = fetch(OSV_URL, archive, MAX_ARCHIVE_BYTES)
        entries = read_osv(archive, counts)
        counts["osv_rows"] = len(entries)
        if datadog or datadog_manifest is not None:
            manifest = datadog_manifest or stage / "datadog.json"
            if datadog_manifest is None:
                hashes["datadog"] = fetch(DATADOG_URL, manifest, MAX_MANIFEST_BYTES)
            additional = read_datadog(manifest, counts)
            counts["datadog_rows"] = len(additional)
            entries.update(additional)
        output = stage / DATABASE_NAME
        with output.open("x", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("package", "policy", "versions", "ranges", "sources"))
            for row in sorted(entries):
                writer.writerow((row.package, row.policy, row.versions, row.ranges, row.source))
        intel = PackageIntelDB()
        digest = add_csv(intel, output, preserve_scope=True)
        os.chmod(output, 0o600)
        os.replace(output, destination)
    return {"status": "updated", "path": str(destination), "packages": len(intel.rules),
            "scope_conflicts": len(intel.scope_conflicts), "database_sha256": digest.hex(),
            "downloads_sha256": hashes, "counts": dict(counts)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync PyPI malware advisory metadata.")
    parser.add_argument("--data-dir", type=Path, default=default_data_directory())
    parser.add_argument("--osv-archive", type=Path, help="Read an operator-supplied PyPI OSV export.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--datadog", action="store_true", help="Also download the Datadog PyPI manifest.")
    source.add_argument("--datadog-manifest", type=Path, help="Read a local Datadog PyPI manifest.")
    args = parser.parse_args()
    try:
        result = sync(args.data_dir.expanduser().resolve(), osv_archive=args.osv_archive,
                      datadog=args.datadog, datadog_manifest=args.datadog_manifest)
    except (OSError, ValueError, BadZipFile, KeyError, TypeError, AttributeError, IntelligenceError) as error:
        print(json.dumps({"status": "error", "detail": str(error)}, ensure_ascii=True))
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

