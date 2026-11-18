#!/usr/bin/env python3
from __future__ import annotations


import argparse
import ast
from bisect import bisect_right
import codecs
import configparser
import csv
import io
import json
import logging
import os
import re
import shlex
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from logging.handlers import RotatingFileHandler
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import unquote, urlparse

from . import scanner_config as config

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

try:
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.utils import (
        InvalidSdistFilename, InvalidWheelFilename, canonicalize_name,
        parse_sdist_filename, parse_wheel_filename,
    )
    from packaging.version import InvalidVersion, Version
except ModuleNotFoundError as exc:
    raise SystemExit(
        "The 'packaging' module is required. Install it with: "
        "python3 -m pip install packaging\n"
        "For Python 3.10 TOML support, also install: python3 -m pip install tomli"
    ) from exc


LOGGER = logging.getLogger(config.LOGGER_NAME)


@dataclass(frozen=True)
class PackageReference:
    name: str
    normalized_name: str
    specifier: str
    exact_version: str | None
    source_file: str
    line_number: int
    source_type: str
    raw_value: str
    direct_reference: bool = False


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    value: str
    repository: str
    file: str
    line_number: int
    description: str
    evidence: str


@dataclass
class ScanStats:
    directories_visited: int = 0
    directories_skipped_depth: int = 0
    physical_files_seen: int = 0
    text_files_scanned: int = 0
    archive_files_scanned: int = 0
    archive_members_scanned: int = 0
    files_skipped_size: int = 0
    files_skipped_binary: int = 0
    files_skipped_error: int = 0
    files_skipped_unreadable_text: int = 0
    files_skipped_elf: int = 0
    files_skipped_pe: int = 0
    files_skipped_macho: int = 0
    files_skipped_link: int = 0
    files_skipped_special: int = 0
    files_skipped_archive: int = 0
    files_skipped_lfs: int = 0
    unresolved_requirement_includes: int = 0
    requirement_includes_skipped_depth: int = 0
    files_skipped_limit: int = 0
    scan_units_consumed: int = 0
    file_limit_reached: int = 0
    package_references: int = 0

    def add(self, other: "ScanStats") -> None:
        for key in asdict(self):
            setattr(self, key, getattr(self, key) + getattr(other, key))


@dataclass
class RepositoryResult:
    repository: str
    path: str
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    packages: list[PackageReference] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class PackageRule:
    name: str
    normalized_name: str
    policy: str  # all_versions | versions_only
    versions: set[str] = field(default_factory=set)
    ranges: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)


class PackageIntelDB:
    def __init__(self) -> None:
        self.rules: dict[str, PackageRule] = {}
        self.scope_conflicts: set[str] = set()
        self.loaded_osv_reports = 0

    def add_rule(
        self,
        name: str,
        policy: str,
        versions: Iterable[str] = (),
        ranges: Iterable[str] = (),
        source: str = "",
    ) -> None:
        normalized = canonicalize_name(name)
        rule = self.rules.get(normalized)
        if rule is None:
            rule = PackageRule(
                name=name,
                normalized_name=normalized,
                policy=policy,
            )
            self.rules[normalized] = rule
        elif rule.policy != config.POLICY_ALL_VERSIONS and policy == config.POLICY_ALL_VERSIONS:
            rule.policy = config.POLICY_ALL_VERSIONS

        rule.versions.update(str(v).strip() for v in versions if str(v).strip())
        rule.ranges.extend(str(v).strip() for v in ranges if str(v).strip())
        if source:
            rule.sources.add(source)

    def load_curated_json(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("malicious_packages", []):
            if isinstance(item, str):
                self.add_rule(item, config.POLICY_ALL_VERSIONS, source=str(path))
                continue
            self.add_rule(
                item["name"],
                item.get("policy", config.POLICY_ALL_VERSIONS),
                item.get("versions", []),
                item.get("ranges", []),
                item.get("source", str(path)),
            )

        for item in data.get("compromised_packages", []):
            self.add_rule(
                item["name"],
                config.POLICY_VERSIONS_ONLY,
                item.get("versions", []),
                item.get("ranges", []),
                item.get("source", str(path)),
            )

    def load_openssf_directory(self, root: Path) -> None:
        candidate = root / config.OPENSSF_OSV_RELATIVE_PATH
        if not candidate.is_dir():
            matches = list(root.glob(config.OPENSSF_OSV_FALLBACK_GLOB))
            if matches:
                candidate = matches[0]
        if not candidate.is_dir():
            raise FileNotFoundError(
                f"OpenSSF PyPI OSV directory not found below: {root}"
            )

        for path in candidate.rglob(config.OPENSSF_OSV_FILE_GLOB):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not str(data.get("id", "")).startswith(config.OPENSSF_ID_PREFIX):
                continue

            source = f"{config.OPENSSF_SOURCE_PREFIX}{data.get('id', path.stem)}"
            loaded_any = False
            for affected in data.get("affected", []):
                package = affected.get("package", {})
                if str(package.get("ecosystem", "")).lower() != config.OPENSSF_ECOSYSTEM:
                    continue
                name = package.get("name")
                if not name:
                    continue
                versions = affected.get("versions", [])
                ranges = self._osv_ranges_to_specifiers(affected.get("ranges", []))
                self.add_rule(
                    str(name),
                    config.POLICY_VERSIONS_ONLY,
                    versions=versions,
                    ranges=ranges,
                    source=source,
                )
                loaded_any = True
            if loaded_any:
                self.loaded_osv_reports += 1

    @staticmethod
    def _osv_ranges_to_specifiers(ranges: Sequence[dict[str, Any]]) -> list[str]:
        output: list[str] = []
        for range_item in ranges:
            events = range_item.get("events", [])
            introduced: str | None = None
            for event in events:
                if "introduced" in event:
                    introduced = str(event["introduced"])
                    continue
                if introduced is None:
                    continue
                lower = "" if introduced in config.OSV_UNBOUNDED_INTRODUCED_VALUES else f">={introduced}"
                upper = ""
                if "fixed" in event:
                    upper = f"<{event['fixed']}"
                elif "last_affected" in event:
                    upper = f"<={event['last_affected']}"
                elif "limit" in event:
                    upper = f"<{event['limit']}"
                spec = ",".join(part for part in (lower, upper) if part)
                if spec:
                    output.append(spec)
                introduced = None
            if introduced is not None and introduced not in config.OSV_UNBOUNDED_INTRODUCED_VALUES:
                output.append(f">={introduced}")
        return output

    def evaluate(self, ref: PackageReference) -> tuple[str, str] | None:
        rule = self.rules.get(ref.normalized_name)
        if rule is None:
            return None

        source_text = "; ".join(sorted(rule.sources)) or "package intelligence database"
        if ref.direct_reference and ref.exact_version is None:
            return (
                config.SEVERITY_SUSPICIOUS,
                f"Unverified artifact source for a package with a malware report. Source: {source_text}",
            )
        if rule.policy == config.POLICY_ALL_VERSIONS:
            return (
                config.SEVERITY_MALICIOUS,
                f"Known malicious/attack-controlled package. Source: {source_text}",
            )

        if not rule.versions and not rule.ranges:
            return (
                config.SEVERITY_SUSPICIOUS,
                f"Known malicious package report with no usable affected versions. Source: {source_text}",
            )

        if ref.exact_version is not None:
            if self._version_is_affected(ref.exact_version, rule):
                return (
                    config.SEVERITY_MALICIOUS,
                    f"Pinned to a known compromised version. Source: {source_text}",
                )
            return None

        if not ref.specifier:
            return (
                config.SEVERITY_SUSPICIOUS,
                "Package has known compromised releases but the dependency is unpinned; "
                f"the resolved version cannot be proven safe. Source: {source_text}",
            )

        if self._specifier_can_include_affected(ref.specifier, rule):
            return (
                config.SEVERITY_SUSPICIOUS,
                "The declared version range can include a known compromised release. "
                f"Source: {source_text}",
            )
        return None

    @staticmethod
    def _version_is_affected(version: str, rule: PackageRule) -> bool:
        if version in rule.versions:
            return True
        try:
            parsed = Version(version)
        except InvalidVersion:
            return False
        for affected in rule.versions:
            try:
                # 公開版と +local が付いた別ビルドを区別する。
                if Version(affected) == parsed:
                    return True
            except InvalidVersion:
                continue
        for spec in rule.ranges:
            try:
                if SpecifierSet(spec).contains(parsed, prereleases=True):
                    return True
            except InvalidSpecifier:
                continue
        return False

    @staticmethod
    def _specifier_can_include_affected(specifier: str, rule: PackageRule) -> bool:
        try:
            declared = SpecifierSet(specifier)
        except InvalidSpecifier:
            return True

        for version in rule.versions:
            try:
                if declared.contains(Version(version), prereleases=True):
                    return True
            except InvalidVersion:
                continue

        for affected_range in rule.ranges:
            try:
                affected = SpecifierSet(affected_range)
            except InvalidSpecifier:
                return True
            if not ordered_bounds_disjoint(declared, affected):
                return True
        return False


def ordered_bounds_disjoint(first: SpecifierSet, second: SpecifierSet) -> bool:
    """順序比較の境界で、範囲の交差が不可能だと証明できる場合だけ真を返す。"""
    lower = []
    upper = []
    clauses = (*first, *second)
    for specifier in clauses:
        operator = specifier.operator
        if operator in {">", ">=", "<", "<="}:
            bound = (Version(specifier.version), len(operator) == 2)
            (lower if operator.startswith(">") else upper).append(bound)
        elif operator == "==" and not specifier.version.endswith(".*"):
            public = Version(Version(specifier.version).public)
            lower.append((public, True))
            upper.append((public, True))
    # 同じ境界では排他的な比較を優先して交差を確認する。
    if not lower or not upper:
        return False
    floor, include_floor = max(lower, key=lambda bound: (bound[0], not bound[1]))
    ceiling, include_ceiling = min(upper)
    if floor != ceiling:
        return floor > ceiling
    return not (include_floor and include_ceiling) or any(
        clause.operator == "!=" and "+" not in clause.version
        and not clause.contains(floor, prereleases=True)
        for clause in clauses
    )


def safe_download_and_extract_openssf(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / config.OPENSSF_CACHE_DIRECTORY_NAME
    with tempfile.TemporaryDirectory(prefix=config.OPENSSF_TEMP_PREFIX, dir=cache_dir) as temp_name:
        temp_dir = Path(temp_name)
        archive_path = temp_dir / config.OPENSSF_ARCHIVE_FILENAME
        request = urllib.request.Request(
            config.OPENSSF_ARCHIVE_URL,
            headers={"User-Agent": config.USER_AGENT},
        )
        with urllib.request.urlopen(
            request, timeout=config.HTTP_TIMEOUT_SECONDS
        ) as response, archive_path.open("wb") as out:
            shutil.copyfileobj(response, out)

        extract_dir = temp_dir / config.OPENSSF_EXTRACT_DIRECTORY_NAME
        extract_dir.mkdir()
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                member = PurePosixPath(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError(f"Unsafe archive member: {info.filename}")
            zf.extractall(extract_dir)

        roots = [p for p in extract_dir.iterdir() if p.is_dir()]
        if len(roots) != 1:
            raise RuntimeError("Unexpected OpenSSF archive structure")
        if target.exists():
            shutil.rmtree(target)
        shutil.move(str(roots[0]), str(target))
    return target


def normalize_defanged(text: str) -> str:
    output = text
    for old, new in config.DEFANG_REPLACEMENTS.items():
        output = re.sub(re.escape(old), new, output, flags=re.IGNORECASE)
    return output


def host_matches(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def strip_url_punctuation(url: str) -> str:
    return url.rstrip(config.URL_TRAILING_PUNCTUATION)


def decode_text(data: bytes) -> str | None:
    if not data:
        return ""
    for markers, encoding in (
        ((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE), "utf-32"),
        ((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE), "utf-16"),
        ((codecs.BOM_UTF8,), "utf-8-sig"),
    ):
        if data.startswith(markers):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                return None
    sample = data[:config.BINARY_SAMPLE_BYTES]
    if sample.count(b"\x00") > max(
        config.BINARY_NUL_MINIMUM, len(sample) // config.BINARY_NUL_DIVISOR
    ):
        return None
    for encoding in config.TEXT_ENCODINGS:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def archive_kind(path: Path) -> str | None:
    lower = path.name.lower()
    if lower.endswith(config.ZIP_ARCHIVE_SUFFIXES):
        return "zip"
    if lower.endswith(config.TAR_ARCHIVE_SUFFIXES):
        return "tar"
    return None


def has_archive_signature(data: bytes) -> bool:
    return data.startswith((
        b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b",
        b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
        b"\x28\xb5\x2f\xfd",
    )) or data[257:262] == b"ustar"


def executable_format(data: bytes) -> str | None:
    # ELFとPEは拡張子に依存せず判定する。PEはDOSヘッダーだけでは確定しない。
    if len(data) >= 52 and data.startswith(b"\x7fELF") and data[4] in {1, 2} and data[5] in {1, 2}:
        return "elf"
    if len(data) >= 64 and data.startswith(b"MZ"):
        offset = int.from_bytes(data[60:64], "little")
        if offset >= 64 and data[offset:offset + 4] == b"PE\0\0":
            return "pe"
    if len(data) >= 28 and data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                                         b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return "macho"
    return None


def open_regular_file(path: Path):
    # LinuxではリンクやFIFOへ差し替えられても、追跡や待機を避ける。
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    stream = os.fdopen(os.open(path, flags), "rb")
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise OSError("not a regular file")
    return stream


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    # Windowsのジャンクションなど、通常のリンク判定に出ない再解析点も除外する。
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def is_probably_text_path(path_name: str) -> bool:
    name = Path(path_name).name.lower()
    suffix = Path(name).suffix.lower()
    return (
        suffix in config.TEXT_EXTENSIONS
        or name in config.MANIFEST_NAMES
        or name.startswith("requirements")
        or name in config.SPECIAL_TEXT_FILE_NAMES
        or suffix == ""
    )


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def requirement_lines(text: str) -> Iterator[tuple[int, str]]:
    logical = ""
    logical_start = 1
    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not logical:
            logical_start = number
        if stripped.endswith("\\"):
            logical += stripped.rstrip("\\").rstrip() + " "
            continue
        yield logical_start, (logical + stripped).strip()
        logical = ""


def requirement_includes(text: str) -> Iterator[str]:
    for _, line in requirement_lines(text):
        match = re.match(r"^(?:--requirement[=\s]+|--constraint[=\s]+|-[rc]\s*)(.*)$", line)
        if match:
            yield match.group(1).split(" #", 1)[0].strip().strip("\"'")


def pypi_artifact_version(url: str, name: str) -> str | None:
    """PyPIの配布ホストにある、同名アーティファクトだけをバージョン照合に使う。"""
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc.lower() != "files.pythonhosted.org":
            return None
        filename = unquote(parsed.path.rsplit("/", 1)[-1])
        if filename.endswith(".whl"):
            package, version, _, _ = parse_wheel_filename(filename)
        else:
            package, version = parse_sdist_filename(filename)
    except (InvalidSdistFilename, InvalidWheelFilename, ValueError):
        return None
    return str(version) if package == canonicalize_name(name) else None


def parse_requirement_string(
    raw: str,
    source_file: str,
    line_number: int,
    source_type: str,
) -> PackageReference | None:
    value = raw.strip().strip("\"'")
    if not value or value.startswith(config.REQUIREMENT_SKIP_PREFIXES):
        return None

    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if value.startswith(config.DIRECT_URL_PREFIXES):
        egg = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", value)
        if not egg:
            return None
        name = egg.group(1)
        return PackageReference(
            name=name,
            normalized_name=canonicalize_name(name),
            specifier="",
            exact_version=None,
            source_file=source_file,
            line_number=line_number,
            source_type=source_type,
            raw_value=raw.strip(),
            direct_reference=True,
        )

    # Condaの依存指定では等号が1つの場合がある。
    conda_match = re.fullmatch(
        r"([A-Za-z0-9_.-]+)\s*=\s*([A-Za-z0-9_.+!-]+)", value
    )
    if conda_match and "==" not in value:
        name, version = conda_match.groups()
        return PackageReference(
            name=name,
            normalized_name=canonicalize_name(name),
            specifier=f"=={version}",
            exact_version=version,
            source_file=source_file,
            line_number=line_number,
            source_type=source_type,
            raw_value=raw.strip(),
        )

    try:
        requirement = Requirement(value)
    except InvalidRequirement:
        # ロックファイルで使われる「名前 バージョン」形式を処理する。
        simple = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9_.-]*)\s+([0-9][A-Za-z0-9_.+!-]*)",
            value,
        )
        if not simple:
            return None
        name, version = simple.groups()
        return PackageReference(
            name=name,
            normalized_name=canonicalize_name(name),
            specifier=f"=={version}",
            exact_version=version,
            source_file=source_file,
            line_number=line_number,
            source_type=source_type,
            raw_value=raw.strip(),
        )

    specifier = str(requirement.specifier)
    pins = {
        Version(clause.version)
        for clause in requirement.specifier
        if clause.operator == "==" and not clause.version.endswith(".*")
    }
    # 複合条件でも、条件をすべて満たす固定バージョンを優先する。
    applicable_pins = [pin for pin in pins if requirement.specifier.contains(pin, prereleases=True)]
    exact_version = str(max(applicable_pins)) if applicable_pins else None
    if requirement.url:
        exact_version = pypi_artifact_version(requirement.url, requirement.name)
        if exact_version:
            specifier = f"=={exact_version}"
    return PackageReference(
        name=requirement.name,
        normalized_name=canonicalize_name(requirement.name),
        specifier=specifier,
        exact_version=exact_version,
        source_file=source_file,
        line_number=line_number,
        source_type=source_type,
        raw_value=raw.strip(),
        direct_reference=bool(requirement.url),
    )


class DependencyExtractor:
    def extract(self, display_path: str, text: str) -> list[PackageReference]:
        name = Path(display_path.split("!", 1)[-1]).name.lower()
        refs: list[PackageReference] = []

        if name.startswith("requirements") or name in config.REQUIREMENT_FILE_NAMES:
            refs.extend(self._parse_line_requirements(display_path, text, "requirements"))
        elif name == "pyproject.toml":
            refs.extend(self._parse_pyproject(display_path, text))
        elif name == "setup.py":
            refs.extend(self._parse_setup_py(display_path, text))
        elif name == "setup.cfg":
            refs.extend(self._parse_setup_cfg(display_path, text))
        elif name == "pipfile":
            refs.extend(self._parse_pipfile(display_path, text))
        elif name == "pipfile.lock":
            refs.extend(self._parse_pipfile_lock(display_path, text))
        elif name in config.LOCK_FILE_NAMES:
            refs.extend(self._parse_toml_lock(display_path, text))
        elif name in config.CONDA_FILE_NAMES:
            refs.extend(self._parse_conda_environment(display_path, text))
        elif name == "tox.ini":
            refs.extend(self._parse_tox(display_path, text))

        refs.extend(self._parse_inline_install_commands(display_path, text))
        if name.endswith(config.PYTHON_SOURCE_SUFFIXES):
            refs.extend(self._parse_python_subprocess_installs(display_path, text))
        return self._dedupe(refs)

    @staticmethod
    def _dedupe(refs: list[PackageReference]) -> list[PackageReference]:
        output: dict[tuple[str, str, str, int, str], PackageReference] = {}
        for ref in refs:
            key = (
                ref.normalized_name,
                ref.specifier,
                ref.source_file,
                ref.line_number,
                ref.source_type,
            )
            output[key] = ref
        return list(output.values())

    @staticmethod
    def _parse_line_requirements(
        display_path: str, text: str, source_type: str
    ) -> list[PackageReference]:
        refs: list[PackageReference] = []
        for logical_start, line in requirement_lines(text):
            # pip-compile形式の末尾に付く --hash オプションを解析前に取り除く。
            line = re.sub(r"\s+--hash(?:=|\s+)\S+", "", line).strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(config.REQUIREMENT_INCLUDE_PREFIXES):
                continue
            if line.startswith(config.REQUIREMENT_INDEX_PREFIXES):
                continue
            ref = parse_requirement_string(line, display_path, logical_start, source_type)
            if ref:
                refs.append(ref)
        return refs

    def _parse_pyproject(self, display_path: str, text: str) -> list[PackageReference]:
        if tomllib is None:
            return []
        try:
            data = tomllib.loads(text)
        except Exception:
            return []
        values: list[tuple[str, str]] = []

        project = data.get("project", {})
        for item in project.get("dependencies", []) or []:
            values.append((str(item), "pyproject.project.dependencies"))
        for group, items in (project.get("optional-dependencies", {}) or {}).items():
            for item in items or []:
                values.append((str(item), f"pyproject.optional.{group}"))

        for item in (data.get("build-system", {}) or {}).get("requires", []) or []:
            values.append((str(item), "pyproject.build-system"))

        tool = data.get("tool", {}) or {}
        poetry = tool.get("poetry", {}) or {}
        self._append_dependency_table(values, poetry.get("dependencies", {}), "poetry.dependencies")
        self._append_dependency_table(values, poetry.get("dev-dependencies", {}), "poetry.dev")
        for group, group_data in (poetry.get("group", {}) or {}).items():
            self._append_dependency_table(
                values,
                (group_data or {}).get("dependencies", {}),
                f"poetry.group.{group}",
            )

        pdm = tool.get("pdm", {}) or {}
        for group, items in (pdm.get("dev-dependencies", {}) or {}).items():
            for item in items or []:
                values.append((str(item), f"pdm.dev.{group}"))

        hatch = tool.get("hatch", {}) or {}
        envs = (hatch.get("envs", {}) or {})
        for env, env_data in envs.items():
            for item in (env_data or {}).get("dependencies", []) or []:
                values.append((str(item), f"hatch.env.{env}"))

        for group, items in (data.get("dependency-groups", {}) or {}).items():
            for item in items or []:
                if isinstance(item, str):
                    values.append((item, f"dependency-groups.{group}"))

        refs: list[PackageReference] = []
        for raw, source_type in values:
            ref = parse_requirement_string(raw, display_path, 1, source_type)
            if ref:
                refs.append(ref)
        return refs

    @staticmethod
    def _poetry_constraint_to_pep440(value: str) -> str:
        value = value.strip()
        if value in config.EMPTY_VERSION_CONSTRAINTS:
            return ""
        if value.startswith("^"):
            raw = value[1:].strip()
            try:
                version = Version(raw)
            except InvalidVersion:
                return ""
            release = list(version.release)
            while len(release) < 3:
                release.append(0)
            index = next((i for i, part in enumerate(release) if part != 0), len(release) - 1)
            upper = release[:]
            upper[index] += 1
            for i in range(index + 1, len(upper)):
                upper[i] = 0
            return f">={raw},<{'.'.join(map(str, upper))}"
        if value.startswith("~") and not value.startswith("~="):
            raw = value[1:].strip()
            try:
                version = Version(raw)
            except InvalidVersion:
                return ""
            release = list(version.release)
            while len(release) < 2:
                release.append(0)
            upper = release[:]
            index = 1 if len(version.release) >= 2 else 0
            upper[index] += 1
            for i in range(index + 1, len(upper)):
                upper[i] = 0
            return f">={raw},<{'.'.join(map(str, upper))}"
        if re.match(r"^[0-9]", value):
            return f"=={value}"
        return value

    @staticmethod
    def _append_dependency_table(
        output: list[tuple[str, str]], table: Any, source_type: str
    ) -> None:
        if not isinstance(table, dict):
            return
        for name, value in table.items():
            if canonicalize_name(str(name)) == "python":
                continue
            if isinstance(value, str):
                constraint = DependencyExtractor._poetry_constraint_to_pep440(value)
                output.append((f"{name}{constraint}" if constraint else str(name), source_type))
            elif isinstance(value, dict):
                constraint = DependencyExtractor._poetry_constraint_to_pep440(
                    str(value.get("version", ""))
                )
                output.append((f"{name}{constraint}" if constraint else str(name), source_type))
            else:
                output.append((str(name), source_type))

    def _parse_setup_py(self, display_path: str, text: str) -> list[PackageReference]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        assignments: dict[str, Any] = {}
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = self._literal_eval(getattr(node, "value", None), assignments)
                for target in targets:
                    if isinstance(target, ast.Name) and value is not None:
                        assignments[target.id] = value

        refs: list[PackageReference] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._call_name(node.func)
            if func_name.split(".")[-1] != "setup":
                continue
            for kw in node.keywords:
                if kw.arg in config.SETUP_REQUIREMENT_KEYS:
                    values = self._literal_eval(kw.value, assignments)
                    refs.extend(
                        self._refs_from_literal_values(
                            values, display_path, getattr(kw.value, "lineno", 1), f"setup.py.{kw.arg}"
                        )
                    )
                elif kw.arg == config.SETUP_EXTRAS_KEY:
                    values = self._literal_eval(kw.value, assignments)
                    if isinstance(values, dict):
                        for group, items in values.items():
                            refs.extend(
                                self._refs_from_literal_values(
                                    items,
                                    display_path,
                                    getattr(kw.value, "lineno", 1),
                                    f"setup.py.extras.{group}",
                                )
                            )
        return refs

    @staticmethod
    def _literal_eval(node: ast.AST | None, assignments: dict[str, Any]) -> Any:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return assignments.get(node.id)
        try:
            return ast.literal_eval(node)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _refs_from_literal_values(
        values: Any, display_path: str, line: int, source_type: str
    ) -> list[PackageReference]:
        if not isinstance(values, (list, tuple, set)):
            return []
        refs: list[PackageReference] = []
        for item in values:
            if not isinstance(item, str):
                continue
            ref = parse_requirement_string(item, display_path, line, source_type)
            if ref:
                refs.append(ref)
        return refs

    def _parse_setup_cfg(self, display_path: str, text: str) -> list[PackageReference]:
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
        except configparser.Error:
            return []
        refs: list[PackageReference] = []
        for section, option, source in (
            ("options", "install_requires", "setup.cfg.install_requires"),
            ("options", "setup_requires", "setup.cfg.setup_requires"),
            ("options", "tests_require", "setup.cfg.tests_require"),
        ):
            if parser.has_option(section, option):
                refs.extend(self._parse_line_requirements(display_path, parser.get(section, option), source))
        if parser.has_section("options.extras_require"):
            for group, value in parser.items("options.extras_require"):
                refs.extend(
                    self._parse_line_requirements(
                        display_path, value, f"setup.cfg.extras.{group}"
                    )
                )
        return refs

    def _parse_pipfile(self, display_path: str, text: str) -> list[PackageReference]:
        if tomllib is None:
            return []
        try:
            data = tomllib.loads(text)
        except Exception:
            return []
        values: list[tuple[str, str]] = []
        self._append_dependency_table(values, data.get("packages", {}), "Pipfile.packages")
        self._append_dependency_table(values, data.get("dev-packages", {}), "Pipfile.dev-packages")
        refs = []
        for raw, source in values:
            ref = parse_requirement_string(raw, display_path, 1, source)
            if ref:
                refs.append(ref)
        return refs

    @staticmethod
    def _parse_pipfile_lock(display_path: str, text: str) -> list[PackageReference]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        refs: list[PackageReference] = []
        for section in ("default", "develop"):
            for name, meta in (data.get(section, {}) or {}).items():
                version = meta.get("version", "") if isinstance(meta, dict) else ""
                raw = f"{name}{version}" if version else str(name)
                ref = parse_requirement_string(raw, display_path, 1, f"Pipfile.lock.{section}")
                if ref:
                    refs.append(ref)
        return refs

    @staticmethod
    def _parse_toml_lock(display_path: str, text: str) -> list[PackageReference]:
        if tomllib is None:
            return []
        try:
            data = tomllib.loads(text)
        except Exception:
            return []
        refs: list[PackageReference] = []
        packages = data.get("package", [])
        if isinstance(packages, dict):
            packages = list(packages.values())
        if not isinstance(packages, list):
            packages = []
        for item in packages:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            raw = str(item["name"])
            if item.get("version"):
                raw += f"=={item['version']}"
            ref = parse_requirement_string(raw, display_path, 1, "lock_file")
            if ref:
                refs.append(ref)
        return refs

    @staticmethod
    def _parse_conda_environment(display_path: str, text: str) -> list[PackageReference]:
        refs: list[PackageReference] = []
        in_dependencies = False
        in_pip = False
        pip_indent = 0
        for number, raw in enumerate(text.splitlines(), start=1):
            stripped = raw.strip()
            indent = len(raw) - len(raw.lstrip())
            if stripped == "dependencies:":
                in_dependencies = True
                in_pip = False
                continue
            if in_dependencies and stripped.startswith("-"):
                value = stripped[1:].strip()
                if value == "pip:":
                    in_pip = True
                    pip_indent = indent
                    continue
                if in_pip and indent <= pip_indent:
                    in_pip = False
                if not value or value == "pip":
                    continue
                ref = parse_requirement_string(
                    value, display_path, number, "conda.pip" if in_pip else "conda"
                )
                if ref:
                    refs.append(ref)
            elif in_dependencies and stripped and indent == 0:
                in_dependencies = False
                in_pip = False
        return refs

    def _parse_tox(self, display_path: str, text: str) -> list[PackageReference]:
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
        except configparser.Error:
            return []
        refs: list[PackageReference] = []
        for section in parser.sections():
            if parser.has_option(section, "deps"):
                refs.extend(
                    self._parse_line_requirements(
                        display_path, parser.get(section, "deps"), f"tox.{section}.deps"
                    )
                )
        return refs

    def _parse_inline_install_commands(self, display_path: str, text: str) -> list[PackageReference]:
        refs: list[PackageReference] = []
        for match in config.INSTALL_COMMAND_RE.finditer(text):
            command = match.group("cmd").lower()
            args = match.group("args")
            line = line_number_for_offset(text, match.start())
            refs.extend(self._parse_install_args(display_path, line, command, args))
        return refs

    def _parse_python_subprocess_installs(self, display_path: str, text: str) -> list[PackageReference]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        refs: list[PackageReference] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = self._call_name(node.func)
            if call_name not in config.PYTHON_COMMAND_CALLS:
                continue
            if not node.args:
                continue
            command: str | None = None
            first = node.args[0]
            try:
                value = ast.literal_eval(first)
            except (ValueError, TypeError):
                continue
            if isinstance(value, str):
                command = value
            elif isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
                command = shlex.join(value)
            if not command:
                continue
            refs.extend(self._parse_inline_install_commands(display_path, command))
        return refs

    def _parse_install_args(
        self, display_path: str, line: int, command: str, args: str
    ) -> list[PackageReference]:
        try:
            tokens = shlex.split(args, comments=False, posix=True)
        except ValueError:
            tokens = args.split()
        refs: list[PackageReference] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in config.INSTALL_OPTIONS_WITH_VALUE:
                skip_next = True
                continue
            if token.startswith("-"):
                continue
            if token in config.LOCAL_INSTALL_TOKENS or token.startswith(
                config.LOCAL_INSTALL_PREFIXES
            ):
                continue
            ref = parse_requirement_string(token, display_path, line, f"inline:{command}")
            if ref:
                refs.append(ref)
        return refs


class PocRepositoryScanner:
    def __init__(
        self,
        root: Path,
        intel: PackageIntelDB,
        max_file_size: int,
        max_files_per_repository: int,
        scan_archives: bool,
        max_archive_members: int,
        max_archive_total_size: int,
        privacy_mail_as_suspicious: bool,
        repository_mode: str,
        exclude_paths: Iterable[Path] = (),
        exclude_directories: Iterable[Path] = (),
        max_depth: int | None = None,
    ) -> None:
        if max_depth is not None and max_depth < 0:
            raise ValueError("max_depth must be nonnegative")
        self.root = root.resolve()
        self.intel = intel
        self.max_file_size = max_file_size
        self.max_files_per_repository = max_files_per_repository
        self.scan_archives = scan_archives
        self.max_archive_members = max_archive_members
        self.max_archive_total_size = max_archive_total_size
        self.privacy_mail_as_suspicious = privacy_mail_as_suspicious
        self.repository_mode = repository_mode
        self.exclude_paths = {path.resolve() for path in exclude_paths}
        self.exclude_directories = {path.resolve() for path in exclude_directories}
        self.max_depth = max_depth
        self.extractor = DependencyExtractor()

    def _is_excluded(self, path: Path) -> bool:
        if not self.exclude_paths and not self.exclude_directories:
            return False
        resolved = path.resolve()
        if resolved in self.exclude_paths:
            return True
        return any(
            resolved == directory or directory in resolved.parents
            for directory in self.exclude_directories
        )

    def discover_repositories(self) -> list[Path]:
        if not self.root.is_dir():
            raise NotADirectoryError(self.root)
        if self.repository_mode == "top-level":
            repos = sorted(
                p for p in self.root.iterdir()
                if (
                    p.is_dir()
                    and p.name not in config.IGNORE_DIR_NAMES
                    and not p.is_symlink()
                    and not self._is_excluded(p)
                )
            )
            return repos or [self.root]
        if self.repository_mode == "root":
            return [self.root]

        git_roots: list[Path] = []
        for current, dirnames, filenames in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            # 走査対象から .git を除外する前に、リポジトリの目印として確認する。
            has_git_marker = ".git" in dirnames or ".git" in filenames
            if has_git_marker and not self._is_excluded(current_path):
                git_roots.append(current_path)

            dirnames[:] = [
                d for d in dirnames
                if (
                    d not in config.IGNORE_DIR_NAMES
                    and not (current_path / d).is_symlink()
                    and not self._is_excluded(current_path / d)
                )
            ]
        if self.repository_mode == "git":
            return sorted(set(git_roots)) or [self.root]

        # autoではGitのルートに加え、配下にGitリポジトリがない直下のディレクトリも扱う。
        repos = set(git_roots)
        for child in self.root.iterdir():
            if (
                not child.is_dir()
                or child.name in config.IGNORE_DIR_NAMES
                or child.is_symlink()
                or self._is_excluded(child)
            ):
                continue
            if not any(root == child or child in root.parents for root in git_roots):
                repos.add(child)
        if (self.root / ".git").exists():
            repos.add(self.root)
        return sorted(repos) or [self.root]

    def scan_all(self) -> list[RepositoryResult]:
        repos = self.discover_repositories()
        repo_set = set(repos)
        LOGGER.info("Repositories discovered: %d", len(repos))
        results: list[RepositoryResult] = []
        for index, repo in enumerate(repos, start=1):
            LOGGER.info(
                "Scanning repository %d/%d: %s",
                index,
                len(repos),
                repo,
            )
            result = self.scan_repository(repo, repo_set)
            results.append(result)
            if result.stats.file_limit_reached:
                LOGGER.warning(
                    "File limit reached for %s: limit=%d consumed=%d",
                    result.repository,
                    self.max_files_per_repository,
                    result.stats.scan_units_consumed,
                )
        return results

    def scan_repository(self, repo: Path, all_repos: set[Path]) -> RepositoryResult:
        repo_name = str(repo.relative_to(self.root)) if repo != self.root else "."
        findings: list[Finding] = []
        package_refs: list[PackageReference] = []
        stats = ScanStats()
        includes: set[tuple[Path, str]] = set()

        nested_repos = {p for p in all_repos if p != repo and repo in p.parents}
        for display_path, text in self._iter_texts(repo, nested_repos, stats):
            refs = self.extractor.extract(display_path, text)
            package_refs.extend(refs)
            findings.extend(self._evaluate_package_refs(repo_name, refs))
            findings.extend(self._scan_indicators(repo_name, display_path, text))
            if not self.scan_archives:
                path = Path(display_path)
                if path.name.lower().startswith("requirements") or path.name.lower() in config.REQUIREMENT_FILE_NAMES:
                    includes.update((path.parent, value) for value in requirement_includes(text))

        # -r/-c はファイル名に関係なく追跡する。ネットワークや対象外のパスは開かない。
        refs = self._scan_requirement_includes(repo, includes, stats)
        package_refs.extend(refs)
        findings.extend(self._evaluate_package_refs(repo_name, refs))

        package_refs = self._dedupe_packages(package_refs)
        findings = self._dedupe_findings(findings)
        stats.package_references = len(package_refs)
        counts = Counter(f.category for f in findings)
        severity_counts = Counter(f.severity for f in findings)
        counts.update({f"severity_{k.lower()}": v for k, v in severity_counts.items()})

        verdict = config.VERDICT_NO_FINDINGS
        if severity_counts[config.SEVERITY_MALICIOUS]:
            verdict = config.VERDICT_MALICIOUS
        elif severity_counts[config.SEVERITY_SUSPICIOUS]:
            verdict = config.VERDICT_SUSPICIOUS
        elif severity_counts[config.SEVERITY_INFO]:
            verdict = config.VERDICT_INFO

        return RepositoryResult(
            repository=repo_name,
            path=str(repo),
            verdict=verdict,
            findings=findings,
            packages=package_refs,
            stats=stats,
            counts=dict(counts),
        )

    def _scan_requirement_includes(
        self, repo: Path, includes: set[tuple[Path, str]], stats: ScanStats
    ) -> list[PackageReference]:
        refs = []
        visited: set[Path] = set()
        pending = sorted(includes, reverse=True)
        while pending:
            directory, value = pending.pop()
            path = Path(value)
            try:
                if not value or path.anchor or "://" in value or "${" in value:
                    raise ValueError("not a local relative path")
                requested = repo / directory / path
                target = requested.resolve(strict=True)
                relative = target.relative_to(repo)
                if any(part.casefold() == ".git" for part in relative.parts):
                    raise ValueError("Git metadata is excluded")
                if target in visited:
                    continue
                visited.add(target)
                # -r/-c で指定されても、上限より深いファイルの内容は読まない。
                if self.max_depth is not None and len(relative.parent.parts) > self.max_depth:
                    stats.requirement_includes_skipped_depth += 1
                    continue
                if self._is_excluded(target) or not stat.S_ISREG(target.lstat().st_mode):
                    raise ValueError("not a scannable regular file")
                with open_regular_file(target) as stream:
                    data = stream.read(self.max_file_size + 1)
                if len(data) > self.max_file_size:
                    raise ValueError("file exceeds the size limit")
                text = decode_text(data)
                if text is None:
                    raise ValueError("file is not text")
            except (OSError, ValueError, RuntimeError):
                stats.unresolved_requirement_includes += 1
                continue
            refs.extend(self.extractor._parse_line_requirements(str(relative), text, "requirements"))
            pending.extend((relative.parent, item) for item in requirement_includes(text))
        return refs

    def _limit_reached(self, stats: ScanStats) -> bool:
        return (
            self.max_files_per_repository > 0
            and stats.scan_units_consumed >= self.max_files_per_repository
        )

    @staticmethod
    def _file_priority(filename: str) -> tuple[int, str]:
        lower = filename.lower()
        if (
            lower in config.MANIFEST_NAMES
            or any(lower.startswith(prefix) for prefix in config.PRIORITY_FILE_PREFIXES)
        ):
            return (0, lower)
        if Path(lower).suffix in config.TEXT_EXTENSIONS:
            return (1, lower)
        if any(lower.endswith(suffix) for suffix in config.ARCHIVE_SUFFIXES):
            return (2, lower)
        return (3, lower)

    def _consume_scan_unit(self, stats: ScanStats) -> bool:
        if self._limit_reached(stats):
            stats.file_limit_reached = 1
            stats.files_skipped_limit += 1
            return False
        stats.scan_units_consumed += 1
        return True

    def _iter_texts(
        self, repo: Path, nested_repos: set[Path], stats: ScanStats
    ) -> Iterator[tuple[str, str]]:
        def record_walk_error(_error: OSError) -> None:
            stats.files_skipped_error += 1

        for current, dirnames, filenames in os.walk(
            repo, onerror=record_walk_error, followlinks=False
        ):
            if self._limit_reached(stats):
                stats.file_limit_reached = 1
                stats.files_skipped_limit += 1
                return

            current_path = Path(current)
            stats.directories_visited += 1
            at_depth_limit = (
                self.max_depth is not None and len(current_path.relative_to(repo).parts) >= self.max_depth
            )
            filtered: list[str] = []
            for dirname in sorted(dirnames):
                child = current_path / dirname
                if dirname.casefold() == ".git":
                    continue
                try:
                    metadata = child.lstat()
                except OSError:
                    stats.files_skipped_error += 1
                    continue
                if is_link_or_reparse(metadata):
                    stats.files_skipped_link += 1
                    continue
                if (
                    dirname in config.IGNORE_DIR_NAMES
                    or child in nested_repos
                    or self._is_excluded(child)
                ):
                    continue
                if at_depth_limit:
                    stats.directories_skipped_depth += 1
                    continue
                filtered.append(dirname)
            dirnames[:] = filtered

            for filename in sorted(filenames, key=self._file_priority):
                if self._limit_reached(stats):
                    stats.file_limit_reached = 1
                    stats.files_skipped_limit += 1
                    return

                path = current_path / filename
                if filename.casefold() == ".git":
                    continue
                try:
                    metadata = path.lstat()
                except OSError:
                    stats.files_skipped_error += 1
                    continue
                if is_link_or_reparse(metadata):
                    stats.files_skipped_link += 1
                    continue
                if self._is_excluded(path):
                    continue
                if not self._consume_scan_unit(stats):
                    return

                stats.physical_files_seen += 1
                relative = str(path.relative_to(repo))
                if not stat.S_ISREG(metadata.st_mode):
                    stats.files_skipped_special += 1
                    continue

                kind = archive_kind(path)
                if kind and self.scan_archives:
                    yield from self._iter_archive_texts(path, relative, kind, stats)
                    if self._limit_reached(stats):
                        stats.file_limit_reached = 1
                        stats.files_skipped_limit += 1
                        return
                    continue
                if kind:
                    stats.files_skipped_archive += 1
                    continue
                if metadata.st_size > self.max_file_size:
                    stats.files_skipped_size += 1
                    continue
                try:
                    with open_regular_file(path) as stream:
                        data = stream.read(self.max_file_size + 1)
                except OSError:
                    stats.files_skipped_error += 1
                    continue
                if len(data) > self.max_file_size:
                    stats.files_skipped_size += 1
                    continue
                if has_archive_signature(data):
                    stats.files_skipped_archive += 1
                    continue
                binary_format = executable_format(data)
                if binary_format:
                    stats.files_skipped_binary += 1
                    attribute = f"files_skipped_{binary_format}"
                    setattr(stats, attribute, getattr(stats, attribute) + 1)
                    continue
                text = decode_text(data)
                if text is None:
                    stats.files_skipped_binary += 1
                    if is_probably_text_path(relative):
                        stats.files_skipped_unreadable_text += 1
                    continue
                if text.split("\n", 1)[0].rstrip("\r") == "version https://git-lfs.github.com/spec/v1":
                    stats.files_skipped_lfs += 1
                    continue
                stats.text_files_scanned += 1
                yield relative, text

    def _iter_archive_texts(
        self, path: Path, relative: str, kind: str, stats: ScanStats
    ) -> Iterator[tuple[str, str]]:
        try:
            if path.stat().st_size > self.max_archive_total_size:
                stats.files_skipped_size += 1
                return
            stats.archive_files_scanned += 1
            if kind == "zip":
                with zipfile.ZipFile(path) as archive:
                    total = 0
                    members = sorted(
                        archive.infolist(),
                        key=lambda info: self._file_priority(info.filename),
                    )
                    for index, info in enumerate(members):
                        if index >= self.max_archive_members:
                            break
                        if self._limit_reached(stats):
                            stats.file_limit_reached = 1
                            return
                        if info.is_dir() or info.file_size > self.max_file_size:
                            continue
                        if not is_probably_text_path(info.filename):
                            continue
                        if not self._consume_scan_unit(stats):
                            return
                        total += info.file_size
                        if total > self.max_archive_total_size:
                            break
                        try:
                            data = archive.read(info)
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            continue
                        text = decode_text(data)
                        if text is None:
                            continue
                        stats.archive_members_scanned += 1
                        yield f"{relative}!{info.filename}", text
            else:
                with tarfile.open(path, mode="r:*") as archive:
                    total = 0
                    for index, member in enumerate(archive):
                        if index >= self.max_archive_members:
                            break
                        if self._limit_reached(stats):
                            stats.file_limit_reached = 1
                            return
                        if not member.isfile() or member.size > self.max_file_size:
                            continue
                        if not is_probably_text_path(member.name):
                            continue
                        if not self._consume_scan_unit(stats):
                            return
                        total += member.size
                        if total > self.max_archive_total_size:
                            break
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            continue
                        data = extracted.read(self.max_file_size + 1)
                        if len(data) > self.max_file_size:
                            continue
                        text = decode_text(data)
                        if text is None:
                            continue
                        stats.archive_members_scanned += 1
                        yield f"{relative}!{member.name}", text
        except (OSError, tarfile.TarError, zipfile.BadZipFile):
            stats.files_skipped_error += 1

    def _evaluate_package_refs(
        self, repo_name: str, refs: list[PackageReference]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for ref in refs:
            result = self.intel.evaluate(ref)
            if result is None:
                continue
            severity, description = result
            display = ref.name + (ref.specifier or "")
            # 侵害版に固定された依存と、侵害版を含み得る依存を別々に設定できる。
            if severity != config.SEVERITY_MALICIOUS:
                category = "possible_compromised_package_version"
            elif self.intel.rules[ref.normalized_name].policy == config.POLICY_ALL_VERSIONS:
                category = "known_malicious_package"
            else:
                category = "known_compromised_package_version"
            findings.append(
                Finding(
                    severity=severity,
                    category=category,
                    value=display,
                    repository=repo_name,
                    file=ref.source_file,
                    line_number=ref.line_number,
                    description=description,
                    evidence=ref.raw_value[:config.EVIDENCE_MAX_CHARS],
                )
            )
        return findings

    def _scan_indicators(
        self, repo_name: str, display_path: str, text: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        member_name = Path(display_path.split("!", 1)[-1]).name.lower()
        for line_number, original_line in enumerate(text.splitlines(), start=1):
            line = normalize_defanged(original_line)
            if member_name.endswith(config.PTH_SUFFIX) and config.EXECUTABLE_PTH_RE.match(
                original_line
            ):
                findings.append(
                    Finding(
                        severity=config.SEVERITY_SUSPICIOUS,
                        category="executable_pth",
                        value=display_path,
                        repository=repo_name,
                        file=display_path,
                        line_number=line_number,
                        description=(
                            "Executable .pth startup hook detected. Python may execute this line "
                            "during interpreter startup even when the package is not imported."
                        ),
                        evidence=original_line.strip()[:config.EVIDENCE_MAX_CHARS],
                    )
                )
            matches = list(config.URL_RE.finditer(line))
            url_starts = [match.start() for match in matches]
            urls = {strip_url_punctuation(match.group(0)) for match in matches}
            for match in config.BARE_DOMAIN_URL_RE.finditer(line):
                # 完全URLの一部をスキームなしURLとして再検出しない。
                index = bisect_right(url_starts, match.start()) - 1
                if index >= 0 and match.start() < matches[index].end():
                    continue
                candidate = strip_url_punctuation(match.group(0))
                host = candidate.split("/", 1)[0].lower()
                if any(host_matches(host, d) for d in config.SHORTENER_DOMAINS):
                    urls.add("https://" + candidate)

            for url in sorted(urls):
                findings.extend(
                    self._classify_url(repo_name, display_path, line_number, url, original_line)
                )

            for email_match in config.EMAIL_RE.finditer(line):
                email = email_match.group(0)
                host = email.rsplit("@", 1)[1].lower().strip(".")
                if any(host_matches(host, d) for d in config.PRIVACY_MAIL_DOMAINS):
                    severity = (
                        config.SEVERITY_SUSPICIOUS
                        if self.privacy_mail_as_suspicious
                        else config.SEVERITY_INFO
                    )
                    findings.append(
                        Finding(
                            severity=severity,
                            category="privacy_mail",
                            value=email,
                            repository=repo_name,
                            file=display_path,
                            line_number=line_number,
                            description=(
                                "Privacy-focused email address detected. It is retained for actor/author "
                                "attribution and is not malicious by itself."
                            ),
                            evidence=original_line.strip()[:config.EVIDENCE_MAX_CHARS],
                        )
                    )
                elif any(host_matches(host, d) for d in config.TEMP_MAIL_DOMAINS):
                    findings.append(
                        Finding(
                            severity=config.SEVERITY_SUSPICIOUS,
                            category="temporary_mail",
                            value=email,
                            repository=repo_name,
                            file=display_path,
                            line_number=line_number,
                            description="Disposable email address detected.",
                            evidence=original_line.strip()[:config.EVIDENCE_MAX_CHARS],
                        )
                    )

            if config.PROTON_KEYWORD_RE.search(line) and not config.EMAIL_RE.search(line):
                severity = (
                        config.SEVERITY_SUSPICIOUS
                        if self.privacy_mail_as_suspicious
                        else config.SEVERITY_INFO
                    )
                findings.append(
                    Finding(
                        severity=severity,
                        category="privacy_mail_keyword",
                        value=config.PROTON_KEYWORD_RE.search(line).group(0),  # type: ignore[union-attr]
                        repository=repo_name,
                        file=display_path,
                        line_number=line_number,
                        description="Proton Mail-related text detected for attribution review.",
                        evidence=original_line.strip()[:config.EVIDENCE_MAX_CHARS],
                    )
                )
        return findings

    @staticmethod
    def _classify_url(
        repo_name: str,
        display_path: str,
        line_number: int,
        url: str,
        evidence: str,
    ) -> list[Finding]:
        try:
            parsed = urlparse(url)
        except ValueError:
            return []
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return []
        path = parsed.path.lower()
        output: list[Finding] = []

        def add(severity: str, category: str, description: str) -> None:
            output.append(
                Finding(
                    severity=severity,
                    category=category,
                    value=url,
                    repository=repo_name,
                    file=display_path,
                    line_number=line_number,
                    description=description,
                    evidence=evidence.strip()[:config.EVIDENCE_MAX_CHARS],
                )
            )

        if any(host_matches(host, domain) for domain in config.SHORTENER_DOMAINS):
            add(config.SEVERITY_SUSPICIOUS, "shortened_url", "Shortened URL hides the final destination.")
        if any(
            host_matches(host, domain)
            for domain in config.WEBHOOK_RECEIVER_DOMAINS
        ):
            add(config.SEVERITY_SUSPICIOUS, "webhook_receiver", "Public webhook receiver URL detected.")
        if (
            any(host_matches(host, domain) for domain in config.DISCORD_DOMAINS)
            and config.DISCORD_WEBHOOK_PATH_FRAGMENT in path
        ):
            add(config.SEVERITY_SUSPICIOUS, "discord_webhook", "Discord webhook endpoint detected.")
        if (
            any(host_matches(host, domain) for domain in config.TELEGRAM_BOT_DOMAINS)
            and config.TELEGRAM_BOT_PATH_RE.search(path)
        ):
            add(config.SEVERITY_SUSPICIOUS, "telegram_bot_api", "Telegram Bot API endpoint with bot token path detected.")
        if any(host_matches(host, d) for d in config.PASTE_DOMAINS):
            add(config.SEVERITY_SUSPICIOUS, "paste_service", "Paste/raw-content service URL detected.")
        if any(host_matches(host, d) for d in config.ANON_FILE_DOMAINS):
            add(config.SEVERITY_SUSPICIOUS, "anonymous_file_host", "Anonymous/public file-hosting URL detected.")
        if any(host_matches(host, d) for d in config.PRIVACY_MAIL_DOMAINS):
            add(config.SEVERITY_INFO, "privacy_mail_url", "Privacy-focused mail service URL detected.")
        return output

    @staticmethod
    def _dedupe_packages(refs: list[PackageReference]) -> list[PackageReference]:
        unique: dict[tuple[str, str, str, int, str], PackageReference] = {}
        for ref in refs:
            unique[(
                ref.normalized_name, ref.specifier, ref.source_file,
                ref.line_number, ref.source_type
            )] = ref
        return sorted(
            unique.values(),
            key=lambda r: (r.source_file, r.line_number, r.normalized_name),
        )

    @staticmethod
    def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
        unique: dict[tuple[str, str, str, str, int], Finding] = {}
        for finding in findings:
            key = (
                finding.severity,
                finding.category,
                finding.value,
                finding.file,
                finding.line_number,
            )
            unique[key] = finding
        order = config.SEVERITY_ORDER
        return sorted(
            unique.values(),
            key=lambda f: (order.get(f.severity, 9), f.file, f.line_number, f.category),
        )


def build_global_summary(results: list[RepositoryResult], intel: PackageIntelDB) -> dict[str, Any]:
    total_stats = ScanStats()
    category_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    unique_malicious_packages: set[str] = set()
    unique_short_urls: set[str] = set()
    for result in results:
        total_stats.add(result.stats)
        for finding in result.findings:
            category_counts[finding.category] += 1
            severity_counts[finding.severity] += 1
            if finding.category in config.KNOWN_BAD_PACKAGE_CATEGORIES:
                package_name = re.split(r"[<>=!~\s\[]", finding.value, maxsplit=1)[0]
                unique_malicious_packages.add(canonicalize_name(package_name))
            if finding.category == "shortened_url":
                unique_short_urls.add(finding.value)

    verdict_counts = Counter(result.verdict for result in results)
    return {
        "repositories_total": len(results),
        "repositories_malicious": verdict_counts[config.VERDICT_MALICIOUS],
        "repositories_suspicious": verdict_counts[config.VERDICT_SUSPICIOUS],
        "repositories_info_only": verdict_counts[config.VERDICT_INFO],
        "repositories_no_findings": verdict_counts[config.VERDICT_NO_FINDINGS],
        "findings_total": sum(category_counts.values()),
        "malicious_findings": severity_counts[config.SEVERITY_MALICIOUS],
        "suspicious_findings": severity_counts[config.SEVERITY_SUSPICIOUS],
        "info_findings": severity_counts[config.SEVERITY_INFO],
        "known_bad_package_occurrences": (
            category_counts["known_malicious_package"]
            + category_counts["known_compromised_package_version"]
        ),
        "unique_known_bad_packages": len(unique_malicious_packages),
        "shortened_url_occurrences": category_counts["shortened_url"],
        "unique_shortened_urls": len(unique_short_urls),
        "privacy_mail_occurrences": (
            category_counts["privacy_mail"]
            + category_counts["privacy_mail_keyword"]
            + category_counts["privacy_mail_url"]
        ),
        "temporary_mail_occurrences": category_counts["temporary_mail"],
        "discord_webhook_occurrences": category_counts["discord_webhook"],
        "telegram_bot_api_occurrences": category_counts["telegram_bot_api"],
        "paste_service_occurrences": category_counts["paste_service"],
        "anonymous_file_host_occurrences": category_counts["anonymous_file_host"],
        "executable_pth_occurrences": category_counts["executable_pth"],
        "intel_package_rules": len(intel.rules),
        "openssf_osv_reports_loaded": intel.loaded_osv_reports,
        "scan_stats": asdict(total_stats),
        "category_counts": dict(category_counts),
    }


def write_json_report(
    output: Path,
    root: Path,
    results: list[RepositoryResult],
    summary: dict[str, Any],
) -> None:
    data = {
        "root": str(root.resolve()),
        "summary": summary,
        "repositories": [
            {
                "repository": result.repository,
                "path": result.path,
                "verdict": result.verdict,
                "counts": result.counts,
                "stats": asdict(result.stats),
                "findings": [asdict(f) for f in result.findings],
                "packages": [asdict(p) for p in result.packages],
            }
            for result in results
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding=config.JSON_ENCODING,
    )


def write_findings_csv(output: Path, results: list[RepositoryResult]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = config.FINDINGS_CSV_FIELDS
    with output.open("w", encoding=config.CSV_ENCODING, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            for finding in result.findings:
                row = asdict(finding)
                row["verdict"] = result.verdict
                writer.writerow({key: row.get(key, "") for key in fields})


def write_repository_csv(output: Path, results: list[RepositoryResult]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fields = config.REPOSITORIES_CSV_FIELDS
    with output.open("w", encoding=config.CSV_ENCODING, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            c = Counter(f.category for f in result.findings)
            s = Counter(f.severity for f in result.findings)
            writer.writerow({
                "repository": result.repository,
                "path": result.path,
                "verdict": result.verdict,
                "malicious": s[config.SEVERITY_MALICIOUS],
                "suspicious": s[config.SEVERITY_SUSPICIOUS],
                "info": s[config.SEVERITY_INFO],
                "known_bad_packages": c["known_malicious_package"] + c["known_compromised_package_version"],
                "shortened_urls": c["shortened_url"],
                "privacy_mail": c["privacy_mail"] + c["privacy_mail_keyword"] + c["privacy_mail_url"],
                "temporary_mail": c["temporary_mail"],
                "discord_webhooks": c["discord_webhook"],
                "telegram_bot_api": c["telegram_bot_api"],
                "paste_services": c["paste_service"],
                "file_hosts": c["anonymous_file_host"],
                "executable_pth": c["executable_pth"],
                "directories_visited": result.stats.directories_visited,
                "physical_files_seen": result.stats.physical_files_seen,
                "text_files_scanned": result.stats.text_files_scanned,
                "archive_files_scanned": result.stats.archive_files_scanned,
                "archive_members_scanned": result.stats.archive_members_scanned,
                "scan_units_consumed": result.stats.scan_units_consumed,
                "file_limit_reached": result.stats.file_limit_reached,
                "files_skipped_limit": result.stats.files_skipped_limit,
                "package_references": result.stats.package_references,
            })


def log_summary(results: list[RepositoryResult], summary: dict[str, Any]) -> None:
    LOGGER.info(
        "repositories=%d malicious=%d suspicious=%d info_only=%d clean=%d",
        summary["repositories_total"],
        summary["repositories_malicious"],
        summary["repositories_suspicious"],
        summary["repositories_info_only"],
        summary["repositories_no_findings"],
    )
    LOGGER.info(
        "known_bad_package_occurrences=%d shortened_urls=%d privacy_mail=%d "
        "temporary_mail=%d executable_pth=%d",
        summary["known_bad_package_occurrences"],
        summary["shortened_url_occurrences"],
        summary["privacy_mail_occurrences"],
        summary["temporary_mail_occurrences"],
        summary["executable_pth_occurrences"],
    )
    scan_stats = summary["scan_stats"]
    LOGGER.info(
        "directories=%d files=%d text_scanned=%d archives=%d archive_members=%d "
        "scan_units=%d truncated_repositories=%d package_refs=%d",
        scan_stats["directories_visited"],
        scan_stats["physical_files_seen"],
        scan_stats["text_files_scanned"],
        scan_stats["archive_files_scanned"],
        scan_stats["archive_members_scanned"],
        scan_stats["scan_units_consumed"],
        scan_stats["file_limit_reached"],
        scan_stats["package_references"],
    )
    for result in results:
        sev = Counter(f.severity for f in result.findings)
        cat = Counter(f.category for f in result.findings)
        LOGGER.info(
            "[%s] %s M=%d S=%d I=%d packages=%d short_urls=%d "
            "scan_units=%d limit_reached=%d",
            result.verdict,
            result.repository,
            sev[config.SEVERITY_MALICIOUS],
            sev[config.SEVERITY_SUSPICIOUS],
            sev[config.SEVERITY_INFO],
            cat["known_malicious_package"] + cat["known_compromised_package_version"],
            cat["shortened_url"],
            result.stats.scan_units_consumed,
            result.stats.file_limit_reached,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Recursively scan PoC repositories for known malicious Python packages, "
            "compromised package versions, shortened URLs, privacy/disposable mail, "
            "webhooks, bot APIs, paste sites, and anonymous file hosts."
        )
    )
    parser.add_argument("root", nargs="?", type=Path, default=config.SCAN_ROOT)
    parser.add_argument(
        "--repository-mode",
        choices=config.REPOSITORY_MODES,
        default=config.REPOSITORY_MODE,
        help="auto: recursively discover Git repositories and use top-level fallback",
    )
    parser.add_argument(
        "--intel-db",
        type=Path,
        default=config.INTEL_JSON_PATH,
        help="Curated malicious package JSON database",
    )
    parser.add_argument(
        "--openssf-dir",
        type=Path,
        default=config.OPENSSF_LOCAL_DIR,
        help="Local clone/extraction of ossf/malicious-packages",
    )
    parser.add_argument(
        "--update-openssf",
        action=argparse.BooleanOptionalAction,
        default=config.UPDATE_OPENSSF,
        help="Download/update the OpenSSF malicious-packages cache before scanning",
    )
    parser.add_argument("--cache-dir", type=Path, default=config.CACHE_DIR)
    parser.add_argument(
        "--exclude",
        action="append",
        type=Path,
        default=list(config.EXCLUDE_PATHS),
        help=(
            "File or directory to exclude from scanning. May be specified multiple times. "
            "The scanner itself, intelligence DB, cache, and report outputs are excluded automatically."
        ),
    )
    parser.add_argument("--max-file-size", type=int, default=config.MAX_FILE_SIZE)
    parser.add_argument(
        "--max-files-per-repository",
        type=int,
        default=config.MAX_FILES_PER_REPOSITORY,
        help="Maximum normal files plus archive members processed per repository; <=0 disables the limit",
    )
    parser.add_argument("--max-archive-members", type=int, default=config.MAX_ARCHIVE_MEMBERS)
    parser.add_argument("--max-archive-total-size", type=int, default=config.MAX_ARCHIVE_TOTAL_SIZE)
    parser.add_argument(
        "--scan-archives",
        action=argparse.BooleanOptionalAction,
        default=config.SCAN_ARCHIVES,
    )
    parser.add_argument(
        "--privacy-mail-as-suspicious",
        action=argparse.BooleanOptionalAction,
        default=config.PRIVACY_MAIL_AS_SUSPICIOUS,
        help="Make Proton/Tuta findings affect the repository verdict; default is INFO only",
    )
    parser.add_argument(
        "--json-output", type=Path, default=config.JSON_OUTPUT
    )
    parser.add_argument(
        "--findings-csv", type=Path, default=config.FINDINGS_CSV_OUTPUT
    )
    parser.add_argument(
        "--repositories-csv", type=Path, default=config.REPOSITORIES_CSV_OUTPUT
    )
    parser.add_argument(
        "--fail-on",
        choices=config.FAIL_ON_CHOICES,
        default=config.FAIL_ON,
        help="Optional CI exit status policy",
    )
    return parser.parse_args()


def configure_logging() -> None:
    LOGGER.setLevel(config.LOG_LEVEL)
    LOGGER.handlers.clear()

    formatter = logging.Formatter(config.LOG_FORMAT)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    LOGGER.addHandler(stream_handler)

    config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding=config.LOG_ENCODING,
    )
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)


def main() -> int:
    configure_logging()
    args = parse_args()
    LOGGER.info(
        "Starting scan: root=%s mode=%s max_files_per_repository=%d",
        args.root,
        args.repository_mode,
        args.max_files_per_repository,
    )
    intel = PackageIntelDB()
    if args.intel_db and args.intel_db.is_file():
        intel.load_curated_json(args.intel_db)
    elif args.intel_db:
        LOGGER.warning("Curated intel DB not found: %s", args.intel_db)

    openssf_dir = args.openssf_dir
    if args.update_openssf:
        try:
            openssf_dir = safe_download_and_extract_openssf(args.cache_dir)
        except Exception as exc:
            LOGGER.warning("OpenSSF update failed: %s", exc)
    elif openssf_dir is None:
        cached = args.cache_dir / config.OPENSSF_CACHE_DIRECTORY_NAME
        if cached.is_dir():
            openssf_dir = cached

    if openssf_dir is not None:
        try:
            intel.load_openssf_directory(openssf_dir)
        except Exception as exc:
            LOGGER.warning("Failed to load OpenSSF DB: %s", exc)

    automatic_exclude_paths = {
        Path(__file__).resolve(),
        args.json_output.resolve(),
        args.findings_csv.resolve(),
        args.repositories_csv.resolve(),
    }
    if args.intel_db is not None:
        automatic_exclude_paths.add(args.intel_db.resolve())
    automatic_exclude_paths.update(path.resolve() for path in args.exclude if path.is_file())

    automatic_exclude_directories = {args.cache_dir.resolve()}
    if openssf_dir is not None:
        automatic_exclude_directories.add(openssf_dir.resolve())
    automatic_exclude_directories.update(
        path.resolve() for path in args.exclude if not path.is_file()
    )

    scanner = PocRepositoryScanner(
        root=args.root,
        intel=intel,
        max_file_size=args.max_file_size,
        max_files_per_repository=args.max_files_per_repository,
        scan_archives=args.scan_archives,
        max_archive_members=args.max_archive_members,
        max_archive_total_size=args.max_archive_total_size,
        privacy_mail_as_suspicious=args.privacy_mail_as_suspicious,
        repository_mode=args.repository_mode,
        exclude_paths=automatic_exclude_paths,
        exclude_directories=automatic_exclude_directories,
    )
    results = scanner.scan_all()
    summary = build_global_summary(results, intel)
    log_summary(results, summary)
    write_json_report(args.json_output, args.root, results, summary)
    write_findings_csv(args.findings_csv, results)
    write_repository_csv(args.repositories_csv, results)

    if args.fail_on == "malicious" and summary["repositories_malicious"]:
        return config.FAILURE_EXIT_CODE
    if args.fail_on == "suspicious" and (
        summary["repositories_malicious"] or summary["repositories_suspicious"]
    ):
        return config.FAILURE_EXIT_CODE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
