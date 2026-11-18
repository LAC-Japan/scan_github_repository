from __future__ import annotations

import logging
import re
from pathlib import Path

# ============================================================
# 基本パス・実行設定
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
LOGGER_NAME = "poc_repository_scanner"

# 引数なしで実行した場合、このディレクトリ直下の各ディレクトリを
# 1リポジトリとして扱い、その内部を再帰走査する。
SCAN_ROOT = Path("/data/github/2022")
REPOSITORY_MODE = "top-level"
REPOSITORY_MODES = ("auto", "git", "top-level", "root")

INTEL_JSON_PATH = SCRIPT_DIR / "malicious_packages.json"
INTEL_CSV_PATH = SCRIPT_DIR / "malicious_packages.csv"
CACHE_DIR = Path.home() / ".cache" / "poc-repository-scanner"
OPENSSF_LOCAL_DIR: Path | None = None

# スキャン出力。毎回上書きする。
JSON_OUTPUT = Path("repository_scan_results.json")
FINDINGS_CSV_OUTPUT = Path("repository_scan_findings.csv")
REPOSITORIES_CSV_OUTPUT = Path("repository_scan_summary.csv")

# 明示的な除外対象。ファイル・ディレクトリのどちらも指定可能。
EXCLUDE_PATHS: tuple[Path, ...] = ()

# ============================================================
# スキャン上限・動作設定
# ============================================================

# 1リポジトリあたりに処理する最大スキャン単位数。
# 通常ファイルとアーカイブ内メンバーを合算する。0以下で無制限。
MAX_FILES_PER_REPOSITORY = 200
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2000
MAX_ARCHIVE_TOTAL_SIZE = 50 * 1024 * 1024
SCAN_ARCHIVES = True
PRIVACY_MAIL_AS_SUSPICIOUS = False

# CI等で利用する終了コード判定。
FAIL_ON = "never"
FAIL_ON_CHOICES = ("never", "malicious", "suspicious")
FAILURE_EXIT_CODE = 2

# ============================================================
# インテリジェンス更新設定
# ============================================================

# Trueの場合も、REFRESH_HOURS以内のキャッシュがあれば再取得しない。
UPDATE_OPENSSF = False
OPENSSF_REFRESH_HOURS = 24
UPDATE_PYPI_INDEX = False
PYPI_INDEX_REFRESH_HOURS = 24

# 個別JSON APIは最新版等を取得する。OpenSSF全件に行うと過剰なため、
# 基本は更新前のローカルDBに含まれていたパッケージのみを対象とする。
UPDATE_PYPI_PROJECT_METADATA = False
PYPI_METADATA_SCOPE = "curated"  # curated | all | none
PYPI_METADATA_MAX_PACKAGES = 500
PYPI_METADATA_WORKERS = 8
HTTP_TIMEOUT_SECONDS = 60

# 更新したインテリジェンスを同じJSON/CSVへ原子的に上書きする。
OVERWRITE_INTEL_FILES = False

# ============================================================
# ログ設定
# ============================================================

LOG_LEVEL = logging.INFO
LOG_FILE = SCRIPT_DIR / "poc_repository_scanner.log"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_ENCODING = "utf-8"
JSON_ENCODING = "utf-8"
CSV_ENCODING = "utf-8-sig"

# ============================================================
# 更新元・OpenSSF形式
# ============================================================

OPENSSF_ARCHIVE_URL = (
    "https://codeload.github.com/ossf/malicious-packages/zip/refs/heads/main"
)
OPENSSF_CACHE_DIRECTORY_NAME = "openssf-malicious-packages"
OPENSSF_TEMP_PREFIX = "openssf-"
OPENSSF_ARCHIVE_FILENAME = "main.zip"
OPENSSF_EXTRACT_DIRECTORY_NAME = "extract"
OPENSSF_OSV_RELATIVE_PATH = Path("osv/malicious/pypi")
OPENSSF_OSV_FALLBACK_GLOB = "*/osv/malicious/pypi"
OPENSSF_OSV_FILE_GLOB = "*.json"
OPENSSF_ID_PREFIX = "MAL-"
OPENSSF_ECOSYSTEM = "pypi"
OPENSSF_SOURCE_PREFIX = "OpenSSF:"

PYPI_INDEX_URL = "https://pypi.org/simple/"
PYPI_PROJECT_JSON_URL = "https://pypi.org/pypi/{project}/json"
USER_AGENT = "poc-repository-scanner/3.1"

# ============================================================
# 判定値・ポリシー
# ============================================================

POLICY_ALL_VERSIONS = "all_versions"
POLICY_VERSIONS_ONLY = "versions_only"
OSV_UNBOUNDED_INTRODUCED_VALUES = {"0", "*"}
EMPTY_VERSION_CONSTRAINTS = {"", "*"}

SEVERITY_MALICIOUS = "MALICIOUS"
SEVERITY_SUSPICIOUS = "SUSPICIOUS"
SEVERITY_INFO = "INFO"
SEVERITY_ORDER = {
    SEVERITY_MALICIOUS: 0,
    SEVERITY_SUSPICIOUS: 1,
    SEVERITY_INFO: 2,
}

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_INFO = "INFO"
VERDICT_NO_FINDINGS = "NO_FINDINGS"
VERDICT_TIMEOUT = "TIMEOUT"

KNOWN_BAD_PACKAGE_CATEGORIES = {
    "known_malicious_package",
    "known_compromised_package_version",
}
PRIVACY_MAIL_CATEGORIES = {
    "privacy_mail",
    "privacy_mail_keyword",
    "privacy_mail_url",
}

# ============================================================
# 再帰走査・ファイル種別
# ============================================================

IGNORE_DIR_NAMES = {
    ".git",
}

ZIP_ARCHIVE_SUFFIXES = (".zip", ".whl", ".egg")
TAR_ARCHIVE_SUFFIXES = (
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
)
ARCHIVE_SUFFIXES = ZIP_ARCHIVE_SUFFIXES + TAR_ARCHIVE_SUFFIXES

MANIFEST_NAMES = {
    "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock",
    "poetry.lock", "pdm.lock", "uv.lock", "pylock.toml",
    "environment.yml", "environment.yaml", "tox.ini",
}
REQUIREMENT_FILE_NAMES = {
    "constraints.txt", "requirements.in", "requirements.lock",
}
LOCK_FILE_NAMES = {"poetry.lock", "pdm.lock", "uv.lock", "pylock.toml"}
CONDA_FILE_NAMES = {"environment.yml", "environment.yaml"}
SPECIAL_TEXT_FILE_NAMES = {"dockerfile", "makefile", "procfile", "license"}
PRIORITY_FILE_PREFIXES = ("requirements", "constraints", "readme")
PYTHON_SOURCE_SUFFIXES = (".py", ".pyw")
PTH_SUFFIX = ".pth"

TEXT_EXTENSIONS = {
    ".bash", ".bat", ".c", ".cc", ".cfg", ".cmd", ".conf", ".cpp",
    ".cs", ".css", ".csv", ".env", ".go", ".h", ".hpp", ".htm",
    ".html", ".ini", ".java", ".js", ".json", ".jsonl", ".jsx",
    ".kt", ".lock", ".lua", ".md", ".php", ".pl", ".properties",
    ".ps1", ".pth", ".py", ".pyw", ".rb", ".requirements", ".rs",
    ".rst", ".sh", ".sql", ".svg", ".swift", ".tex", ".toml",
    ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml", ".zsh",
}

TEXT_ENCODINGS = ("utf-8", "utf-8-sig", "cp932", "latin-1")
BINARY_SAMPLE_BYTES = 8192
BINARY_NUL_MINIMUM = 4
BINARY_NUL_DIVISOR = 100
EVIDENCE_MAX_CHARS = 500

# ============================================================
# 依存関係抽出
# ============================================================

REQUIREMENT_SKIP_PREFIXES = (
    "#", "-r ", "--requirement", "-c ", "--constraint",
)
DIRECT_URL_PREFIXES = (
    "git+", "hg+", "svn+", "bzr+", "http://", "https://",
)
REQUIREMENT_INCLUDE_PREFIXES = ("-r", "--requirement", "-c", "--constraint")
REQUIREMENT_INDEX_PREFIXES = (
    "--index-url", "--extra-index-url", "--find-links", "-i", "-f",
)
INSTALL_OPTIONS_WITH_VALUE = {
    "-r", "--requirement", "-c", "--constraint", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "--proxy", "--target",
    "--platform", "--python-version", "--implementation", "--abi",
}
LOCAL_INSTALL_TOKENS = {".", ".."}
LOCAL_INSTALL_PREFIXES = ("./", "../", "/")
SETUP_REQUIREMENT_KEYS = {"install_requires", "setup_requires", "tests_require"}
SETUP_EXTRAS_KEY = "extras_require"

PYTHON_COMMAND_CALLS = {
    "os.system", "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
}

# ============================================================
# URL・メール・サービス検出
# ============================================================

SHORTENER_DOMAINS = {
    "0rz.tw", "1url.com", "adf.ly", "amzn.to", "bc.vc", "bit.do",
    "bit.ly", "buff.ly", "cutt.ly", "clck.ru", "dub.sh", "goo.gl",
    "han.gl", "hubs.ly", "ift.tt", "is.gd", "kutt.it", "lc.chat",
    "lnkd.in", "ow.ly", "qrco.de", "rb.gy", "rebrand.ly", "s.id",
    "short.io", "shorturl.at", "snip.ly", "soo.gd", "t.co", "t.ly",
    "tiny.cc", "tiny.one", "tinyurl.com", "trib.al", "urlz.fr",
    "v.gd", "x.gd",
}

PRIVACY_MAIL_DOMAINS = {
    "pm.me", "proton.me", "protonmail.ch", "protonmail.com", "tuta.com",
    "tutanota.com", "tutanota.de", "tutamail.com", "keemail.me",
}

TEMP_MAIL_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "dispostable.com",
    "emailondeck.com", "getnada.com", "grr.la", "guerrillamail.com",
    "guerrillamail.info", "guerrillamailblock.com", "maildrop.cc",
    "mailinator.com", "sharklasers.com", "temp-mail.org", "tempmail.com",
    "throwawaymail.com", "yopmail.com",
}

PASTE_DOMAINS = {
    "0x0.st", "controlc.com", "dpaste.org", "hastebin.com", "paste.ee",
    "paste.rs", "pastebin.com", "rentry.co",
}

ANON_FILE_DOMAINS = {
    "anonfiles.com", "file.io", "gofile.io", "mega.nz", "mediafire.com",
    "send.vis.ee", "transfer.sh",
}

WEBHOOK_RECEIVER_DOMAINS = {"webhook.site"}
DISCORD_DOMAINS = {"discord.com", "discordapp.com"}
DISCORD_WEBHOOK_PATH_FRAGMENT = "/api/webhooks/"
TELEGRAM_BOT_DOMAINS = {"api.telegram.org"}
TELEGRAM_BOT_PATH_RE = re.compile(r"/bot[^/]+/")

DEFANG_REPLACEMENTS = {
    "hxxps[:]//": "https://",
    "hxxp[:]//": "http://",
    "https[:]//": "https://",
    "http[:]//": "http://",
    "hxxps://": "https://",
    "hxxp://": "http://",
    "[.]": ".",
    "(.)": ".",
    "{.}": ".",
    "[:]": ":",
}
URL_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""

URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'`\]\[(){}]+")
BARE_DOMAIN_URL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}/[^\s<>\"'`\]\[(){}]+"
)
EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9.-]{0,251}[A-Z0-9])?\.[A-Z]{2,63}\b"
)
PROTON_KEYWORD_RE = re.compile(
    r"(?i)\b(?:proton\s*mail|proton-?mail|protom-?mail)\b"
)
INSTALL_COMMAND_RE = re.compile(
    r"(?im)(?:^|[;&|]\s*|\$\s*|>\s*|\!|%)"
    r"(?P<cmd>"
    r"(?:python(?:3(?:\.\d+)?)?\s+-m\s+pip|pip(?:3(?:\.\d+)?)?|pipx)\s+install"
    r"|uv\s+add|poetry\s+add|pdm\s+add|pipenv\s+install"
    r")\s+(?P<args>[^\r\n;&|]+)"
)
EXECUTABLE_PTH_RE = re.compile(r"^\s*import(?:\s|\t)")
PACKAGE_NAME_FROM_FINDING_RE = re.compile(r"[<>=!~\s\[]")
OSV_BOUNDARY_VERSION_RE = re.compile(r"(?:<=|>=|<|>|==)\s*([^,\s]+)")

# ============================================================
# CSV出力列
# ============================================================

FINDINGS_CSV_FIELDS = (
    "repository", "verdict", "severity", "category", "value", "file",
    "line_number", "description", "evidence",
)

REPOSITORIES_CSV_FIELDS = (
    "repository", "path", "verdict", "malicious", "suspicious", "info",
    "known_bad_packages", "shortened_urls", "privacy_mail", "temporary_mail",
    "discord_webhooks", "telegram_bot_api", "paste_services", "file_hosts",
    "executable_pth", "directories_visited", "physical_files_seen",
    "text_files_scanned", "archive_files_scanned", "archive_members_scanned",
    "scan_units_consumed", "file_limit_reached", "files_skipped_limit",
    "package_references",
)
