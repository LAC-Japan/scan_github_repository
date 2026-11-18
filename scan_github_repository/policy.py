"""重要度別のTOMLから、検出後の分類とブロック条件を読み込む。"""

from dataclasses import dataclass
import hashlib
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


DEFAULT_DIRECTORY = Path(__file__).with_name("config")
SEVERITIES = ("INFO", "SUSPICIOUS", "MALICIOUS")

# 0.2系のカスタム設定では、追加ルールに既存の重要度別ブロック設定を引き継ぐ。
ADDED_RULES = {
    "shortened_url_reference": "INFO",
    "remote_shell_example": "INFO",
    "remote_shell_pipeline": "SUSPICIOUS",
    "known_malicious_import": "MALICIOUS",
}

# 検出エンジンが返すルール ID。脱落やタイプミスを検査開始前に検出する。
RULE_IDS = {
    "privacy_mail",
    "privacy_mail_keyword",
    "privacy_mail_url",
    "possible_compromised_package_version",
    "executable_pth",
    "temporary_mail",
    "shortened_url",
    "webhook_receiver",
    "discord_webhook",
    "telegram_bot_api",
    "paste_service",
    "anonymous_file_host",
    "known_malicious_package",
    "known_compromised_package_version",
    *ADDED_RULES,
}


class PolicyError(ValueError):
    """設定ファイルやルールの割り当てが不正。"""


@dataclass(frozen=True)
class Rule:
    severity: str
    enabled: bool
    block: bool


@dataclass(frozen=True)
class Policy:
    rules: dict[str, Rule]
    digest: str


def load_policy(directory: Path) -> Policy:
    rules = {}
    blocks = {}
    digest = hashlib.sha256()
    for severity in SEVERITIES:
        path = directory / f"{severity.lower()}.toml"
        try:
            contents = path.read_bytes()
            settings = tomllib.loads(contents.decode("utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise PolicyError(f"{path.name}: {error}") from error

        if settings.keys() != {"block", "rules"}:
            raise PolicyError(f"{path.name}: expected block and [rules]")
        block = settings["block"]
        entries = settings["rules"]
        if type(block) is not bool or not isinstance(entries, dict):
            raise PolicyError(f"{path.name}: block must be boolean and rules must be a table")
        blocks[severity] = block

        for name, enabled in entries.items():
            if type(enabled) is not bool:
                raise PolicyError(f"{path.name}: {name} must be boolean")
            if name in rules:
                raise PolicyError(f"{path.name}: duplicate rule {name}")
            rules[name] = Rule(severity, enabled, block)

        digest.update(hashlib.sha256(contents).digest())

    if directory.resolve() != DEFAULT_DIRECTORY.resolve() and rules.keys() == RULE_IDS - ADDED_RULES.keys():
        rules.update({
            name: Rule(severity, True, blocks[severity]) for name, severity in ADDED_RULES.items()
        })
    missing = RULE_IDS - rules.keys()
    unknown = rules.keys() - RULE_IDS
    if missing or unknown:
        raise PolicyError(f"missing rules: {sorted(missing)}, unknown rules: {sorted(unknown)}")
    return Policy(rules, digest.hexdigest())

