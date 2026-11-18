"""構文と記述の用途を確認し、既知IOCと危険な実行手順を区別する。"""

import ast
from dataclasses import replace
from pathlib import Path
import re
import shlex

from packaging.utils import canonicalize_name
from .vendor.repository_scanner import Finding, PocRepositoryScanner, normalize_defanged


# 公開調査で実体と配布パッケージの対応を確認できた名前だけを使う。
MALICIOUS_IMPORTS = {
    "frint": "frint",
    "skytext": "skytext",
    "slogsec": "slogsec",
    "logcrypt.cryptography": "logcrypt.cryptography",
}
IMPORT_HINT = re.compile(r"\b(?:frint|skytext|slogsec|logcrypt)\b")
MARKDOWN_LINK = re.compile(
    r"\[(?P<label>!\[[^\]]*\]\([^)]+\)|[^\[\]]+)\]\(\s*<?(?P<target>[^\s)>]+)"
)
DOWNLOAD_LABEL = re.compile(r"(?i)(?:\bdownload\b|ダウンロード|下载|\bdescargar\b)")
COMMENT_START = ("#", "//", "/*", "* ", "<!--", "///", "'''", '"""')
C_STYLE_SUFFIXES = {".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".php", ".ts"}
C_STYLE_TOKENS = re.compile(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|(?P<comment>(?<!:)//|/\*)""")
DOC_SUFFIXES = {".md", ".rst", ".adoc"}
SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".ksh"}


def local_module(root: Path, source: Path, module: str) -> bool:
    parts = module.split(".")
    # 同梱の実装を外部パッケージと誤認しない。親パッケージの構造も考慮する。
    bases = {root, root / "src", (root / source).parent}
    for base in bases:
        candidate = base.joinpath(*parts)
        if candidate.with_suffix(".py").is_file() or candidate.with_suffix(".pyw").is_file():
            return True
        if (candidate / "__init__.py").is_file():
            return True
    return False


def imported_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and not node.level and node.module:
        names = [f"{node.module}.{alias.name}" for alias in node.names]
        return [*names, node.module]
    return []


def known_imports(root: Path, source: Path, text: str):
    if not IMPORT_HINT.search(text):
        return
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        # 解析できない文字列を実行可能な import と誤認しない。
        return
    for node in ast.walk(tree):
        for name in imported_modules(node):
            for module, package in MALICIOUS_IMPORTS.items():
                if name == module or name.startswith(module + "."):
                    if not local_module(root, source, module):
                        yield node.lineno, package


def is_documentation(path: Path) -> bool:
    return path.suffix.lower() in DOC_SUFFIXES or path.name.lower().startswith("readme")


def is_download_link(evidence: str, url: str) -> bool:
    for link in MARKDOWN_LINK.finditer(normalize_defanged(evidence)):
        target = link.group("target")
        if target in {url, url.removeprefix("https://")} and DOWNLOAD_LABEL.search(link.group("label")):
            return True
    return False


def is_comment(path: Path, evidence: str, url: str) -> bool:
    if evidence.startswith(COMMENT_START):
        return True
    if path.suffix.lower() not in C_STYLE_SUFFIXES:
        return False
    for match in C_STYLE_TOKENS.finditer(evidence):
        marker = match.group("comment")
        if marker is None:
            continue
        comment = evidence[match.end():]
        if marker == "/*":
            comment = comment.partition("*/")[0]
        if url in normalize_defanged(comment):
            return True
        if marker == "//":
            return False
    return False


def is_shell_script(path: Path, text: str) -> bool:
    first_line = text.partition("\n")[0]
    return path.suffix.lower() in SHELL_SUFFIXES or bool(
        re.match(r"^#!.*[/\s](?:ba|z|k)?sh(?:\s|$)", first_line)
    )


def command_parts(tokens: list[str]) -> list[str]:
    if tokens and tokens[0] in {"sudo", "command"}:
        index = 1
        while index < len(tokens) and tokens[index] in {"-n", "--"}:
            index += 1
        return tokens[index:]
    return tokens


def shell_tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=False, punctuation_chars="|;&<>()")
    lexer.whitespace_split = True
    return list(lexer)


def is_remote_pipe(tokens: list[str], line: str) -> bool:
    if "://" not in line or "\\|" in line:
        return False
    try:
        pipe = tokens.index("|")
    except ValueError:
        return False
    before_pipe = tokens[:pipe]
    # if/while の条件に置かれたパイプも実行される。引用符内の語は含めない。
    if before_pipe and before_pipe[0] in {"if", "elif", "while", "until", "then", "do", "else"}:
        before_pipe = before_pipe[1:]
    download = command_parts(before_pipe)
    shell = command_parts(tokens[pipe + 1:])
    return bool(
        download and shell
        and Path(download[0]).name in {"curl", "wget"}
        and Path(shell[0]).name in {"bash", "sh", "zsh", "ksh"}
        and not any(token in {";", "&", "&&", "||"} for token in download)
        and any(re.fullmatch(r"https?://[^\s'\"]+", arg.strip("\"'")) for arg in download[1:])
    )


def remote_shell_lines(text: str, *, documentation: bool):
    """明示的なURLを使う単純なパイプを検出し、文字列やヒアドキュメントを除く。"""
    logical = ""
    start = 0
    heredocs = []
    for number, raw in enumerate(text.splitlines(), 1):
        if heredocs:
            strip_tabs, delimiter = heredocs[0]
            if (raw.lstrip("\t") if strip_tabs else raw) == delimiter:
                heredocs.pop(0)
            continue

        line = raw.strip()
        if not logical:
            start = number
        if documentation:
            line = line.lstrip("> ").removeprefix("$ ").strip("`")
        elif not logical and line.startswith("#"):
            continue
        if line.endswith("\\"):
            logical += line[:-1] + " "
            continue
        command = logical + line
        logical = ""
        if documentation and "|" not in command:
            continue
        try:
            if not documentation and ("'" in command or '"' in command):
                # 代入に続く引用符を含め、複数行の文字列をひとまとまりにする。
                shlex.split(command, comments=True)
            tokens = shell_tokens(command)
        except ValueError:
            if not documentation:
                if len(command) > 8192:
                    return
                logical = command + "\n"
            continue
        if not documentation:
            for operator, delimiter in zip(tokens, tokens[1:]):
                if operator != "<<":
                    continue
                value = delimiter.removeprefix("-").strip("\"'")
                if re.fullmatch(r"[A-Za-z_]\w*", value):
                    heredocs.append((delimiter.startswith("-"), value))
        if is_remote_pipe(tokens, command):
            yield start


class ProjectScanner(PocRepositoryScanner):
    """低確度の参考情報と、配布を止める検出を分ける。"""

    def _scan_indicators(self, repo_name: str, display_path: str, text: str) -> list[Finding]:
        path = Path(display_path)
        findings = super()._scan_indicators(repo_name, display_path, text)
        documentation = is_documentation(path)
        for index, finding in enumerate(findings):
            if finding.category != "shortened_url":
                continue
            evidence = finding.evidence.lstrip()
            reference = documentation or is_comment(path, evidence, finding.value)
            if reference and not is_download_link(evidence, finding.value):
                findings[index] = replace(finding, severity="INFO", category="shortened_url_reference")

        if path.suffix.lower() in {".py", ".pyw"}:
            for line, package in known_imports(self.root, path, text):
                rule = self.intel.rules.get(canonicalize_name(package))
                if rule is not None and rule.policy == "all_versions":
                    findings.append(Finding(
                        "MALICIOUS", "known_malicious_import", package, repo_name,
                        display_path, line, "Import of a published malicious package.", "",
                    ))

        if documentation or is_shell_script(path, text):
            category = "remote_shell_example" if documentation else "remote_shell_pipeline"
            severity = "INFO" if documentation else "SUSPICIOUS"
            for line in remote_shell_lines(text, documentation=documentation):
                findings.append(Finding(
                    severity, category, "", repo_name, display_path, line,
                    "An explicit remote URL is piped into a shell.", "",
                ))
        return findings

