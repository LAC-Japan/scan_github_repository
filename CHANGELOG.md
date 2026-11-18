# 変更履歴 / Changelog

## 0.4.2

- プロジェクトと主コマンドを `scan_github_repository` に改名し、CODE BLUE 2026 の発表との関係を日英READMEに記載しました。
- Renamed the project and primary command to `scan_github_repository` and documented its connection to CODE BLUE 2026 in both READMEs.

## 0.4.1

- `scan-directory` と `scan-clone` に任意のディレクトリ深さ上限を追加しました。上限による省略は検査未完了として扱います。
- Added an optional directory depth limit to both scan commands. Skipped paths mark the scan incomplete.

## 0.4.0

- 外部データの同梱を廃止し、`sync-package` でOpenSSFの情報を取得します。Datadogは任意で追加できます。
- 修正版直前のプレリリースを照合し、公式のPyPI配布物と同名の外部フォークを区別します。
- 条件式にある外部取得からシェルへのパイプも検出します。

### English

- Synchronize OpenSSF metadata with `sync-package`, optionally including Datadog. Release archives omit external data.
- Check prereleases before a fixed version and distinguish official PyPI artifacts from same-named external forks.
- Detect remote-to-shell pipelines within shell conditions.

## 0.3.1

- 複合条件内の固定バージョンを認識し、影響範囲と交差しない依存指定を除外します。
- 追加CSVによるバージョン限定から全バージョンへの拡大を抑え、競合をJSONに記録します。

### English

- Recognize pins in compound requirements and exclude requirements proven disjoint from affected ranges.
- Preserve version-limited rules when an extra CSV reports all versions and surface the conflict in JSON.

## 0.3.0

- 既知悪性パッケージのPython importを検出します。同梱実装と相対importを区別します。
- 短縮URLの重複を除去し、文書・コメントの参照先とダウンロード誘導を区別します。
- 外部URLからシェルへ直接渡す処理を検出し、文書内の例はINFOに分類します。
- ELF・PE・Mach-Oを形式別に報告します。既定でINFOは記録のみとなります。

### English

- Detect verified malicious Python imports and distinguish local or relative imports.
- Deduplicate shortened URLs and distinguish references from download links.
- Detect direct remote-to-shell pipelines and report documentation examples as INFO.
- Report ELF, PE, and Mach-O separately. The default policy now records INFO without blocking.
