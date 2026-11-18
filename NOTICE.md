# Third-party materials / 第三者由来の資料

- `sync-package` converts metadata from [OpenSSF Malicious Packages via OSV](https://google.github.io/osv.dev/data/) and optionally the [Datadog PyPI manifest](https://github.com/DataDog/malicious-software-packages-dataset) to a local CSV. Downloaded metadata retains its upstream [Apache License 2.0](scan_github_repository/vendor/LICENSE-APACHE-2.0) terms.
- `sync-package` はOpenSSFと、指定時にはDatadogのメタデータをローカルCSVに変換します。取得したデータには各出典のApache License 2.0が適用されます。
- The scanner and detector configuration in `scan_github_repository/vendor/` were adapted from Aramasa's `aramasa_core/poc/vendor/`.
- Other report references appear in the CSV's `sources` column. その他の報告元はCSVの `sources` 列を参照してください。

