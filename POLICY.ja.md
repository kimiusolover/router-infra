# router-infra の運用方針

[English README](README.md)

- 共有契約は宣言的な方針に限定し、機種事実・ファームウェア・秘密情報を含めません。
- レビューゲートは、受理された人間のレビューと対象・根拠のハッシュを結びます。後続の別バイト列を黙って承認しません。
- リリース検証は、完全な成果物一覧、SBOM、来歴、外部署名検証、リリースゲートを要求します。
- 収集ツールは明示された診断 JSON だけを局所処理し、デバイス操作、URL 取得、Issue 作成、修復、公開を行いません。
- bot 提案は二段階に分けます。第1段階は GitHub-hosted runner 上で `contents: read` の検証と patch/manifest artifact の作成だけを行います。第2段階は成功した `main` push の `workflow_run` だけを受け、artifact の SHA-256、base commit、適用可否、許可パスを再検証してから `bot/*` の PR を作成します。artifact 内のスクリプトや test-command は第2段階で実行しません。
- workflow、共有方針、ReviewGate、source-lock と各リポジトリが指定した保護パスは `needs-human-review` で停止し、PR を作成しません。bot は merge、タグ、署名、Release 公開、デバイス・ネットワーク操作を行いません。呼出側は PR 作成段階にだけ `contents: write` と `pull-requests: write` を与え、Ruleset で bot の push を `bot/*` に限定します。
