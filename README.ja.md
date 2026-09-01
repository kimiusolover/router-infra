# router-infra

[English README](README.md)

Router OS 関連リポジトリで共有する CI、リリース方針、署名連携、SBOM、来歴記録のための基盤です。

このリポジトリはポリシーと再利用可能なワークフローを扱います。ファームウェア、パッケージレシピ、機種定義、秘密鍵は格納しません。各利用側リポジトリが自身のビルド・テストと責務を持ちます。

## 安全境界

`public_release` は共有 `release.yml` が実装する公開経路だけを保護します。GitHub の権限設定など、直接公開を防ぐ別の対策までは代替しません。詳細は [POLICY.ja.md](POLICY.ja.md) と `docs/integration.md` を参照してください。
