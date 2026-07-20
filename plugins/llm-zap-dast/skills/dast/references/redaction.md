# マスク（redaction）とレポート衛生

## gitignore チェック（成果物を書く前に）

成果物には対象の通信が含まれます。`reports/dast/<run-id>/` へ書き出す前に：

1. 対象リポジトリの `.gitignore` に `reports/` と `.env` が含まれるか確認する。
2. 無ければ、追記する前に**利用者に確認する**。**同意なく `.gitignore` を編集しない。**
   判断は `run.log` に記録する。

## マスク（既定：マスクし、生を残さない）

- **既定でマスクして保存し、マスク前の生データは残さない。**
- エクスポートしたZAP JSON（アラート＋HTTP履歴）**全体**を、`scripts/redact.py` に1工程として
  通す。ヘッダ2種を消すだけでは不十分。
- 最低限マスクするもの：`Cookie` / `Authorization` / `Set-Cookie` ヘッダ、セッションID、CSRF
  トークン、JWT、既知のPIIパターン。**許可リスト方式**（残す項目を絞る）**と**、既知の秘匿
  パターンの除去を**併用**する。
- 生データの保持は `--keep-raw` を指定したときのみ。その場合は、成果物と `run.log` に「マスク前
  データを含む」旨の強い警告を残す。
- **秘匿情報を成果物へ平文で書かない。** 認証情報/トークンをログ・レポートへ出力しない。

## redact.py の使い方

```bash
# 標準入出力：
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/redact.py < zap-alerts.raw.json > zap-alerts.json
# またはファイル指定：
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/redact.py --in raw.json --out zap-alerts.json
```

このスクリプトはJSON構造全体を再帰的にマスクする：機微なヘッダ名、一般的な
トークン/JWT/セッションのパターン、PIIパターン（メール、長い秘匿文字列の総当たり）。マスクした値は
`***REDACTED:<kind>***` マーカーに置換され、値を漏らさずに構造と「存在した事実」を残す。

何らかの理由でマスクに失敗したら、**生データの書き出しにフォールバックしない** — その成果物に
ついては停止とみなし、失敗を記録する。
