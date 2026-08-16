# CLAUDE.md — このリポジトリを改修するときの規約

このファイルは **llm-zap-dast プラグインを"開発・保守する"側**のためのメタ規約です。
**使い方・インストール・設定キーは `README.md`** を見てください（ここでは繰り返しません）。
利用者向け文言・レポートは**日本語**で書きます（機械的な文字列は原文のまま）。

## このリポジトリは何か

OWASP ZAP ＋ ソース解析 ＋ ブラウザ操作で **LLM 支援型グレーボックス DAST** を行う Claude Code
プラグインを開発・配布するリポジトリ。プラグイン本体は `plugins/llm-zap-dast/`
（マニフェストは `.claude-plugin/`、配布カタログは直下の `.claude-plugin/marketplace.json`）。

## ディレクトリ地図と「正典 / 非正典」

- **正典（挙動の真実はここ）**：`plugins/llm-zap-dast/skills/dast/` 配下 ——
  `SKILL.md`（工程フロー）／`references/`（詳細9本）／`scripts/`（Python）／`templates/`。
  ＋ `plugins/llm-zap-dast/scripts/` と `tests/`。
- **利用者向けミラー**：`README.md`（挙動を変えたらここも同期する。下記）。
- **非正典（歴史的な作業メモ。仕様として扱わない）**：リポジトリ直下の
  `llm-zap-dast-implementation-instructions.md` / `llm-zap-dast-v2-auth-plan.md` /
  `skill-improvement-proposal.md` / `認証の実装方法案*.md`。これらは `.gitignore` 済みで配布物には
  入らないが作業ツリーには残る。**古い方針（例：認証の best-effort）が書かれているので、参照・改修の
  根拠にしない。**

## 編集の分担（3レイヤ）

- **`SKILL.md` はフロー制御に徹する。** 大きな手順を展開しない。新しい詳細手順は `references/` に
  置き、SKILL からリンクする（SKILL 冒頭の設計宣言）。
- **`references/` が詳細の置き場**。トピックごとに権威ファイルを1つに保ち、内容を他所へコピーしない
  （二重管理は stale の元）。
- **`scripts/` は薄いラッパ。** 判断は LLM、スクリプトは ZAP API への反映のみ。**対象固有のログイン
  処理や方式をハードコードしない**（`authentication.md` の二層構造、`zap_auth.py` の docstring）。

## 壊してはいけない不変条件（緩める改修をしない）

- **安全の権威は `references/safety-policy.md`。** 破壊の3軸（8A 対象内部 / 8B 可用性 / 8C 外部副作用）
  と「停止 vs fail-soft スキップ」の線引きはここが正。**安全ゲートを緩める/迂回する改修はしない。**
- **認証は「できなければ停止」。** `authentication.enabled: true` は認証付きで診断する約束。認証できない
  と分かったら未認証へ degrade せず run を停止（`references/authentication.md`・`safety-policy.md`）。
- **秘匿情報を出力に出さない。** 資格情報は環境変数「名」からのみ読み値を印字しない、`clear-authentication`
  teardown 必須、`usersList` は平文パスワードを返すので必ずマスク（`redaction.md`／`safety-policy.md`）。

## ZAP 挙動は「実測してから書く」

ZAP のセッション/認証/検証まわりは推測やバイトコード読解ではなく**実機で1回測ってから**
references に書く。検証は形の違う対象を2つ以上で行う（トークン型だけだと層のバグが隠れる）。
測り方（測定ハーネスと opt-in 手順）は `tests/live/README.md`、実機で確認済みの罠は
`references/authentication.md`「実機で確認済みの落とし穴」と `references/zap-integration.md` に集約済み。

## 開発・リリース手順

- **ブランチを切らず `main` に直接コミット**（分割はコミット単位で）。
- テスト：オフラインは `python -m pytest tests/`。ZAP 挙動を触ったら `DAST_LIVE_ZAP` で opt-in の
  live テスト（`tests/live/`）。プラグイン構造を触ったら `claude plugin validate`。
- **配布はコミットSHA単位でキャッシュ**される。配布先へ反映するには
  `/plugin marketplace update shibasaki-security-tools` でカタログ更新→再取得（更新漏れだと古い版のまま）。

## 実行環境の前提

- スクリプト参照は必ず **`${CLAUDE_PLUGIN_ROOT}/scripts/`** 経由、パスをハードコードしない。`python3` で実行。
- **サードパーティ依存は pyyaml / requests / playwright のみ**（requests 無しは urllib フォールバック）。
  新たな依存を足さない。

## README との同期

`README.md` は利用者向けミラー。**挙動・設定・安全ルールを変えたら README も同じコミットで更新する。**
権威は常に `references/`（README ではなく）で、両者が食い違ったら references が正。
