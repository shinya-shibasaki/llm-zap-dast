# CLAUDE.md — このリポジトリを改修するときの規約

このファイルは **llm-zap-dast プラグインを"開発・保守する"側**のためのメタ規約です。
**使い方・インストール・設定キーは `README.md`** を見てください（ここでは繰り返しません）。
利用者向け文言・レポートは**日本語**で書きます（機械的な文字列は原文のまま）。

## このリポジトリは何か

LLM 支援型のセキュリティ診断を行う Claude Code プラグインを開発・配布するリポジトリ。Skill は2本：
**`dast`**（OWASP ZAP ＋ ソース解析 ＋ ブラウザ操作でグレーボックス DAST）と
**`sast`**（OWASP ASVS 5.0 基準・攻撃マップを分母にした静的診断。semgrep ＋ LLM 精読、独立3回＋統合）。
プラグイン本体は `plugins/llm-zap-dast/`（マニフェストは `.claude-plugin/`、配布カタログは直下の
`.claude-plugin/marketplace.json`）。**プラグイン名が `llm-zap-dast` なのは歴史的経緯**で、改名は
既存利用者の入れ直しを強いるため据え置いている。

## ディレクトリ地図と「正典 / 非正典」

- **正典（挙動の真実はここ）**：`plugins/llm-zap-dast/skills/<dast|sast>/` 配下 ——
  `SKILL.md`（工程フロー）／`references/`（dast は詳細9本、sast は6本）／`templates/`。
  ＋ `plugins/llm-zap-dast/references/`（全スキル共通の安全則）、`plugins/llm-zap-dast/scripts/`、
  `plugins/llm-zap-dast/standards/`（同梱の OWASP ASVS 5.0。ライセンスは `NOTICE`）、`tests/`。
- **利用者向けミラー**：`README.md`（挙動を変えたらここも同期する。下記）。
- **非正典（歴史的な作業メモ。仕様として扱わない）**：リポジトリ直下の
  `llm-zap-dast-implementation-instructions.md` / `llm-zap-dast-v2-auth-plan.md` /
  `skill-improvement-proposal.md` / `認証の実装方法案*.md`。これらは `.gitignore` 済みで配布物には
  入らないが作業ツリーには残る。**古い方針（例：認証の best-effort）が書かれているので、参照・改修の
  根拠にしない。**

## 編集の分担（3レイヤ）

- **`SKILL.md` はフロー制御に徹する。** 大きな手順を展開しない。新しい詳細手順は `references/` に
  置き、SKILL からリンクする（SKILL 冒頭の設計宣言）。**SKILL.md に安全則を書かない**（上記2層）。
- **SAST の方法論は設定に出さない。** 独立3回・ジェネラリスト方式・ASVS のレベル方針は
  `skills/sast/references/` が正典。「対象・環境ごとに変わる事実」だけを `sast.yaml` に置く。
  改修時はまず「これは対象ごとに変わる事実か、方法論か」を判定し、方法論なら設定項目を増やして
  回避しない。
- **SAST はサブエージェントに委譲する構成。** 実際に対象を読むのは子なので、**安全則を子へ届ける
  経路を壊さない**——`skills/sast/references/safety-policy.md` 冒頭の逐語「サブエージェント契約」
  ブロックと、各 reference 冒頭の「先に安全則を全文読め」の二重化がそれ。テストで守っている。
- **`references/` が詳細の置き場**。トピックごとに権威ファイルを1つに保ち、内容を他所へコピーしない
  （二重管理は stale の元）。
- **`scripts/` は薄いラッパ。** 判断は LLM、スクリプトは ZAP API への反映のみ。**対象固有のログイン
  処理や方式をハードコードしない**（`authentication.md` の二層構造、`zap_auth.py` の docstring）。

## 壊してはいけない不変条件（緩める改修をしない）

- **安全の権威は2層。** 共通＝`plugins/llm-zap-dast/references/safety-core.md`、スキル固有＝
  `skills/*/references/safety-policy.md`。**新しい安全事項は必ずどちらかに置き、帰属が曖昧なものは
  既定で共通側**（分担形の失敗モードは「どちらの担当でもないと双方が思う」こと）。**SKILL.md に安全則を
  書かない。** 各 SKILL.md は「共通 → 自スキル固有」の順で全文読ませる。
- **「停止 vs fail-soft スキップ」の線引きは `safety-core.md` が正**——設定が明示的に約束した結果の
  クラスが成立しないなら停止（認証・semgrep）、カバレッジが減るだけなら記録して続行（Firefox・Playwright）。
- **DAST 固有の安全は `skills/dast/references/safety-policy.md`。** 破壊の3軸（8A 対象内部 / 8B 可用性 /
  8C 外部副作用）はここが正。**安全ゲートを緩める/迂回する改修はしない**（これは両層に等しく掛かる）。
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
- テスト：日常は**オフライン** `python -m pytest tests/`（ZAP不要・速い）。**ZAP統合/認証層
  （`zap_auth.py` 等、ZAP の実挙動に影響する変更）を触ったときだけ** opt-in の live テストで実測する
  （`DAST_LIVE_ZAP=… python -m pytest tests/live`）。理由・回し方・2標的の使い分けは `tests/live/README.md`。
  ドキュメントや ZAP に触れない変更は live 不要。プラグイン構造を触ったら `claude plugin validate`。
- **配布はコミットSHA単位でキャッシュ**される。配布先へ反映するには
  `/plugin marketplace update shibasaki-security-tools` でカタログ更新→再取得（更新漏れだと古い版のまま）。

## 実行環境の前提

- スクリプト参照は必ず **`${CLAUDE_PLUGIN_ROOT}/scripts/`** 経由、パスをハードコードしない。`python3` で実行。
- **Python の import 依存は pyyaml / requests / playwright のみ**（requests 無しは urllib
  フォールバック）。新たな import 依存を足さない。
- **外部 CLI ツールは semgrep のみ**（SAST 専用）。ZAP と Firefox は DAST の実行環境であって Python
  依存ではない。**新たな外部ツールを足さない**——特に SCA 系（`npm audit`／`pip-audit`／`osv-scanner`）は
  依存解決で任意コード実行を起こしうるので、SAST の「実行しない」境界の外側。
- **semgrep の挙動も実測してから書く。** 通信・出力・走査範囲は 2026-08-19 に 1.163.0 で実測済み
  （ZAP をプロキシに立てて観測）。結果は `skills/sast/references/safety-policy.md` §3 と
  `profiling.md` に集約。推測で書き換えない。

## README との同期

`README.md` は利用者向けミラー。**挙動・設定・安全ルールを変えたら README も同じコミットで更新する。**
権威は常に `references/`（README ではなく）で、両者が食い違ったら references が正。
