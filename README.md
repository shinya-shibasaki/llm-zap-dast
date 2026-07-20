# llm-zap-dast

[Claude Code](https://code.claude.com) 向けの、LLM支援型**グレーボックスDAST**プラグインです。
作業中のアプリのソースコードを読み、その内容を手がかりに **OWASP ZAP** とブラウザ（Playwright）を
駆動して、稼働中のアプリケーションを動的に診断します。

診断対象アプリケーションのリポジトリ内で実行します：

```bash
cd target-application
claude
```

```text
/llm-zap-dast:dast
```

## 何をするものか（ZAP単体との違い）

- **ZAP単体**は稼働中アプリをブラックボックスでクロール・スキャンします。あなたのルート、認証
  モデル、隠しパラメータ、業務ロジックは知りません。
- **llm-zap-dast** はまず**ソースコード**を解析して診断対象マップ（エンドポイント、認証/認可、
  入力、管理者機能）を作り、ZAPが実際に到達した範囲と突き合わせ、ブラウザでカバレッジの穴を埋め、
  ZAPの自動スキャンが見逃す**シナリオ診断**（IDOR、権限昇格、認証回避、業務ロジック不備 …）を
  設計します。グレーボックスであり、人間のペンテスターの代替ではありません。

### 役割分担

| コンポーネント | 担当 |
| --- | --- |
| **LLM（Claude）** | ソース解析、診断対象マップ、カバレッジ分類、シナリオ設計、証拠の突き合わせ、レポート作成 |
| **OWASP ZAP** | プロキシ、Spider、Passive Scan、ゲート付きActive Scan、アラートエンジン、HTTP履歴 |
| **Playwright / ブラウザ** | ログイン必須 / JS描画 / 複数ステップ / 権限別の画面への到達（ZAP Proxy経由） |

## 前提条件

以下は利用者側で用意済みであることを前提とします：

- **Claude Code**（`/plugin` コマンドが使える新しめのバージョン）。
- **OWASP ZAP** がインストール済みであること。**手動での事前起動は任意**です — 未起動の場合、
  スキルが `zap.autostart`（既定 true）で `127.0.0.1` にローカルZAPを自動起動します（下記参照）。
  自分で起動しておく場合：`zap.sh -daemon -host 127.0.0.1 -port 8080`。
- **Python 3.8+** と `PyYAML`・`requests`（`pip install pyyaml requests`）。
- **診断対象のWebアプリケーション**がローカルで稼働していること。
- **Playwright**（任意。無ければPlaywright工程はスキップされる — fail-soft）。

### 追加依存の理由

`PyYAML` は `dast.yaml` の解析に、`requests` は ZAP REST API の駆動と疎通確認に使います
（`requests` が無い場合スクリプトはHTTPを `urllib` にフォールバックしますが、`requests` を推奨）。
これ以外のサードパーティ依存はありません。

## Marketplace の登録（GitHubから）

`marketplace.json` はプラグインを**相対パス**（`./plugins/llm-zap-dast`）で参照します。相対パスは
**マーケットプレイスをGitソースとして追加した場合にのみ解決**されます。**GitHubリポジトリ**を
追加してください。`marketplace.json` のrawなダイレクトURLを貼り付けると相対パスの解決に失敗します。

```text
/plugin marketplace add shinya-shibasaki/llm-zap-dast
```

（CLI での同等コマンド：`claude plugin marketplace add shinya-shibasaki/llm-zap-dast`）

## プラグインのインストール

```text
/plugin install llm-zap-dast@shibasaki-security-tools
```

形式は `<plugin-name>@<marketplace-name>` です。ここではマーケットプレイスが
`shibasaki-security-tools`、プラグインが `llm-zap-dast` です。

## Skill の実行

```text
/llm-zap-dast:dast
```

コマンド名は「プラグイン名 : スキル名」で、`dast` はスキルのディレクトリ（`skills/dast/`）から
決まります。この Skill は**手動実行のみ**（`disable-model-invocation: true`）です。DASTは対象へ
通信を行うため、Claude が会話の途中で自動起動することはありません。

### 引数

| 形式 | 意味 |
| --- | --- |
| `/llm-zap-dast:dast` | `dast.yaml` を使って工程0→7を実行 |
| `/llm-zap-dast:dast http://localhost:3000` | 位置引数のURLで `target.base_url` を上書き |
| `/llm-zap-dast:dast --config dast.yaml` | 設定ファイルを指定 |
| `/llm-zap-dast:dast --init` | リポジトリ解析から `dast.yaml` の下書きを生成（確認後に書き出し） |
| `/llm-zap-dast:dast --only <step>` | その工程（0–7）のみ実行 |
| `/llm-zap-dast:dast --from <step>` | その工程から工程7まで再開 |
| `/llm-zap-dast:dast --keep-raw` | マスク前の生データを保持（既定：保持しない） |

`--only` / `--from` は、Skillを分割せずに一部の再実行や途中再開を可能にします。工程0の安全ゲートは
常に最初に実行されます。

## 設定ファイル（`dast.yaml`）

`dast.yaml` を**診断対象リポジトリのルート**に置きます（任意。
[`examples/dast.yaml`](examples/dast.yaml) 参照）。値は実行時に読み込まれ、プラグインに固定
埋め込みされません。**認証情報をこのファイルに書かない** — 環境変数の「名前」を参照します。

**手で書くのが大変な場合は生成を支援できます。** `/llm-zap-dast:dast --init` を実行すると、Claude が
リポジトリを解析して `base_url`（検出したポート）、`source_roots`、破壊的エンドポイントの
`exclude.paths` 候補などを埋めた `dast.yaml` の下書きを作り、検証したうえで**確認後に書き出します**
（既存ファイルは無断上書きしません）。また `dast.yaml` が無い状態で普通に実行した場合も、生成を
提案します。安全既定（`active_scan: false` / `allow_production: false` / ローカル限定）は生成物でも
維持されます。

```yaml
target:
  base_url: http://localhost:3000
  allowed_hosts: [localhost, 127.0.0.1]
  source_roots: [src]
zap:
  api_url: http://localhost:8080
  api_key_env: ZAP_API_KEY        # 既定はキーなし。下記のルール参照
authentication:
  enabled: false                  # v1 は認証を実行しない（器のみ）
  method: browser
  login_url: /login
  username_env: DAST_USERNAME
  password_env: DAST_PASSWORD
scan:
  spider: true
  ajax_spider: false
  playwright: true
  active_scan: false              # 既定OFF。有効化しても工程5のゲートが必要
  scenario_tests: true
safety:
  require_local_target: true
  allow_production: false
exclude:
  paths: [/logout, /admin/delete-all, /api/reset]
output:
  directory: reports/dast
```

要点：

- **ZAPの自動起動（`zap.autostart`、既定 true）。** ZAPが未起動のとき、スキルがローカルZAPを
  `127.0.0.1` で自動起動します。既に起動済みのZAPがあればそれを使い、自動起動しません。ZAPが
  見つからない/起動に失敗した場合は、手動起動を案内してスキップします（fail-soft）。**スキルが
  起動したインスタンスだけ**を診断後に停止し、あなたが起動していたZAPには触れません。起動は必ず
  `127.0.0.1` に限定され、`start_command` で `0.0.0.0` バインドを指定しても拒否されます。無効化
  するには `zap.autostart: false`。任意で `zap.start_command` や `zap.docker` を指定できます。
  なお **WSLからWindows側のZAPは自動起動できません**（手動起動が必要）。
- **キーなしZAPはローカル限定。** `zap.api_url` または `target.base_url` のホストが
  `localhost` / `127.0.0.1` / `::1` 以外の場合、キーなし運用は**拒否**されます。キーを使うには
  `api_key_env` で指定した環境変数を設定します。
- **`exclude.paths` は全経路に適用**されます — Spider、Ajax Spider、Passive、Active、Playwright。
  `/logout` はGETで到達し得るため、除外が重要です。
- **認証はv1では未実装。** `authentication` ブロックは器と方式定義のみで、Skillは認証の要否を記録
  しますが、ログインは行いません。

## ローカル開発

インストールせずにプラグインを読み込みます：

```bash
claude --plugin-dir ./plugins/llm-zap-dast
```

編集後は Claude Code 内で `/reload-plugins` を実行すると変更が反映されます。

## 検証

組み込みのバリデータで Marketplace とプラグイン構造を検証します：

```bash
claude plugin validate .                        # marketplace.json ＋ ローカルプラグインのエントリ
claude plugin validate ./plugins/llm-zap-dast   # プラグインのマニフェストと構成要素
```

テストスイートを実行します（実物のZAPやWebサーバは不要 — ネットワーク部分は避けています）：

```bash
pip install pyyaml pytest
python -m pytest tests/
```

スクリプトを直接動かすこともできます：

```bash
python3 plugins/llm-zap-dast/scripts/validate_config.py --config examples/dast.yaml
python3 plugins/llm-zap-dast/scripts/check_environment.py --config examples/dast.yaml --json
python3 plugins/llm-zap-dast/scripts/redact.py < some-zap-export.json > masked.json
```

## 安全対策

セキュリティ制御を最優先します：

- 診断対象は `allowed_hosts` のホストのみ。スコープはプロンプトだけでなく、run単位の
  **ZAP Context** で担保します。
- **Active Scan は既定OFF**。設定＋安全チェックによるゲートで制御し、実行前に確認を取ります。
  このゲートは**ZAPのモードとは独立**です。
- ZAPは **Protectedモード**で動作。**ATTACKモードは禁止**で、設定検証で拒否します。
- **本番は既定で拒否**（`safety.allow_production: false`）。
- **キーなし＋非ローカルは拒否**。秘匿情報（Cookie/Authorization/トークン/JWT/PII）は既定で
  すべての成果物で**マスク**され、`--keep-raw` を付けない限り生データは残しません。
- 破壊的操作なし、DoS相当の検証なし。

**許可されたシステムのみを診断してください。** 自分が所有していない、または明示的な書面の許可が
ないホストに対して実行しないでください。

## 出力

成果物は対象リポジトリ内の `reports/dast/<run-id>/` に出力されます（既定でマスク済み）：

```text
reports/dast/<run-id>/
├── run.log
├── execution-summary.json
├── environment-check.json
├── target-map.md
├── coverage-analysis.md
├── zap-alerts.json        # マスク済み
├── scenarios.md
├── findings.md
└── report.md
```

書き出す前に、Skillは対象リポジトリの `.gitignore` が `reports/` と `.env` を無視しているか確認し、
無ければ追記前に確認します — 同意なく `.gitignore` を編集することはありません。

## WSL / ネットワークの注意

**WSLからは、Windowsホスト上のZAPへ `localhost` で到達できないことがあります。**
`check_environment.py` がZAPエンドポイント不達を報告したら、`localhost` の代わりにWindowsホストの
IP（WSLの既定ゲートウェイなど）を使うか、WSL内でZAPを起動してください。環境チェックは接続失敗時に
このヒントを表示します。

## v1では未実装

- 認証 / ログイン（器と方式定義のみ — 実行は**しない**）。
- GUI / Web管理画面 / 外部データベース。
- 独自MCPサーバー / 複雑なサブエージェント。
- CI/CD統合 / 本番環境診断 / 自動更新。

これらは初期バージョンでは意図的に対象外です。
