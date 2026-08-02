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
- **Firefox**（ZAPが自分で起動するブラウザ。**必須**）。ZAPは Ajax Spider、Active Scan の
  DOM XSS ルール、Browser Based Authentication、client アドオンで Firefox を Selenium 経由で
  起動します。後述の Playwright の Chromium では代替できません。

  ```bash
  wget -O /tmp/firefox.tar.xz "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US"
  sudo tar -xJf /tmp/firefox.tar.xz -C /opt
  sudo ln -sf /opt/firefox/firefox /usr/local/bin/firefox
  ```

  `geckodriver` は ZAP の `webdriverlinux` アドオンが同梱するため、別途インストールは不要です。
  言語は `lang=en-US` のままで構いません（headlessで動かすためUIは誰も見ません）。
  **Ubuntu では `apt install firefox` を使わないでください** — 実体が snap への移行パッケージで、
  snap の confinement 下では geckodriver から起動できないことがあります。`firefox-esr` は Debian
  のパッケージで Ubuntu のアーカイブには存在しません。
- **Python 3.8+** とプラグインが使う Python ライブラリ。次でインストールします：

  ```bash
  python3 -m pip install --user --break-system-packages pyyaml requests playwright
  python3 -m playwright install chromium   # Playwright のブラウザ本体
  ```

  （PEP 668 の制約が無い環境では `--break-system-packages` は不要です。）

  ここで入るのは **Python版の Playwright** です（Node版の `npm i playwright` や Playwright MCP
  とは別物で、それらでは代替されません）。また `--user` でのインストール先は
  `~/.local/lib/pythonX.Y/site-packages` で、**診断対象リポジトリに `.venv` があると venv からは
  見えません**（venv は既定でユーザーsite-packagesを隠すため）。工程0の `playwright` チェックが
  **どのインタプリタで使えるか**まで報告し、工程4/6 はそれを使うので、どちらに入れても動きます。
- **診断対象のWebアプリケーション**がローカルで稼働していること。

### 追加依存の理由

`PyYAML` は `dast.yaml` の解析（必須）、`requests` は ZAP REST API の駆動と疎通確認（無い場合は
`urllib` に自動フォールバックするが推奨）、`playwright` は工程4/6 のブラウザ操作に使います
（Playwright が無ければ工程4は fail-soft でスキップされます）。これ以外のサードパーティ依存は
ありません。

### ブラウザが2種類必要な理由

紛らわしい点なので明示します。**用途が違うため両方必要**で、片方でもう片方を代替できません。

| ブラウザ | 誰が起動するか | 使われる場面 |
| --- | --- | --- |
| **Firefox**（システムにインストール） | **ZAP** が Selenium 経由で起動 | Ajax Spider、Active Scan の DOM XSS ルール、Browser Based Authentication（認証の primary 方式）、client アドオン |
| **Chromium**（Playwright管理） | **プラグイン**が Playwright 経由で起動 | 工程4（カバレッジ補完）、工程6（シナリオ診断のブラウザ操作） |

ZAPは自前のプロセスからブラウザを起動するため、`~/.cache/ms-playwright` にある Chromium は
参照しません。Firefox が無い状態でも工程0〜工程3のSpiderまでは進むため、**Ajax Spider に到達して
初めて Selenium の例外で失敗**します。さらに **Active Scan の DOM XSS ルールは警告ログを残すだけで
黙ってスキップ**され、レポート上は「Active Scan 実行済み」と見えてしまいます。このため
`check_environment.py`（工程0）が Firefox の有無を前提条件として検査します。

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

（CLI での同等コマンド：`claude plugin install llm-zap-dast@shibasaki-security-tools`）

### インストールスコープ（ユーザー単位／プロジェクト単位）

インストール時に次の3スコープから選べます（**既定はユーザー単位**）。

| スコープ | 範囲 | 保存先 | 共有 |
| --- | --- | --- | --- |
| **User**（既定） | 自分の全プロジェクト | ユーザー設定（`~/.claude`） | されない |
| **Project** | このリポジトリの全共同作業者 | リポジトリの `.claude/settings.json` | される |
| **Local** | このリポジトリで自分だけ | `.claude/settings.local.json`（個人用） | されない |

CLI でスコープを指定する例：

```bash
claude plugin install llm-zap-dast@shibasaki-security-tools --scope local
```

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
提案します。安全既定（`allow_production: false` / ローカル限定）は生成物でも維持されます
（`active_scan` は既定ON。ただし実行時は工程5のゲート＋明示確認が必須です）。

```yaml
target:
  base_url: http://localhost:3000
  allowed_hosts: [localhost, 127.0.0.1]
  source_roots: [src]
zap:
  api_url: http://localhost:8080
  api_key_env: ZAP_API_KEY        # 既定はキーなし。下記のルール参照
authentication:
  enabled: false                  # true で認証付きDAST（best-effort）
  method: auto                    # auto | browser | form | json | basic | script
  login_url: /login
  username_env: DAST_USERNAME     # 単一アカウント（従来どおり）
  password_env: DAST_PASSWORD
  # 複数アカウント（認可診断用）。同一ロール2=水平／異ロール=垂直／3=両方。値は環境変数名のみ。
  # users:
  #   - { label: alice, role: user,  username_env: DAST_ALICE_USER, password_env: DAST_ALICE_PASS }
  #   - { label: bob,   role: user,  username_env: DAST_BOB_USER,   password_env: DAST_BOB_PASS }
  #   - { label: admin, role: admin, username_env: DAST_ADMIN_USER, password_env: DAST_ADMIN_PASS }
  max_attempts: 3
  verification: { method: auto }  # 認証確認（差分でチェック）
  session_management: { method: auto }
  active_scan: true               # 認証付きActive Scanの追加ゲート（既定ON）
scan:
  spider: true
  ajax_spider: false
  playwright: true
  active_scan: true               # 既定ON。実行時は工程5のゲート＋明示確認が必須
  scenario_tests: true
  destructive: true               # 対象内部の破壊的検証（既定ON・使い捨てローカル前提）
  availability_impact: false      # DoS相当・可用性を損なう検証（別軸・既定OFF）
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
- **認証付きDAST（best-effort）。** `authentication.enabled: true` で、工程2.5がZAPの認証機能を
  使ってログインし、**差分で「本当に認証できたか」を確認**してから認証後の探索/スキャン/シナリオ
  診断に進みます。primary は ZAP Browser Based Authentication（要 ZAP 2.16.1+）、ZAPが扱えない
  ログインは Playwright を fallback。**任意アプリでの認証成功は保証しません**（失敗は成功と扱わず
  「未実施」と記録）。**認証情報は環境変数名のみ**を書き、値は成果物・ログに出しません。ZAP User に
  残る資格情報は run 後に削除します。**対象は原則、自分が所有する使い捨てのローカル脆弱アプリを想定
  しており、本番・現実の稼働アプリには向けません。** 認証付き Active Scan は `scan.active_scan` と
  `authentication.active_scan` の**両方 true ＋ 工程5の明示確認**で実行します。
- **複数アカウント（`authentication.users`）。** 認可系の診断範囲はアカウント構成で決まります。
  **同一ロール2**で水平IDOR・水平権限昇格・別人トークン、**異ロール（低権限＋管理者）**で垂直権限
  昇格の拒否確認、**3アカウント（同一ロール2＋管理者）**で両方が可能です。単一アカウントでは水平系は
  構造的に不可能なので「未実施」と記録します。`users` を書くと単一の `username_env`/`password_env` より
  優先されます（値は書かず環境変数名のみ）。ロール選定は対象に応じて LLM が行います。
- **破壊的検証（`scan.destructive`、既定ON）。** 対象が使い捨てのローカル脆弱アプリなので、対象アプリ
  **内部**の不可逆な状態変更（削除・更新・実際の権限昇格など）まで踏み込んで確認します。非ローカル対象＋
  `allow_production: false` では設定検証が**拒否**します（本番は構造的に破壊できない）。`false` にすると
  従来どおり検出止まり。**外部への副作用**（外部メール・課金・外部登録・実在内部インフラへの SSRF 等、
  サンドボックスの外に出る操作）は破壊フラグに関係なく**常に禁止**です。**可用性を損なう検証**（DoS相当）は
  別軸の `scan.availability_impact`（既定OFF）でのみ有効化します。

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
python3 plugins/llm-zap-dast/scripts/redact.py --fields user_password < some-zap-export.json > masked.json
python3 plugins/llm-zap-dast/scripts/zap_auth.py --config examples/dast.yaml detect-capabilities --json
```

## 安全対策

セキュリティ制御を最優先します：

- 診断対象は `allowed_hosts` のホストのみ。スコープはプロンプトだけでなく、run単位の
  **ZAP Context** で担保します。
- **Active Scan は既定ON**ですが、工程5のゲート（設定＋安全チェック）を満たし、**かつ**実行前に
  利用者の明示的な確認を取れた場合のみ実行します。無確認では走りません。このゲートは**ZAPの
  モードとは独立**です。
- ZAPは **Protectedモード**で動作。**ATTACKモードは禁止**で、設定検証で拒否します。
- **本番は既定で拒否**（`safety.allow_production: false`）。
- **キーなし＋非ローカルは拒否**。秘匿情報（Cookie/Authorization/トークン/JWT/PII）は既定で
  すべての成果物で**マスク**され、`--keep-raw` を付けない限り生データは残しません。
- **破壊は3軸で扱います**：対象アプリ内部の破壊（`scan.destructive`、既定ON・使い捨てローカル前提。
  非ローカルは検証で拒否）／可用性・DoS相当（`scan.availability_impact`、別軸・既定OFF）／
  サンドボックス外への副作用（外部メール・課金・外部登録・実在インフラへのSSRF等＝**常に禁止**、
  破壊フラグでも解禁されません）。

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
├── authentication.md      # 認証付きDAST時のみ（マスク済み）
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

## 対象外 / 制約

- **認証は best-effort。** 任意アプリでの認証成功は保証しません。MFA / SSO / OAuth / SAML /
  CAPTCHA は自動化対象外。認可系（水平IDOR・水平/垂直権限昇格）の実施可否は**アカウント構成に依存**
  します（`authentication.users`）。構成が足りないクラスは「未実施」として記録します（実装済みの
  ように扱いません）。
- **対象は使い捨てのローカル脆弱アプリを前提**。本番・現実の稼働アプリには向けません
  （ローカル限定レールで構造的に本番を拒否）。
- GUI / Web管理画面 / 外部データベース。
- 独自MCPサーバー / 複雑なサブエージェント。
- CI/CD統合 / 本番環境診断 / 自動更新。

これらは意図的に対象外です。
