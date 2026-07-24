# LLM × OWASP ZAP DASTプラグイン 実装指示書

## 1. 目的

Claude Codeから利用できる、Webアプリケーション向けのDAST（動的アプリケーションセキュリティテスト）支援プラグインを作成してください。

利用者は、診断対象となる開発リポジトリでClaude Codeを起動し、プラグインのSkillを実行します。

利用イメージは次のとおりです。

```bash
cd target-application
claude
```

Claude Code上で次を実行します。

```text
/llm-zap-dast:dast
```

このSkillは、現在Claude Codeが開いているリポジトリを診断対象のソースコードとして扱い、ローカルで起動しているWebアプリケーションとOWASP ZAPを使ってDASTを進めます。

ソースコード解析を含むため、純粋なブラックボックスDASTではなく、**LLM支援型のグレーボックスDAST**という位置づけです。

ZAP、対象Webアプリケーション、Playwrightなど、診断に必要な実行環境は利用者側ですでに用意されている前提とします。

---

## 2. 配布方式

Claude CodeのPlugin Marketplaceを使用します。

マーケットプレイス定義とプラグイン本体は、**同じGitHubリポジトリ**に配置してください。マーケットプレイス用とプラグイン用のリポジトリは分割しないでください。

リポジトリ名は以下を想定します。

```text
llm-zap-dast
```

このリポジトリは、次の2つの役割を持ちます。

1. Plugin Marketplaceとしてプラグインを配布する
2. `llm-zap-dast`プラグイン本体を格納する

> **重要（相対パス配布の注意）**
> `marketplace.json`はプラグインを相対パス（`./plugins/llm-zap-dast`）で参照します。相対パス参照は、利用者がマーケットプレイスを**Gitソース（GitHubリポジトリ）として追加した場合にのみ解決**されます。`marketplace.json`のrawなダイレクトURLを直接指定して追加すると相対パスは解決に失敗します。READMEの登録手順は、必ずGitHubリポジトリを指定する形で記述してください。

---

## 3. 全体構成

以下を基本としたディレクトリ構成を作成してください。

```text
llm-zap-dast/
├── .claude-plugin/
│   └── marketplace.json
│
├── plugins/
│   └── llm-zap-dast/
│       ├── .claude-plugin/
│       │   └── plugin.json
│       │
│       ├── skills/
│       │   └── dast/
│       │       ├── SKILL.md
│       │       ├── references/
│       │       │   ├── methodology.md
│       │       │   ├── safety-policy.md
│       │       │   ├── source-analysis.md
│       │       │   ├── zap-integration.md
│       │       │   ├── scenario-testing.md
│       │       │   ├── redaction.md
│       │       │   └── report-format.md
│       │       └── templates/
│       │           ├── dast-config.example.yaml
│       │           ├── target-map.example.md
│       │           ├── scenario-list.example.md
│       │           └── report.example.md
│       │
│       └── scripts/
│           ├── check_environment.py
│           ├── validate_config.py
│           └── redact.py
│
├── examples/
│   └── dast.yaml
│
├── tests/
│   ├── test_marketplace.py
│   ├── test_plugin_structure.py
│   └── test_config_validation.py
│
├── README.md
├── LICENSE
└── .gitignore
```

初期実装では、サブエージェント、Hooks、MCPサーバーは必須としません。構成を必要以上に複雑にせず、まずSkillとして一連のDASTフローが実行できる状態を作ってください。

**成果物はプラグイン1つ・Skill1つに限定します。フェーズごとのSkill分割は行いません。**（分割は状態受け渡しの規約を自前で持つ必要が生じ、初期段階の「まず動く」を妨げます。工程ごとの見直し・部分実行は、後述のチェックポイント・フェーズ別成果物・引数で対応します。）

詳細な手順は`references/`へ、再現可能な機械的処理は`scripts/`へ分離し、`SKILL.md`本文はフロー制御に徹してください。SKILL.mdを巨大な一枚プロンプトにしないでください。

---

## 4. Marketplaceの実装

以下のファイルを作成してください。

```text
.claude-plugin/marketplace.json
```

このMarketplaceに、同じリポジトリ内の以下のプラグインを登録してください。

```text
./plugins/llm-zap-dast
```

Marketplace名は、プラグイン名と区別できる名称にしてください（例：`shinya-security-tools`）。

`marketplace.json`には少なくとも以下を含めてください。

- Marketplace名（`name`）
- 所有者情報（`owner`。**文字列ではなくオブジェクト**。例：`{ "name": "...", "email": "..." }`）
- 説明（`description`）
- プラグイン一覧（`plugins`配列）。各エントリに以下を含める。
  - プラグイン名（`name`）
  - プラグインの相対パス（`source`。例：`./plugins/llm-zap-dast`）
  - プラグインの説明（`description`）

`$schema`・`version`・`category`・`tags`などは任意で付与して構いません。JSONはClaude Codeの現在の公式仕様に適合させてください。**実装時に必ず公式ドキュメントを確認し、古い記事の形式をそのまま流用しないでください。**

---

## 5. Pluginの実装

以下のファイルを作成してください。

```text
plugins/llm-zap-dast/.claude-plugin/plugin.json
```

プラグイン名は`llm-zap-dast`とします。説明は、以下の目的が分かる内容にしてください。

```text
ソースコード解析、OWASP ZAP、ブラウザ操作を組み合わせて、
開発中のWebアプリケーションに対するDASTを支援するClaude Codeプラグイン
```

少なくとも以下を含めてください。

- `name`
- `description`
- `author`（**オブジェクト**）
- `repository`
- `license`

`author`・`owner`は文字列ではなくオブジェクト形式で記述してください。バージョンの扱いは現在の公式仕様を確認してください。開発初期にバージョン固定が更新を妨げる場合は、無理に固定バージョンを設定しないでください。

---

## 6. Skillの実装

以下にSkillを作成してください。

```text
plugins/llm-zap-dast/skills/dast/SKILL.md
```

利用者が実行するコマンドは以下です。

```text
/llm-zap-dast:dast
```

### コマンド名の決まり方

`/llm-zap-dast:dast`は「プラグイン名 : スキル名」です。プラグイン由来のSkillは名前空間が付与され、`/プラグイン名:スキル名`で呼び出されます。

このうち**スキル名`dast`は、スキルのディレクトリ名（`skills/dast/`）から決まります**。SKILL.mdのfrontmatterの`name`は表示ラベルであり、コマンド名を変えません（プラグイン直下のSKILL.mdのみ例外的に`name`がコマンド名になりますが、本構成はサブディレクトリに置くため該当しません）。コマンド名を変えたい場合はディレクトリ名を変更してください。

### 手動実行の強制

Skillは手動実行を基本とします。DASTは対象システムへ通信を行うため、Claudeが通常の会話中に自動判断で勝手に起動しないようにしてください。現行仕様に従い、frontmatterで以下を設定してください。

```yaml
disable-model-invocation: true
```

### 引数

Skillは引数を受け取れるようにし、`$ARGUMENTS`で扱ってください。少なくとも以下を想定します。

```text
/llm-zap-dast:dast
/llm-zap-dast:dast http://localhost:3000
/llm-zap-dast:dast --config dast.yaml
/llm-zap-dast:dast --only <step>
/llm-zap-dast:dast --from <step>
/llm-zap-dast:dast --keep-raw
```

- 位置引数（例：`http://localhost:3000`）は対象URLの上書き。
- `--config <path>`：設定ファイルの指定。
- `--only <step>`：指定した工程のみ実行。
- `--from <step>`：指定した工程から実行を再開。
- `--keep-raw`：後述のとおり、マスク前の生データを保持する（既定は保持しない）。

`--only` / `--from`は、Skillを分割せずに「一部だけ」「途中から」を実現するための手段です。

### チェックポイントと見直し

各工程の終了時にサマリを出力し、次工程へ進む前に確認を取れるようにしてください。特にActive Scanの直前では必ず確認を挟みます。工程ごとの成果物は`reports/dast/<run-id>/`へ個別ファイルとして残し、人間が工程単位で後から読み返せるようにします。

---

## 7. DASTの基本フロー

Skillは、安全確認（ステップ0）に続けて、7つの診断ステップを順に実行します。

### fail-softの原則

各ステップは、前提条件（ZAPへの接続、対象URLの疎通、必要な設定、Playwrightの有無など）を満たさない場合、**エラーで全体を停止させるのではなく、そのステップを安全にスキップ**してください。スキップした場合は、理由を実行ログ（`run.log`）とレポートの両方に明記します。これにより、ZAPやPlaywrightが未導入の環境でも、`/llm-zap-dast:dast`は最後まで（スキップ付きで）走り切ります。

ただし、**安全に関わる前提が満たせない場合（許可されていないホスト、設定不整合など）は、スキップではなく停止**してください。fail-softは「機能が欠けている」場合の挙動であり、「安全が担保できない」場合には適用しません。

---

### ステップ0：実行条件・安全確認

以下を確認してください。

- 現在の作業ディレクトリがGitリポジトリか
- 診断対象URL・診断対象ホスト
- ZAP APIの接続先、ZAPへ接続できるか
- 対象Webアプリケーションへ接続できるか
- Active Scanを実施してよい環境か
- 診断結果の保存先
- 認証が必要か（v1では認証は実行しないが、要否は記録する）
- 除外すべきURLや機能があるか

設定が不足している場合、推測でActive Scanを開始しないでください。不足項目を整理し、安全に関わる場合は診断を停止してください。

このステップでは、後述の`validate_config.py`と`check_environment.py`を呼び出し、その結果を判断の一次情報として使ってください。

---

### ステップ1：ソースコード解析

現在の開発リポジトリを解析し、以下を抽出してください。

- Webフレームワーク、アプリケーションの起動方法
- 画面URL、APIエンドポイント、HTTPメソッド、入力パラメータ
- フォーム、ファイルアップロード
- 認証処理、認可処理、セッション処理
- 管理者向け機能、外部通信、データベースアクセス
- セキュリティ上重要な処理

**ソースコードに存在する情報と、推測した情報を明確に分けてください。**

---

### ステップ2：診断対象マップ生成

ソースコード解析結果をもとに、診断対象マップを作成します。少なくとも以下を含めてください。

- URLまたはAPIエンドポイント、HTTPメソッド
- 認証要否、必要な権限
- 入力箇所、想定されるデータ形式
- セキュリティ上の注目点、想定脆弱性
- 診断優先度
- 情報の根拠（ソース由来か推測か）、未確認事項

成果物は`reports/dast/<run-id>/target-map.md`へ保存してください。

---

### ステップ3：ZAPによる初期探索

ZAPを使用して、以下を実行してください。

1. 対象URLをZAPへ登録する
2. **ZAP Contextを作成し、後述のスコープ制御を適用する**
3. Traditional Spiderを実行する
4. Passive Scanの完了を待つ
5. 必要に応じてAjax Spiderを実行する
6. ZAPが到達したURL・HTTP履歴・アラートを取得する

ZAP操作の実装方針は「11. ZAP連携の実装方針」に従ってください。

---

### ステップ4：Playwrightによる探索補完

まず、ソースコードから抽出したURLと、ZAPが実際に到達したURLを比較し、未到達箇所を分類してください（例：ログインが必要 / JavaScript操作が必要 / 特定の画面遷移が必要 / 特定のデータが必要 / 管理者権限が必要 / URLは存在するが未使用 / APIが画面から直接呼ばれない / クローラーでは到達困難）。この比較結果は`reports/dast/<run-id>/coverage-analysis.md`へ保存します。

次に、Playwrightまたは利用可能なブラウザ操作機能を使って、ZAPで未到達だった画面への遷移を試みます。**ブラウザ通信はZAP Proxyを経由させ、ZAPの履歴へ記録される構成を優先してください。**HTTPS対象では、ZAPのルートCAを信頼させるか、ブラウザ側で証明書エラーを無視する設定が必要になる点に留意してください（詳細は`references/zap-integration.md`に記載）。

対象とする操作：ログイン、メニュー操作、フォーム送信、JavaScriptで生成される画面、複数ステップの画面遷移、権限ごとの画面確認。

次の操作は自動実行しないでください：データの一括削除、ユーザー削除、パスワード変更、外部へのメール送信、課金処理、外部サービスへの登録、本番データの変更、その他復旧できない操作。

---

### ステップ5：Active Scan

Active Scanは、以下がすべて確認できた場合だけ実行してください。

- 診断対象が許可された環境である
- 対象ホストが許可リスト（`allowed_hosts`）に含まれる
- Active Scanが設定で明示的に有効（`scan.active_scan: true`）
- 危険なURLが除外されている
- 対象が本番環境ではない、または明確な許可がある

Active Scanを実行する前に、以下を表示し、利用者の確認を取ってください。

- 対象URL、対象ホスト、除外URL
- 使用するZAPポリシー
- 想定される影響

設定が曖昧な場合は、Passive Scanまでで停止してください。

> Active Scanのゲートは、ZAPの動作モード（後述のProtectedモード）とは**独立**した制御です。Protectedモードは「スコープ外を触らない」を守るだけで、スコープ内のActive Scanは許可します。したがって「スコープ内でもゲートを満たすまでActive ScanのAPIを呼ばない」という制御を、モードとは別に必ずかけてください。

---

### ステップ6：シナリオベース診断

ソースコード解析とZAPの履歴をもとに、ZAPの自動スキャンだけでは検出しにくい診断シナリオを作成し、ZAP・curl・Playwright等を使って追加検証します。

対象例：IDOR、水平/垂直権限昇格、認証回避、セッション管理不備、CSRF、業務ロジックの不備、パラメータ改ざん、Mass Assignment、HTTPメソッド変更、隠しパラメータ変更、ファイルアップロード制御、リダイレクト、APIの認可不足、レート制限不足。

各シナリオには以下を含めてください。

- シナリオID、対象機能、想定される脆弱性、根拠
- 前提条件、操作手順
- 期待される安全な挙動、脆弱だった場合の挙動
- 実行可否、実行結果、証拠、追加確認事項

破壊的なペイロードや、対象環境の可用性を損なう検証（DoS相当を含む）は実行しないでください。成果物は`reports/dast/<run-id>/scenarios.md`へ保存します。

---

### ステップ7：結果整理・レポート生成

ZAPのアラートとシナリオ診断結果を分析し、以下を明確に分けてください。

- ツールが検出した事実 / HTTP通信で確認できた事実 / ソースコードから確認できた事実 / LLMによる推測
- 再現できた脆弱性 / 再現できなかった指摘 / 誤検知の可能性がある指摘 / 人間による確認が必要な指摘

根拠のない断定はしないでください。分析結果は`reports/dast/<run-id>/findings.md`に整理し、最終レポートを`reports/dast/<run-id>/report.md`へ出力します。

レポートには以下を含めてください。

1. 診断概要
2. 対象情報
3. 実行日時
4. 使用したツール
5. 実行した診断工程（スキップした工程とその理由を含む）
6. 探索範囲
7. 未到達範囲
8. 検出結果一覧
9. 再現確認結果
10. 証拠
11. リスク説明
12. 修正案
13. 未確認事項
14. 診断上の制約
15. 免責事項

---

## 8. 対象リポジトリ側の設定ファイル

診断対象の開発リポジトリに、任意で以下の設定ファイルを置けるようにしてください。

```text
dast.yaml
```

サンプル形式は以下を基本としてください。

```yaml
target:
  base_url: http://localhost:3000

  allowed_hosts:
    - localhost
    - 127.0.0.1

  source_roots:
    - src

zap:
  api_url: http://localhost:8080

  # APIキーは既定では不要（キーなし運用）。
  # ただし zap.api_url または target.base_url のホストが
  # localhost / 127.0.0.1 / ::1 以外の場合、キーなし運用は拒否される。
  # キーを使う場合は、値そのものは書かず環境変数名を指定する。
  api_key_env: ZAP_API_KEY

# 認証は v1 では実行しない（器と方式定義のみ）。
# 将来（v2）の primary は ZAP Browser Based Authentication（要 ZAP 2.16.1+）。
# ZAP が対応できないログインフロー向けに Playwright ログインを fallback とする。
# （選定理由：ZAP ネイティブ認証は自動再認証を持つ。Playwright による手動認証
#   パターンは再認証をサポートしないため、長時間スキャンで不利。）
authentication:
  enabled: false
  method: browser        # browser | playwright（v2で使用。v1では無視）
  login_url: /login
  username_env: DAST_USERNAME
  password_env: DAST_PASSWORD

scan:
  spider: true
  ajax_spider: false
  playwright: true
  active_scan: false
  scenario_tests: true

safety:
  require_local_target: true
  allow_production: false

exclude:
  # 除外は Spider / Ajax Spider / Passive / Active / Playwright の全経路に適用する。
  paths:
    - /logout
    - /admin/delete-all
    - /api/reset

output:
  directory: reports/dast
```

設定値を固定でSkill内へ埋め込まないでください。認証情報そのものを設定ファイルへ書かず、環境変数名を指定する形式にしてください。

---

## 9. 初期実装（v1）の範囲

### 必須

- Marketplace構成 / Plugin構成
- `/llm-zap-dast:dast` Skill（単一Skill、手動実行、引数対応、fail-soft、チェックポイント）
- `dast.yaml`の読み込みと検証
- 実行環境の確認
- ソースコード解析手順・診断対象マップ生成手順
- ZAP初期探索手順（Spider / Ajax Spider / Passive / アラート取得）
- 未到達URLの比較手順、Playwrightによる探索補完手順
- ZAP Contextによるスコープ制御、Protectedモードの適用
- Active Scanの安全条件（既定OFF、ゲート）
- シナリオ診断手順
- 秘匿情報のマスク（redaction）
- レポートテンプレート・レポート生成
- README
- MarketplaceとPluginの検証方法、テスト

### v1では必須としない

- 認証（ログイン）機能の実装（**器と方式定義のみ置く**）
- 完全なGUI / Web管理画面 / 外部データベース
- 独自MCPサーバー / 複雑なサブエージェント構成
- CI/CDへの自動組み込み / 本番環境診断 / 自動更新機構
- あらゆる認証方式への対応 / すべてのZAP API操作の独自ラッパー
- 独自の脆弱性スキャナー実装

必要以上に作り込まないでください。

---

## 10. スクリプトの役割

`SKILL.md`本文（LLMの判断）と、スクリプト（機械的処理）を分離してください。以下を実装します。

### `check_environment.py`

以下を確認します。

- Pythonバージョン
- Gitリポジトリか
- 設定ファイルの存在
- 対象URLへの接続
- ZAP APIへの接続
- 必要な環境変数（キー運用時のみ）
- 出力先へ書き込めるか
- **ZAPが実際にローカルにバインドされているか**（設定文字列が`localhost`でも、ZAPが`0.0.0.0`で全開放されているケースを検知する）

結果を人間が読める形式とJSON形式の両方で出力できるようにしてください。

### `validate_config.py`

以下を検証します。

- YAMLとして読み込めるか
- 必須項目が存在するか
- URL形式が正しいか
- `base_url`のホストが`allowed_hosts`に含まれるか
- **APIキーが無い場合、`zap.api_url`と`target.base_url`のホストが`localhost` / `127.0.0.1` / `::1`のいずれかであること**（非ローカルが指定されていればキーなし運用を拒否する）
- `allow_production: false`の場合に外部ホストが指定されていないか
- Active Scan有効時に安全設定が不足していないか
- ZAPモードに`ATTACK`（または相当の設定）が指定されていないか（Active Scanゲートを迂回するため拒否する）
- 認証有効時に環境変数名が指定されているか（v1では認証は実行しないが、設定の整合は検証する）
- 除外パスが絶対URLではなく意図した形式か

### `redact.py`

ZAPからエクスポートしたJSON（アラート・HTTP履歴）**全体**に対する秘匿情報マスクを行います。詳細は「12. レポートと秘匿情報」を参照してください。

外部ライブラリを追加する場合は、追加理由をREADMEへ記載してください（想定される依存：`PyYAML`、`requests` 程度）。

---

## 11. ZAP連携の実装方針

- **既定はZAP REST APIをprimaryとします。**ZAPをデーモンモード（`-daemon`）で起動し、`http://<host>:<port>/JSON/...`へAPIキー付き（またはキーなし）のHTTPリクエストを送る方式です。CLIやデスクトップGUIの有無・バージョン差に影響されにくく、再現性が高いためです。
- **フロー制御・JSON処理・redactionはPythonに寄せてください（`requests`を使用）。**Spider完了のポーリング、進捗の待ち合わせ、到達URLとソース抽出URLの突合、run-idごとのファイル出力、マスク処理などはPythonで実装します。
- `zaproxy` Pythonパッケージや ZAP MCP は、環境に応じた薄いフォールバックにとどめます。
- **curlは、単発の疎通確認の手動例としてREADMEおよび`references/zap-integration.md`に掲載する程度**にしてください（フロー全体をcurl＋jqで組まない）。
- 実行方法を場当たり的に変更せず、採用した方法と理由を`run.log`へ残してください。

### ZAP動作モード

- **既定はProtectedモード**とします。Protectedモードでは、スパイダー巡回・アクティブスキャン・ファジング・強制ブラウズ・リクエスト改変再送などの攻撃的操作が、**スコープ外URLに対しては行われません**。
- **ATTACKモードは使用しないでください。**ATTACKモードはスコープ内の新規ノードを発見と同時にアクティブスキャンするため、Active Scanゲートと衝突します。
- モードは万能ではなく、API経由の操作に対する強制はZAPのバージョンにより差があり得ます。したがって**実際の境界はZAP Contextのスコープと「スコープ外URLをそもそも叩かない」実装で担保**し、Protectedモードはその上に重ねる防御層と位置づけてください。v1の動作確認時に、Protectedモードが実際にAPI操作を制約するかを一度確認してください。

### スコープ制御（ZAP Context）

- run単位でZAP Contextを作成し、**include正規表現を`allowed_hosts`に限定**します。out-of-scopeはスキャンしない設定にし、Spiderがリンクをたどって別ホストへ出ても対象化しないようにします。
- `exclude.paths`は、**Spider / Ajax Spider / Passive / Active / Playwright操作のすべて**に効かせてください。特に`/logout`はGETで到達し得るため、Spiderからの除外も必須です。
- `validate_config.py`の設定チェックは入口の一次防御として残し、ZAP Contextは実行時の実境界として二重にかけます。

---

## 12. レポートと秘匿情報

### 保存構成

実行単位で以下の構成にしてください。

```text
reports/
└── dast/
    └── <run-id>/
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

`run-id`は、日時と短い識別子を使って重複しにくくしてください（例：`20260720-143000-a1b2c3`）。

### 出力先とgitignore

成果物は**対象リポジトリ内の`reports/dast/<run-id>/`**へ出力します。成果物には診断対象の通信内容が含まれるため、書き出す前に、対象リポジトリの`.gitignore`に`reports/`と`.env`が含まれているかを確認し、**含まれていなければ利用者に確認したうえで追記**してください。**無断で`.gitignore`を書き換えないでください。**

### 秘匿情報のマスク（redaction）

- **既定でマスクして保存し、マスク前の生データは残しません。**
- ZAPからエクスポートしたJSON（アラート・HTTP履歴）**全体**に対して、`redact.py`によるマスク処理を1工程として通してください。ヘッダ2種を消すだけでは不十分です。
- マスク対象には少なくとも次を含めます：`Cookie` / `Authorization` / `Set-Cookie`ヘッダ、セッションID、CSRFトークン、JWT、および既知のPIIパターン。許可リスト方式（残す項目を絞る）と、既知の秘匿パターンの除去を併用してください。
- `--keep-raw`が指定された場合のみ生データを保持できます。その場合は、成果物および`run.log`に「マスク前データを含む」旨の警告を残してください。
- **秘匿情報を成果物へ平文で保存しないでください。**認証情報やトークンをログ・レポートへ出力しないでください。

---

## 13. 安全要件

本プラグインはセキュリティ診断を行うため、安全制御を最優先します。以下を実装・明記してください。

- 許可されたホスト（`allowed_hosts`）以外を診断しない
- URLから対象範囲を自動で拡大しない、外部リンクを診断対象に追加しない（**ZAP Contextのスコープで担保**）
- Active Scanは設定で明示的に有効化し、実行前に確認を取る（**モードとは独立のゲート**）
- ZAPは既定でProtectedモード、ATTACKモードは使用しない
- 本番環境はデフォルトで拒否する
- APIキーが無い場合、ZAP接続先・診断対象が非ローカルなら実行を拒否する
- 認証情報をログやレポートへ出力しない、Cookie/Authorization/トークン/PIIをマスクする
- 破壊的な操作・DoSに相当する診断・ファイル削除・ユーザー削除を行わない
- 診断対象外のホストへペイロードを送信しない
- 推測と確認済み事実を分離する

Skillの指示だけでなく、可能な範囲で`validate_config.py` / `check_environment.py` / `redact.py`にも安全制御を実装してください。

---

## 14. READMEに記載する内容

### 概要

このプラグインが何をするものか、ZAP単体との違い、そしてLLM・ZAP・Playwrightそれぞれの担当範囲。

### 前提条件

Claude Code、OWASP ZAP、Python、診断対象Webアプリケーション、必要に応じてPlaywright。

### Marketplaceの登録

GitHubリポジトリからMarketplaceを登録するコマンドを記載してください。**相対パス参照のため、rawなダイレクトURLではなくGitHubリポジトリを指定する必要がある点を明記してください。**

### Pluginのインストール

Marketplaceからプラグインをインストールするコマンド（`<plugin-name>@<marketplace-name>`形式）を記載してください。

### Skillの実行

```text
/llm-zap-dast:dast
```

引数（`--config` / `--only` / `--from` / `--keep-raw`、位置引数の対象URL）の説明も記載してください。

### 設定ファイル

`dast.yaml`の例と各項目の説明。特に、APIキーなし運用時のローカル限定条件、除外パスが全経路に効くこと、認証はv1未実装であることを明記してください。

### ローカル開発

ローカルプラグインを読み込んでテストする手順を記載してください（コマンドは現在の公式仕様を確認して記述）。例：

```bash
claude --plugin-dir ./plugins/llm-zap-dast
```

### 検証

MarketplaceおよびPluginの構造を検証する方法を、現在の公式仕様を確認して記述してください。

### 安全上の注意

許可のないシステムを診断しないことを明記してください。

### 未実装機能の扱い

認証など、v1で未実装の機能を実装済みのように記載しないでください。

---

## 15. テスト

外部の本物のWebサーバーやZAPを必須とせず、通信部分はモックまたはローカルの簡易HTTPサーバーで確認できるようにしてください。少なくとも以下をテストします。

### Marketplaceテスト

- `marketplace.json`がJSONとして正しい
- 必須項目が存在する
- プラグインの相対パスが存在する

### Plugin構造テスト

- `plugin.json`が存在する
- `SKILL.md`が存在する
- プラグイン名が一致している
- Skillのディレクトリ構成が正しい

### 設定検証テスト

- 正常な設定が成功する
- 必須項目不足で失敗する
- 許可されていないホストで失敗する
- APIキーなし＋非ローカルホスト指定で失敗する
- Active Scanの安全条件不足で失敗する
- ZAPモードにATTACKが指定されていると失敗する
- 認証用環境変数名不足（認証有効時）で失敗する
- 不正なURLで失敗する

---

## 16. 実装の進め方

以下の順序で進めてください。各工程で、作成した内容と判断理由を簡潔に説明してください。

1. Claude Codeの現在の公式Plugin / Marketplace / Skill仕様を確認する
2. 実装計画を作成する
3. ディレクトリ構成を作成する
4. `marketplace.json`を作成する
5. `plugin.json`を作成する
6. `SKILL.md`を作成する
7. referenceファイルを作成する
8. テンプレートを作成する
9. `validate_config.py` / `check_environment.py` / `redact.py`を作成する
10. テストを作成する
11. READMEを作成する
12. ローカルでPluginを読み込んで検証する
13. Marketplaceとして検証する
14. 問題があれば修正する

---

## 17. 実装上の原則

- 公式ドキュメントを優先する。古い記事だけを根拠に実装しない
- 不明なPlugin仕様を推測しない
- 初期段階で過剰設計しない
- Skillを巨大な一枚プロンプトにしない。詳細は`references/`へ、再現可能な処理は`scripts/`へ分離する
- LLMの判断と機械的処理を分離する
- 対象固有情報をPluginへ固定しない
- Windows / WSL / Linuxでパスが異なることを考慮する。**特にWSLからWindowsホスト上のZAPへは`localhost`で到達できないため、`check_environment.py`は接続失敗時に原因が分かるメッセージを出し、READMEにもこの注意を記載する**
- シークレットをリポジトリへ保存しない。`.env`、レポート、ZAPセッションを適切に`.gitignore`へ追加する
- エラーを握り潰さない。実行失敗時に原因が分かるメッセージを出す
- 未実装機能を実装済みのようにREADMEへ書かない

---

## 18. 完了条件

以下をすべて満たしたら、初期実装完了とします。

1. リポジトリをClaude CodeのMarketplaceとして登録できる
2. Marketplaceから`llm-zap-dast`プラグインをインストールできる
3. 任意のGitリポジトリでClaude Codeを起動できる
4. `/llm-zap-dast:dast`が表示される
5. Skillを手動実行できる
6. `dast.yaml`を読み取れる
7. 設定不備を安全に検出できる（非ローカル＋キーなし、ATTACKモード指定などを含む）
8. ソースコード解析から診断対象マップを作成できる
9. ZAP接続前の環境確認ができる
10. ZAPが既定でProtectedモードになり、Active Scanがデフォルトで無効になっている
11. 許可されていないホストへの診断を拒否できる
12. ZAPやPlaywrightが未導入でも、該当工程をスキップして最後まで走り切る（fail-soft）
13. `reports/dast/<run-id>/`へ成果物を作成し、秘匿情報がマスクされている
14. テストが成功する
15. READMEの手順だけで導入と実行方法を理解できる

---

## 19. 最初の応答

すぐにファイル作成を始める前に、以下を提示してください。

1. 現在のリポジトリ状態の確認結果
2. 参照したClaude Code公式仕様
3. 実装予定のディレクトリ構成
4. 実装を何段階に分けるか
5. 初期実装に含めるもの / 除外するもの
6. 主な安全対策
7. 想定される技術的な不明点

その後、実装を開始してください。
