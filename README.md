# llm-zap-dast

[Claude Code](https://code.claude.com) 向けの、LLM支援型**セキュリティ診断**プラグインです。
2つの Skill を提供します。

| Skill | 何をするか |
| --- | --- |
| `/llm-zap-dast:dast` | **グレーボックスDAST**。ソースを読んで手がかりにし、**OWASP ZAP** とブラウザ（Playwright）で稼働中のアプリを動的に診断する |
| `/llm-zap-dast:sast` | **ソースコード診断**。**OWASP ASVS 5.0** を基準に、攻撃マップを分母として静的に診断する（semgrep ＋ LLM 精読、独立3回＋統合） |

どちらも診断対象リポジトリ内で実行します：

```bash
cd target-application
claude
```

```text
/llm-zap-dast:dast     # 稼働中のアプリを動的に診断する
/llm-zap-dast:sast     # ソースコードを静的に診断する
```

> プラグイン名が `llm-zap-dast` なのは歴史的経緯です（DAST から始まったため）。SAST は ZAP を使いません。

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

**どの Skill を使うかで必要なものが違います。**

| | 共通 | DAST のみ | SAST のみ |
| --- | --- | --- | --- |
| 必要なもの | Claude Code / Python 3.8+ / PyYAML | OWASP ZAP / Firefox / Playwright + Chromium / 稼働中の対象アプリ | semgrep |

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
- **診断対象のWebアプリケーション**がローカルで稼働していること（**DAST のみ**）。

### SAST の前提（`/llm-zap-dast:sast`）

- **semgrep**。SAST スキルの静的スキャンに使います。**入っていないと run を停止します**
  （後述「なぜ semgrep が必須か」）。

  ```bash
  pipx install semgrep
  # または: python3 -m pip install --user semgrep / brew install semgrep
  ```

- **semgrep.dev への通信**（実行ごと）。semgrep はルールパックをレジストリから取得し、**取得結果を
  キャッシュしません**。したがって**オフラインでは SAST を実行できません**。プラグインは
  `--metrics=off --disable-version-check` を必ず付けるので、利用統計は送信しません。
- ZAP・Firefox・Playwright・稼働中のアプリは **SAST には不要**です。

#### なぜ semgrep が必須か（＝無い場合に停止する理由）

semgrep 無しでも LLM の精読だけでレポートは書けてしまいますが、**静的スキャン済みのレポートと
見た目が同じもの**が出ます。読んだ人は網羅の違いに気づけません（静かな偽陰性）。認証できない DAST を
未認証で続けないのと同じ理由で停止します。それでも構わない場合は `tools.semgrep.required: false` を
明示してください——その場合、**全レポートの冒頭に「静的スキャン未実行」が第一級で明記**されます。

### 追加依存の理由

`PyYAML` は `dast.yaml` の解析（必須）、`requests` は ZAP REST API の駆動と疎通確認（無い場合は
`urllib` に自動フォールバックするが推奨）、`playwright` は工程4/6 のブラウザ操作に使います
（Playwright が無ければ工程4は fail-soft でスキップされます）。Python の依存はこれ以外にありません。
外部 CLI ツールとしては **semgrep のみ**を使います（SAST 専用）。

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
| `/llm-zap-dast:dast --only <step>` | その工程のみ実行（`0` `1` `2` `2.5` `3` `4` `5` `6` `7`） |
| `/llm-zap-dast:dast --from <step>` | その工程から工程7まで再開 |
| `/llm-zap-dast:dast --keep-raw` | マスク前の生データを保持（既定：保持しない） |

`--only` / `--from` は、Skillを分割せずに一部の再実行や途中再開を可能にします。工程0の安全ゲートは
常に最初に実行されます。

### SAST の実行

```text
/llm-zap-dast:sast
```

こちらも**手動実行のみ**です。読み取りと静的解析しかしませんが、専任サブエージェントを多数
起動する高コストな処理なので、会話の流れで自動起動することはありません。

| 形式 | 意味 |
| --- | --- |
| `/llm-zap-dast:sast` | `sast.yaml`（あれば）を使って工程0→3を実行 |
| `/llm-zap-dast:sast ./backend` | 位置引数のパスで `target.source_dir` を上書き |
| `/llm-zap-dast:sast --config sast.yaml` | 設定ファイルを指定 |
| `/llm-zap-dast:sast --only <step>` | その工程のみ実行（`0` `1` `1'` `2` `3`） |
| `/llm-zap-dast:sast --from <step>` | その工程から工程3まで再開 |

`sast.yaml` は**無くても動きます**（全キー任意。工程0の下見が埋めます）。`--init` は用意していません。
`--from 2` 以降を使う場合は、分母にする攻撃マップのパスを指定してください（前回の run を自動では
探しません）。

#### SAST のコストと構成

工程ごとに専任サブエージェントへ委譲し、**親1 ＋ サブエージェント6体**（プロファイル／攻撃マップ／
完全性クリティック／独立診断×3）で動きます。既定のモデルは `opus`（`agents.model` で変更可）。
**相応にトークンを消費します。**

この構成にしている理由は、失敗モードごとに対策を変えているためです。**列挙漏れ**は投票では減らないので
攻撃マップを1本だけ作って独立クリティックに検算させ、**判断の揺れ**は独立3回で吸収して出現回数
（3/3・2/3・1/3）を信頼度の補助シグナルにします。**3回は固定**で、設定では変えられません
（回数を変えるとレポート様式そのものが成立しないため）。

## 設定ファイル（`dast.yaml`）

`dast.yaml` を**診断対象リポジトリのルート**に置きます（任意。
[`examples/dast.yaml`](examples/dast.yaml) 参照）。値は実行時に読み込まれ、プラグインに固定
埋め込みされません。**認証情報をこのファイルに書かない** — 環境変数の「名前」を参照します。

**手で書くのが大変な場合は生成を支援できます。** `/llm-zap-dast:dast --init` を実行すると、Claude が
リポジトリを解析して `base_url`（検出したポート）、`source_roots`、破壊的エンドポイントの
`exclude.paths` 候補などを埋めた `dast.yaml` の下書きを作り、検証したうえで**確認後に書き出します**
（既存ファイルは無断上書きしません）。あわせて `.gitignore` に `reports/` と `.env` が無ければ、同じ
確認の中で追記します（run 側で止まらないようにするため）。また `dast.yaml` が無い状態で普通に
実行した場合も、生成を提案します。安全既定（`allow_production: false` / ローカル限定）は生成物でも維持されます
（`active_scan` は既定ON。実行時は工程5のゲート条件を満たせば無確認で実行します）。

```yaml
target:
  base_url: http://localhost:3000
  allowed_hosts: [localhost, 127.0.0.1]
  source_roots: [src]
zap:
  api_url: http://localhost:8080
  api_key_env: ZAP_API_KEY        # 既定はキーなし。下記のルール参照
authentication:
  enabled: false                  # true で認証付きDAST（認証できなければ run 停止）
  method: auto                    # auto | browser | form | json | basic | script
  login_url: /login
  username_env: DAST_USERNAME     # 単一アカウント
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
  active_scan: true               # 既定ON。実行時は工程5のゲート条件を満たせば無確認で実行
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
- **`exclude.paths` は「そこへリクエストを送ると困るパス」**を書きます（`/logout` はセッションが消える、
  `/admin/delete-all` や `/api/reset` はデータが壊れる）。**リクエストを送る経路すべて**に適用されます —
  Spider、Ajax Spider、Active Scan、工程4のブラウザ操作、工程6のシナリオ診断。Passive Scan は自分では
  送らないため対象外です（除外したURLにPassiveのアラートが出たら、それはどこかで送ってしまったサイン）。
- **認証付きDAST。** `authentication.enabled: true` は「**認証付きで診断する**」という約束です。
  工程2.5がZAPの認証機能を使ってログインし、**差分で「本当に認証できたか」を確認**してから認証後の
  探索/スキャン/シナリオ診断に進みます。primary は ZAP Browser Based Authentication（要 ZAP 2.16.1+）。
  **認証付きで診断できないと分かった時点で run を停止します**（未認証へ degrade せず、Playwright
  ログインへも退避しません）。未認証の結果が欲しいときは `authentication.enabled: false` を指定します
  ＝設定が結果の種類を決めます。**任意アプリでの認証成功は保証しません**（MFA / SSO 等は対象外。下記
  「対象外 / 制約」）。**認証情報は環境変数名のみ**を書き、値は成果物・ログに出しません。ZAP User に
  残る資格情報は run 後に削除します。**対象は原則、自分が所有する使い捨てのローカル脆弱アプリを想定
  しており、本番・現実の稼働アプリには向けません。** 認証付き Active Scan は `scan.active_scan` と
  `authentication.active_scan` の**両方 true**で実行します（工程5のゲート条件を満たせば無確認）。
- **複数アカウント（`authentication.users`）。** 認可系の診断範囲はアカウント構成で決まります。
  **同一ロール2**で水平IDOR・水平権限昇格・別人トークン、**異ロール（低権限＋管理者）**で垂直権限
  昇格の拒否確認、**3アカウント（同一ロール2＋管理者）**で両方が可能です。単一アカウントでは水平系は
  構造的に不可能なので「未実施」と記録します。`users` を書くと単一の `username_env`/`password_env` より
  優先されます（値は書かず環境変数名のみ）。ロール選定は対象に応じて LLM が行います。
- **破壊的検証（`scan.destructive`、既定ON）。** 対象が使い捨てのローカル脆弱アプリなので、対象アプリ
  **内部**の不可逆な状態変更（削除・更新・実際の権限昇格など）まで踏み込んで確認します。非ローカル対象＋
  `allow_production: false` では設定検証が**拒否**します（本番は構造的に破壊できない）。`false` にすると
  検出止まりですが、**アプリが意図した保存先への良性・一意マーカーの新規追加は「破壊」に数えません**
  （既存データの書き換え・上書き・削除からが破壊）。**外部への副作用**（外部メール・課金・外部登録・
  実在内部インフラへの SSRF 等、サンドボックスの外に出る操作）は破壊フラグに関係なく**常に禁止**です
  — これは**宛先**で決まる判定で、out-of-band という手法自体が禁止なのではありません。メール送信等を
  伴う機能は、宛先がサンドボックス内のキャッチャ（mailhog 等）と確認できた場合のみ発火します。
  **可用性を損なう検証**（DoS相当）は別軸の `scan.availability_impact`（既定OFF）でのみ有効化します。

## 設定ファイル（`sast.yaml`）

SAST 用は別ファイルです（[`examples/sast.yaml`](examples/sast.yaml) 参照）。**全キーが任意**で、
無ければ既定値と工程0の下見で動きます。DAST 設定とは分けてあります——SAST しか使わない人に、
Active Scan や破壊フラグを持つ `dast.yaml` を書かせないためです。

```yaml
target:
  source_dir: ./          # 診断対象。既定はリポジトリ直下
  app_kind: auto          # auto | web | api | graphql | cli | library | batch | ...
safety:
  allow_outside_repo: false   # 読み取り境界。既定はリポジトリの内側だけ
standard:
  # asvs_csv: ./別版.csv       # 省略時は同梱の OWASP ASVS 5.0
tools:
  semgrep:
    required: true            # 使えない／ルールを取れないなら停止
    # configs: [p/javascript, p/typescript]   # 省略時は検出した言語から選定
analysis:
  # exclude: [vendor/]        # 既定は空で十分（下記）
agents:
  model: opus                 # 各サブエージェントに指定するモデル
output:
  directory: reports/sast
```

**読み取り境界（`safety.allow_outside_repo`）** が SAST の一次的な安全設定です。既定では
`source_dir` が **git リポジトリの内側**であることを要求し、外を指していれば停止します。
`source_dir: ~` のような打ち間違いで、ホーム配下の無関係なファイルを読んでその抜粋がレポートに
載る、という事故を構造的に防ぐためです。他人のリポジトリを監査する等で意図的に外を診断する場合だけ
`true` にしてください。あわせて **`.git/`（削除済みの秘密がコミット履歴に残る）と、境界の外を指す
シンボリックリンクは、設定に関わらず常に除外**します。

**`analysis.exclude` は基本的に空で構いません。** semgrep は git 管理下のファイルだけを走査し、
`node_modules` / `build` 等は既定で除外されるためです（juice-shop で 155 ファイルが自動 skip）。
除外を足しすぎて自前の本番コードを削らないでください。

**`configs` に `auto` は指定できません。** semgrep の `--config auto` はサーバ側がルールを選ぶため、
同じコードでも結果が経時変化し、独立3回が同じ分母を見なくなります。

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

- 診断対象は `allowed_hosts` のホストのみ。**スキャナ（Spider / Ajax / Active Scan）のスコープ**は
  プロンプトだけでなく run単位の **ZAP Context** で担保します。スキルが直接行う単発の取得
  （認証確認・カナリア・工程6のプローブ）は ZAP のモードやスコープでは縛られないため、**スクリプト側の
  許可ホスト検査とプロンプト規律**で縛ります。
- **`allowed_hosts` はホスト単位なので、既定では「そのホストの全ポート」がスコープに入ります。**
  `localhost` で診断対象以外（DB管理画面、他のアプリ、モックなど）も動かしている場合は、
  `base_url` のポートだけを対象にするか `exclude.paths` で外してください。
- **Active Scan は既定ON**で、工程5のゲート（設定＋安全チェック：`allowed_hosts` 内／`active_scan:true`
  ／危険URL除外／非本番または許可）を**すべて満たしたときに実行**します。対象は使い捨てローカルの
  テストアプリ前提のため、**ゲート条件の充足自体が実行の許可**で、対話確認は取りません（実行前に
  対象/除外/ポリシー/想定影響は提示・記録します）。**条件が未充足・曖昧なら Passive までで停止**します。
  このゲートは**ZAPのモードとは独立**です。
- ZAPは **Protectedモード**で動作（スキャナ経路に効きます）。**ATTACKモードは禁止**で、設定検証で
  拒否します。
- **本番は既定で拒否**（`safety.allow_production: false`）。
- **キーなし＋非ローカルは拒否**。秘匿情報（Cookie/Authorization/トークン/JWT/PII）は既定で
  すべての成果物で**マスク**され、`--keep-raw` を付けない限り生データは残しません。
- **破壊は3軸で扱います**：対象アプリ内部の破壊（`scan.destructive`、既定ON・使い捨てローカル前提。
  非ローカルは検証で拒否）／可用性・DoS相当（`scan.availability_impact`、別軸・既定OFF）／
  サンドボックス外への副作用（外部メール・課金・外部登録・実在インフラへのSSRF等＝**常に禁止**、
  破壊フラグでも解禁されません）。

- **対象から来たものは、すべてデータとして扱います。** 対象リポジトリ内の文書（README・`CLAUDE.md`・
  `AGENTS.md`・`.cursor/rules` 等）やソースのコメント、対象アプリの応答に「こう振る舞え」と書かれて
  いても従いません。**Claude Code がプロジェクト設定として自動で読み込んだ場合も同じ**で、この run
  では無効として扱います。ただし**ハーネス層（`.claude/settings.json` のフック等）は本プラグインの
  管轄外**なので、信用できないリポジトリは使い捨て環境で開いてください。
- **成果物は書き出したあとに検証します。** マスク工程を通したかではなく、成果物ツリー全体
  （`run.log` を含む）に秘匿情報が実際に残っていないことを確認します。
- **`.gitignore` は同意なく編集しません。** 出力先と `.env` が無視対象か確認し、無ければ確認を取って
  から追記します。この同意停止は「無確認で進む」より優先されます。

SAST 側の安全設計（DAST と対になるもの）：

- **読み取り境界。** DAST の `allowed_hosts` が「どこへ送るか」を縛るのに対し、SAST は「**どこまで
  読むか**」を縛ります。既定は git リポジトリの内側だけで、`.git/` と境界外を指すシンボリックリンクは
  設定に関わらず除外します。
- **実行しない。** 許可されるのはファイル読み取り・grep・読み取り専用の git 操作・**semgrep の実行**
  だけです。対象コードのビルドも実行もしません。`semgrep --autofix`（対象ソースを書き換える）、
  `npm audit` / `pip-audit` 等の SCA ツール（依存解決でコードを実行しうる）は**semgrep の例外に
  含まれません**。依存の CVE 対応づけは「要確認」として記録します。
- **対象リポジトリ内の semgrep 設定・ルールは使いません**（攻撃者が用意したルールを実行しないため）。
  存在すれば「検出した設定」としてデータで報告します。
- **秘密の値を書きません。** `.env` など `.gitignore` されたファイルは読みません——本物の資格情報が
  入っているのが普通で、読む必要もないからです（「`.env` がコミットされているか」は
  `git ls-files` で判定できます）。

**許可されたシステムのみを診断してください。** 自分が所有していない、または明示的な書面の許可が
ないホストに対して実行しないでください。**SAST も同じです** — 自分が所有していない、または許可を
得ていないコードベースに対して実行しないでください。

### 安全則の置き場（2層）

| 層 | ファイル | 内容 |
| --- | --- | --- |
| 共通 | `plugins/llm-zap-dast/references/safety-core.md` | 停止と fail-soft の線引き、秘匿情報の非出力と検証、対象由来はデータ、サブエージェントへの伝播、推測と事実の分離 |
| DAST 固有 | `plugins/llm-zap-dast/skills/dast/references/safety-policy.md` | `allowed_hosts`、ZAP モード、Active Scan ゲート、破壊の3軸、認証の停止条件 |
| SAST 固有 | `plugins/llm-zap-dast/skills/sast/references/safety-policy.md` | 読み取り境界、実行しない境界（ホワイトリスト）、semgrep の例外、秘密の扱い |

Skill は「共通 → 自スキル固有」の順で両方を読んでから作業を始めます。**停止するか続行するかの線は
「設定が明示的に約束した結果のクラスが成立しないなら停止、カバレッジが減るだけなら記録して続行」**
です（認証できないなら停止／Firefox が無ければ Ajax Spider をスキップして記録）。

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
無ければ追記前に確認します — 同意なく `.gitignore` を編集することはありません。`--init` を通して
いれば通常はこの時点で追記済みなので、run 側では止まりません（`--init` が `.gitignore` の整備まで
行います）。

SAST の成果物は `reports/sast/<run-id>/` に出力されます：

```text
reports/sast/<run-id>/
├── run.log
├── environment-check.json
├── attack-map.md          # 対象プロファイル ＋ 攻撃対象面の一覧（全診断の分母）
├── report-01.md           # 独立診断 1回目
├── report-02.md
├── report-03.md
└── report-04.md           # 統合版（出現回数・信頼度・ばらつき一覧つき）

reports/sast/latest.json   # 最新 run を指すポインタ（シンボリックリンクではない）
```

レポートには**未修正の脆弱性と対象ソースの抜粋**が入るため、冒頭に取扱注意を明記します。
検出したハードコード秘密は `file:line`・種別・影響・直し方だけを書き、**値は書きません**
（値を読まなくても「`.env` がコミットされているか」は判定できます）。

## WSL / ネットワークの注意

**WSLからは、Windowsホスト上のZAPへ `localhost` で到達できないことがあります。**
`check_environment.py` がZAPエンドポイント不達を報告したら、`localhost` の代わりにWindowsホストの
IP（WSLの既定ゲートウェイなど）を使うか、WSL内でZAPを起動してください。環境チェックは接続失敗時に
このヒントを表示します。

## 対象外 / 制約

- **認証は「できなければ停止」。** 任意アプリでの認証成功は保証しません（MFA / SSO / OAuth / SAML /
  CAPTCHA は自動化対象外）。**認証付きを指定した run が認証できないと分かったら、未認証で継続せず
  停止します**（認証状態の分からない結果＝静かな偽陰性を避けるため）。認可系（水平IDOR・水平/垂直
  権限昇格）の実施可否は**アカウント構成に依存**します（`authentication.users`）。構成が足りない
  クラスは「未実施」として記録します（実装済みのように扱いません）。
- **対象は使い捨てのローカル脆弱アプリを前提**。本番・現実の稼働アプリには向けません
  （ローカル限定レールで構造的に本番を拒否）。
- GUI / Web管理画面 / 外部データベース。
- 独自MCPサーバー。
- CI/CD統合 / 本番環境診断 / 自動更新。

これらは意図的に対象外です。

> 以前はここに「複雑なサブエージェント」も入っていました。SAST の追加で方針を変更しています——
> SAST は工程ごとに専任サブエージェントへ委譲し、独立3回診断＋統合で結論を出す構成です
> （下記「SAST のコストと構成」）。
