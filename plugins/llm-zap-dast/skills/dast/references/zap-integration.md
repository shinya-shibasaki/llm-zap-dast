# ZAP連携

## 主方式：ZAP REST API

既定は **ZAP REST API を primary** とします。ZAPをデーモンモードで起動し、
`http://<host>:<port>/JSON/...` へHTTPリクエストを送ります。理由：CLI/デスクトップの有無や
バージョン差に影響されにくく、再現性が高いためです。

```bash
# 例：ZAPをデーモンモードで起動（ZAPは利用者が用意。これは説明用）
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=true   # キーなし：ローカル限定
# APIキーを使う場合（非ローカルでは必須）：
zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=$ZAP_API_KEY
```

**フロー制御・JSON処理・redaction は Python（`requests`）に寄せる。** Spider完了のポーリング、
Passive Scanの待ち合わせ、到達URLとソース抽出URLの突合、run単位のファイル出力、マスク処理は
すべてPythonで行う。`zaproxy` Python パッケージや ZAP MCP は薄いフォールバックにとどめる。
**フロー全体を curl＋jq で組まない。** curl は単発の疎通確認の例としてのみ（下記および README）
用いる。

```bash
# 単発の疎通確認のみ（フローではない）：
curl -s "http://127.0.0.1:8080/JSON/core/view/version/"
curl -s "http://127.0.0.1:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY"
```

方法を場当たり的に変えないこと。採用した方法とその理由を `run.log` に残す。

### ZAPの自動起動（`zap.autostart`、既定true）

既存の起動済みZAPを優先します。ZAPが不達で `zap.autostart` が有効なとき、スキルは
`scripts/zap_control.py start` でローカルZAPを起動できます。

- 起動は**必ず `-host 127.0.0.1`**（ループバック限定）。`0.0.0.0` にはしない。`zap.start_command`
  で 0.0.0.0 バインドを指定しても拒否する。
- キーなし運用はローカル限定のまま（非ローカルなら `validate_config.py` が拒否）。
- 探索順：`zap.start_command`（明示指定）→ PATH上のバイナリ（`zap.sh` / `zap` /
  `owasp-zap` / `zaproxy`）→ `zap.docker`（明示イメージ、ホスト側は 127.0.0.1 にのみ公開）。
- 見つからない／起動失敗 → **fail-soft でスキップ**し、下記の手動起動を案内する。
- **ライフサイクル**：スキルが起動したインスタンス**だけ**を、実行後に
  `zap_control.py shutdown`（ZAPの `/JSON/core/action/shutdown/`）で停止する。利用者が事前に
  起動していたZAPには触れない。
- **WSLの注意**：ZAPがWindows側にある構成では、WSL内のスキルからは起動できない。この場合は
  手動起動が必要（`zap.autostart` を実質スキップし、案内にフォールバック）。

### 主要APIエンドポイント（ZAP 2.14+；利用中のバージョンで確認すること）

- Context：`/JSON/context/action/newContext/`、`.../includeInContext/`、
  `.../excludeFromContext/`、`.../setContextInScope/`
- モード：`/JSON/core/action/setMode/`（`safe` | `protect` | `standard` | `attack`）—
  `protect` を使う。`attack` は決して使わない。
- Spider：`/JSON/spider/action/scan/`、`/JSON/spider/view/status/`、
  `/JSON/spider/view/results/`
- Ajax Spider：`/JSON/ajaxSpider/action/scan/`、`/JSON/ajaxSpider/view/status/` —
  **Firefox が必要**（下記「ブラウザ前提」）
- Passive：`/JSON/pscan/view/recordsToScan/`（0 ⇒ 完了）
- Active：`/JSON/ascan/action/scan/`、`/JSON/ascan/view/status/` — **ゲート付き**、工程5のみ
- データ：`/JSON/core/view/urls/`、`/JSON/core/view/messages/`（HTTP履歴）、
  `/JSON/core/view/alerts/` または `/JSON/alert/view/alerts/`
- Proxy：ブラウザのHTTP(S)プロキシを `http://<zap-host>:<zap-port>` に向ける。
- 認証（工程2.5・`references/authentication.md`）：
  `/JSON/authentication/view/getSupportedAuthenticationMethods/`、
  `.../action/setAuthenticationMethod/`、`.../setLoggedInIndicator/`、`.../setLoggedOutIndicator/`；
  `/JSON/sessionManagement/action/setSessionManagementMethod/`；
  `/JSON/users/action/newUser/`、`.../setAuthenticationCredentials/`、**`.../setUserEnabled/`**
  （新規Userは既定で無効）、`.../removeUser/`、`/JSON/users/view/usersList/`（**平文パスワードを
  返すのでマスク必須**）；検証戦略は **`/JSON/context/action/setContextCheckingStrategy/`**
  （コンテキスト**名**を取る。`authentication` 側には無い）；
  `/JSON/forcedUser/action/setForcedUser/`、`.../setForcedUserModeEnabled/`；
  User指定スキャン：`/JSON/spider/action/scanAsUser/`、`/JSON/ajaxSpider/action/scanAsUser/`、
  `/JSON/ascan/action/scanAsUser/`（**認証付きActive Scanは二重ゲート＋確認が前提**）。
  **Browser Based Authentication は ZAP 2.16.1+ ＋ Firefox が必要**（下記「ブラウザ前提」）。
  利用可否は実行時に `zap_auth.py detect-capabilities` で確認する（バージョン差を吸収）。

### ブラウザ前提（Firefox・必須）

ZAPは次の機能で、**自分のプロセスから Selenium 経由で Firefox を起動**する。工程4/6で使う
Playwright の Chromium とは別物で、相互に代替できない（READMEの「ブラウザが2種類必要な理由」）。

| ZAPの機能 | 使う場面 |
| --- | --- |
| Ajax Spider | 工程3（`scan.ajax_spider: true` のとき） |
| DOM XSS Active Scan ルール | 工程5 |
| Browser Based Authentication | 工程2.5（認証の primary 方式） |
| client アドオン | ZAP起動時のプロファイル生成 |

前提が満たされない場合の見え方：

- **Ajax Spider** は `SessionNotCreatedException: Expected browser binary location, but unable to
  find binary in default location` で失敗する（工程3で顕在化）。
- **DOM XSS ルールは黙ってスキップされる。** `zap.log` に
  `WARN DomXssScanRule - Skipping scanner, failed to start browser` が出るだけで、Active Scan
  自体は正常終了する。**レポートには「Active Scan 実行済み」と書けてしまう**ので、Firefox が無い
  環境ではこの取りこぼしを必ず記録すること。

工程0の `check_environment.py` が `browser_firefox` として検査する。**未充足のまま Active Scan を
実行した場合は、DOM XSS が未検査であることを `execution-summary.json` とレポートの「スキップした
工程と理由」に明記する**こと（`report-format.md`）。

### 認証操作は `zap_auth.py` に寄せる（判断しない薄いラッパ）

認証の Context/方式/セッション/検証/User 設定、User指定スキャン、teardown は
`scripts/zap_auth.py` の各コマンドで行う。**LLMが設定値を判断し、スクリプトは反映するだけ。**
`configure-authentication` は `method: auto` を拒否（LLMが具体方式へ解決してから渡す）、
`test-authentication` は合否ではなく**生の証拠**を返す（両側を同条件で読み、揃わなければ
`evidence_complete: false`＋終了コード1）、`active-scan-as-user` は `--gate-passed`
を要求する。詳細は `references/authentication.md`。

## ZAP動作モード

- **既定：Protectedモード。** Protectedモードでは、攻撃的操作（スパイダー巡回、Active Scan、
  ファジング、強制ブラウズ、改変再送）が、**スコープ外URLに対しては行われない**。
- **ATTACKモードは禁止** — スコープ内の新規ノードを発見と同時にActive Scanするため、Active Scan
  ゲートと衝突する。
- モードは万能ではない：API経由操作への強制はZAPのバージョンにより差があり得る。したがって
  **実際の境界は ZAP Context のスコープ＋コード上で「スコープ外URLを叩かない」で担保**し、
  Protectedモードはその上の防御層と位置づける。v1の動作確認時に、ProtectedモードがAPI操作を
  実際に制約するかを一度確認する。

## スコープ制御（ZAP Context）

- run単位でContextを作成し、`include` 正規表現を `allowed_hosts` に限定する；スコープ外を
  スキャンしないよう設定する。Spiderが別ホストへのリンクをたどっても対象化しない。
- `exclude.paths` を **Spider / Ajax Spider / Passive / Active / Playwright** のすべてに効かせる。
  `/logout` はGETで到達し得るため、Spiderからの除外も必須。
- `validate_config.py` は入口側の一次防御として残し、Contextは実行時の実境界とする（多層防御）。

`allowed_hosts` ＋ `base_url` から推奨する include 正規表現：ホストをエスケープし、スキーマと
任意ポートを許可する。例：`^https?://localhost(:\d+)?/.*$`。許可ホストごとに1つ追加する。
**ホスト直後の `/` は必須**（これがホスト境界を固定する。緩めると `localhost.example.com` の
ような別ホストを取り込む書き間違いを誘発する）。

**Contextは run で1つ。** 工程2.5（認証）で作成した Context を工程3以降でも使う。認証設定は
Context に紐づくため、工程3で作り直すと認証が無効になる。スコープ登録は認証より先に必要なので
（`references/authentication.md`）、実際の登録は工程2.5 の `zap_auth.py include-in-context` で行う。

**末尾スラッシュの注意**：上の正規表現はホスト直後の `/` を要求するため、`http://localhost:3000`
（パスなし）は**スコープ外**と判定され、`scanAsUser` は `url_not_in_context` で失敗する。
`target.base_url` はスラッシュ無しで書かれるので、`zap_auth.py` は scanner に渡すURLに `/` を
補う（`seed_url`）。HTTPではパス無し＝`/` なので意味は変わらず、スコープも変わらない。

## Playwright を ZAP 経由で（工程4）

- ブラウザをZAP Proxy経由にして、通信をZAP履歴に記録させる。
- HTTPS：ブラウザプロファイルに **ZAPのルートCA** を取り込む/信頼させるか、証明書エラーを無視して
  ブラウザを起動する（例：Playwright `ignoreHTTPSErrors: true` /
  `--ignore-certificate-errors`）。この点は診断条件としてレポートに記す。
- ブラウザ操作中も `exclude.paths` を守る。工程4は到達（カバレッジ）が目的なので、`scan.destructive`
  が有効でも**破壊的操作を巻き込みで発火させない**（意図的な破壊検証は工程6）。外部への副作用（8C）は
  常に禁止（`references/safety-policy.md`）。

## WSL / ネットワークの注意

WSLからは、**Windowsホスト上で動くZAPへ `localhost` で到達できないことがある。**
`check_environment.py` がZAPエンドポイント不達を報告したら、まずこれを疑う：`localhost` の代わりに
Windowsホストのipアドレス（WSLの既定ゲートウェイ／`host.docker.internal` など）を使うか、WSL内で
ZAPを動かす。READMEにも記載している。
