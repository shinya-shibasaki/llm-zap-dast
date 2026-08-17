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
  `.../excludeFromContext/`、`.../setContextInScope/`（**新規Contextは既定で in-scope なので通常は
  呼ばない**。実測：`newContext` 直後の `inScope` は `true`。`false` にすると Protected下で
  Spider/Active Scan が `mode_violation` になる）
- モード：`/JSON/core/action/setMode/`（`safe` | `protect` | `standard` | `attack`）—
  `protect` を使う。`attack` は決して使わない。
- Spider：`/JSON/spider/action/scan/`、`/JSON/spider/view/status/`、
  `/JSON/spider/view/results/`
- Ajax Spider：`/JSON/ajaxSpider/action/scan/`、`/JSON/ajaxSpider/view/status/` —
  **Firefox が必要**（下記「ブラウザ前提」）
- Passive：`/JSON/pscan/view/recordsToScan/`（0 ⇒ 完了）
- Active：`/JSON/ascan/action/scan/`（**`contextId` を渡し `url` は省く**。上記
  「Active Scan は Context を対象に起動する」）、`/JSON/ascan/view/status/` — **ゲート付き**、工程5のみ
- 除外（スキャナ単位・**セッション単位でContextに紐づかない**）：
  `/JSON/spider/action/excludeFromScan/`、`/JSON/ascan/action/excludeFromScan/`、
  それぞれの `.../view/excludedFromScan/` と `.../action/clearExcludedFromScan/`（**後始末で必須**）
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
  `/JSON/ascan/action/scanAsUser/`（**認証付きActive Scanは二重ゲート＋工程5ゲート条件の充足が前提**）。
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
- モードは万能ではない：**実際の境界は ZAP Context のスコープ＋コード上で「スコープ外URLを叩かない」
  で担保**し、Protectedモードはその上の防御層と位置づける。

**Protectedモードが実際に何を縛るか（ZAP 2.17.0 で実測）**：

| API | Protectedモードは縛るか |
| --- | --- |
| `spider/action/scan` ／ `scanAsUser` | **縛る**（スコープ外URL → `mode_violation`） |
| `ascan/action/scan` ／ `scanAsUser` | **縛る**（スコープ外URL → `mode_violation`）。加えて**スコープ内でも**下記の起動形で拒否される |
| `core/action/accessUrl` | **縛らない**。Protected でも `safe` でも、スコープ外の生存ホストへ実際に到達した（対象側のカウンタで確認） |

`accessUrl` を使うのは `test-authentication` / `verify-canary` / 工程6のプローブなので、**この経路の
境界はモードではなく呼び出し側（`allowed_hosts` チェックとプロンプト規律）にある**。上の「実際の境界は
Context のスコープ＋コード」という位置づけは、この実測どおりである。

### Active Scan は Context を対象に起動する（URL を渡さない）

**Protectedモードでは、対象のルートURLを渡した再帰 Active Scan は拒否される**（実測）：

```
ascan/action/scan     url=http://host:port/   recurse 既定(true)  → mode_violation
ascan/action/scanAsUser 同上                                     → mode_violation
```

理由：`recurse=true` のとき ZAP は**起動ノードをベアのサイトノード `http://host:port`**（スラッシュ
無し）として評価し、下記の include 正規表現（ホスト直後の `/` を必須にする＝ホスト境界を固定している
形）がそれに一致しないため。`zap.log` に
`Scans are not allowed on nodes not in scope Protected mode http://host:port` が出る。

**正しい起動の仕方は `url` を省き、`contextId` で Context を対象にすること。** run のスコープは
Context（include ＋ exclude）そのものなので、指定が意図と一致する。

```
ascan/action/scan       contextId=<id>              # 未認証 Active Scan（工程5）
ascan/action/scanAsUser contextId=<id> userId=<id>  # 認証付き（zap_auth.py active-scan-as-user）
```

実測で確認した性質：

- **Context の exclude を守る**（除外したエンドポイントへの攻撃 0 回、隣のエンドポイントは 16 回）。
- **Context 外のホストは撃たない**（そのホストが ZAP のサイトツリーに載っていても 0 回）。
- **`contextId` も省くと ZAP が `missing_parameter` で拒否する** — 「全部を撃つ」形には落ちない。
- 対象は **Context ∩ サイトツリー**。ZAPセッションを使い回すと**前の run が発見したURLも含む**
  （`allowed_hosts` の内側で exclude も効くが、レポートの探索範囲とはズレるので記録する）。
- `standard` モードでも同じ挙動（回帰なし）。

**`recurse=false` は回避策ではない。** `mode_violation` は消えて起動するが、実測では**配下を1件も
撃たない**（ルートページのみ。同一対象で products/boom への攻撃が `recurse=false` では 0 回、
Context 指定では 16 回）。「Active Scan 実行済み」に見えて何も検査していない状態になる。
部分スキャンをしたいときだけ、`url` に**実在するサブパス**を渡す（ベアオリジンは上記のとおり拒否）。

## スコープ制御（ZAP Context）

- run単位でContextを作成し、`include` 正規表現を `allowed_hosts` に限定する；スコープ外を
  スキャンしないよう設定する。Spiderが別ホストへのリンクをたどっても対象化しない。
- `exclude.paths` を**リクエストを送る経路すべて**に効かせる（下記「exclude の効かせ方」）。
  `/logout` はGETで到達し得るため、Spiderからの除外も必須。
- `validate_config.py` は入口側の一次防御として残し、Contextは実行時の実境界とする（多層防御）。

### exclude の効かせ方（経路別・ZAP 2.17.0 で実測）

`exclude.paths` は「**そこへリクエストを送ると困るパス**」を列挙するものである（`/logout` は
セッションが消える、`/admin/delete-all` や `/api/reset` はデータが壊れる）。したがって効かせる先は
**送信する経路**であり、下表が唯一の列挙である（他所にコピーしない）。

| 経路 | 効かせ方 | 実測メモ |
| --- | --- | --- |
| Spider | Context 除外（`context/action/excludeFromContext`） | 除外URLへのリクエスト0・spider results にも出ない。**後から除外しても以降は効く** |
| Ajax Spider | 同上 | Context のスコープで動く |
| Active Scan | Context 除外（Context 指定起動なので自動的に効く）。特定スキャナだけ外したいときは `ascan/action/excludeFromScan` | Context 除外で攻撃0回（対照は16回） |
| 工程4 Playwright | **プロンプト規律のみ**（ZAP側の担保は無い） | `core/action/excludeFromProxy` は存在するが意味を未実測なので担保に数えない |
| 工程6 LLMプローブ | **プロンプト規律** ＋ `zap_auth.py` の `path_is_excluded`（リダイレクト追従の判定） | 送信はLLMが行うため機械的担保は部分的 |

**Passive Scan は対象に含めない。** Passive は自分では何も送らないため、除外の対象になる筋の機能では
ない。**除外したURLに Passive アラートが出ていたら、それは上表のどこかで除外が漏れて「送ってしまった」
サイン**である。消すのではなく、送った経路を直すこと。
（実測：Context 除外は Passive に効かず、`pscan/action/setScanOnlyInScope` を `true` にすれば効く
──`pscan/view/scanOnlyInScope` の既定は `false`。だが**採用しない**：安全上の効果はゼロで、代わりに
スコープ外通信の Passive アラートを全部失い、しかもこれは `newSession` でも戻らないグローバル設定である。）

**粒度と副作用**（どちらを使うかで結果が変わる）：

- **Context 除外**：送信経路をまとめて塞げる。ただし**その URL には forced-user の認証が乗らなくなる**
  （実測：除外前 200＋ログイン試行1回 → 除外後 401・`Authorization` ヘッダ無し・ログイン試行0回）。
  除外してはいけないURLは `references/authentication.md`「除外してはいけないURL」。
- **スキャナ単位除外**（`spider|ascan/action/excludeFromScan`）：そのスキャナだけ。認証は乗ったまま。
  ただし**セッション単位**で、**Context を削除しても残る** — 後始末で `clearExcludedFromScan` を
  呼ばないと**利用者のZAPに残り、以後のスキャンが黙って一部を飛ばす**。**`contextName` を付けて
  呼んでも ZAP は `OK` を返して黙って無視する**（Context 単位だと誤解した呼び出しがエラーにならない）。

**`exclude.paths`（パス）→ 除外正規表現への変換**：`validate_config.py` は「前置き一致」で検証する
（`/logout` は `/logout/...` も飲む）ので、正規表現も同じ意味に揃える。クエリ付き（`/logout?x=1`）も
含める形にすること。食い違うと「検証は通ったのに ZAP では除外されていない」が起きる。

`allowed_hosts` ＋ `base_url` から推奨する include 正規表現：ホストをエスケープし、スキーマと
任意ポートを許可する。例：`^https?://localhost(:\d+)?/.*$`。許可ホストごとに1つ追加する。
**ホスト直後の `/` は必須**（これがホスト境界を固定する。緩めると `localhost.example.com` の
ような別ホストを取り込む書き間違いを誘発する）。ZAP は正規表現を**完全一致**で照合するので、
この形は `localhost.example.com` を取り込まない（実測）。

**`(:\d+)?` は「そのホストの全ポートがスコープ内」を意味する。** `allowed_hosts` がホスト単位なので
これは意図した挙動だが、**同じ `localhost` で動いている別サービス（DB管理画面、他のアプリ、
`localhost` に立てたモック等）もスコープに入る**。対象以外をローカルで動かしている場合は、
ポートを固定した形（`^https?://localhost:3000/.*$`）にするか、`exclude.paths` で外すこと。
run.log にどちらを選んだか残す。

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
