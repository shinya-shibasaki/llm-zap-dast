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

### 主要APIエンドポイント（ZAP 2.14+；利用中のバージョンで確認すること）

- Context：`/JSON/context/action/newContext/`、`.../includeInContext/`、
  `.../excludeFromContext/`、`.../setContextInScope/`
- モード：`/JSON/core/action/setMode/`（`safe` | `protect` | `standard` | `attack`）—
  `protect` を使う。`attack` は決して使わない。
- Spider：`/JSON/spider/action/scan/`、`/JSON/spider/view/status/`、
  `/JSON/spider/view/results/`
- Ajax Spider：`/JSON/ajaxSpider/action/scan/`、`/JSON/ajaxSpider/view/status/`
- Passive：`/JSON/pscan/view/recordsToScan/`（0 ⇒ 完了）
- Active：`/JSON/ascan/action/scan/`、`/JSON/ascan/view/status/` — **ゲート付き**、工程5のみ
- データ：`/JSON/core/view/urls/`、`/JSON/core/view/messages/`（HTTP履歴）、
  `/JSON/core/view/alerts/` または `/JSON/alert/view/alerts/`
- Proxy：ブラウザのHTTP(S)プロキシを `http://<zap-host>:<zap-port>` に向ける。

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

## Playwright を ZAP 経由で（工程4）

- ブラウザをZAP Proxy経由にして、通信をZAP履歴に記録させる。
- HTTPS：ブラウザプロファイルに **ZAPのルートCA** を取り込む/信頼させるか、証明書エラーを無視して
  ブラウザを起動する（例：Playwright `ignoreHTTPSErrors: true` /
  `--ignore-certificate-errors`）。この点は診断条件としてレポートに記す。
- ブラウザ操作中も `exclude.paths` と破壊的操作の禁止を守る。

## WSL / ネットワークの注意

WSLからは、**Windowsホスト上で動くZAPへ `localhost` で到達できないことがある。**
`check_environment.py` がZAPエンドポイント不達を報告したら、まずこれを疑う：`localhost` の代わりに
Windowsホストのipアドレス（WSLの既定ゲートウェイ／`host.docker.internal` など）を使うか、WSL内で
ZAPを動かす。READMEにも記載している。
