# dast.yaml の生成支援（--init と自動オファー）

`dast.yaml` を手で書く負担を減らすため、リポジトリ解析から下書きを生成する。生成は Claude の
判断で行い、検証は `validate_config.py`（機械的処理）に任せる。**確認を取ってから書き出す。**

## 起動条件

- **明示**：`/llm-zap-dast:dast --init` — 設定を生成して書き出したら**停止**する（スキャンは
  実行しない）。
- **自動オファー**：`dast.yaml` が無い状態で通常実行したとき、工程0で「生成しますか？」と提案する。
  断られたら既定値で続行する（`dast.yaml` は必須ではない）。

## 生成手順

1. **リポジトリ解析**（工程1と同じ観点）で次を検出する：フレームワークと起動方法、待受ホスト/
   ポート、ソースのルートディレクトリ、フォーム、`/logout` やデータ削除・リセット等の破壊的
   エンドポイント。
2. `templates/dast-config.example.yaml` を土台に、検出値で埋めた下書きを作る（コメントは残す）：
   - `target.base_url`：検出したスキーム/ホスト/ポート（例：`http://localhost:<port>`）。
   - `target.allowed_hosts`：`localhost`、`127.0.0.1`（検出ホストがローカルなら追加）。
   - `target.source_roots`：検出したソースディレクトリ（例：`src`、`app`）。
   - `zap.api_url`：既定 `http://localhost:8080`。`api_key_env: ZAP_API_KEY`、`autostart: true`。
   - `authentication.enabled: false`（ログイン処理を検出しても**v1では無効のまま**。要否はメモ
     として提示するが、値は false に保つ）。
   - `scan`：`spider: true`、`playwright: true`、**`active_scan: true`**（既定ON。検出内容に
     かかわらず true。実行時は工程5のゲート＋明示確認が必須で、無確認では走らない）、`scenario_tests: true`。
     - `ajax_spider`：**SPA / JS描画依存かどうかを判定して提案する**（下記ヒューリスティック）。
       SPAと判断できれば `true`、そうでなければ `false`。攻撃は送らず遅くなるだけなので、検出時の
       自動 true は安全。**推測である旨と根拠を明示**し、利用者が変えられるようにする。
   - `safety`：`require_local_target: true`、**`allow_production: false`**。
   - `exclude.paths`：検出した破壊的エンドポイントを候補として列挙（例：`/logout`、
     `/admin/delete-all`、`/api/reset`）。**推測である旨を明示**し、利用者に取捨選択させる。
   - `output.directory`：`reports/dast`。
3. 下書きを利用者に提示し、**どの値が検出由来で、どれが既定/推測か**を明確に説明する（**日本語で**）。
4. **検証**：書き出し予定のパスに一旦保存し、`validate_config.py --config <path>` を実行。
   エラーがあれば直してから確定する。
5. **書き出しは確認後のみ。** 既存の `dast.yaml` を**無断で上書きしない** — 差分を見せ、同意を
   得てから書く。
6. 書き出し後、`.gitignore` に `reports/` と `.env` があるか確認する（`references/redaction.md`）。
   認証情報は設定ファイルに書かず、環境変数名で参照する旨を改めて伝える。

## ajax_spider の判定ヒューリスティック

Ajax Spider は実ブラウザでJS描画をクロールするため、SPA/JS依存アプリでは到達範囲が大きく広がる
一方、そうでないアプリでは遅くなるだけで恩恵が薄い。次を手がかりに `ajax_spider` を提案する。

**`true` を提案（SPA / JS依存の兆候）**：
- フロントのフレームワーク検出：React / Vue / Angular / Svelte / SolidJS、Next.js / Nuxt / Remix
  などのクライアント寄り構成（`package.json` の依存、`vite`/`webpack` ビルド）。
- クライアントサイドルーティング（`react-router`、`vue-router` など）や、単一マウント要素
  （`<div id="root">` / `#app`）＋JSでの描画。
- UIがGraphQL/XHR/fetch中心でサーバHTMLをほとんど返さない、APIファーストな作り。

**`false` を維持（サーバレンダリング中心の兆候）**：
- サーバサイドテンプレート主体（Flask/Django templates、Rails ERB、Laravel Blade、Thymeleaf、
  素のHTML）で、リンク遷移がHTTPベース。
- JSフレームワーク依存が無い、または限定的（部分的な補助スクリプト程度）。

判断が曖昧なときは `false`（軽い既定）にし、「SPAなら `true` にすると到達範囲が広がる」旨をメモ
として添える。いずれの場合も**検出由来か推測かを明示**し、利用者が最終的に選べるようにする。
（`active_scan` はこの判定の対象外。検出内容にかかわらず既定 true。）

## 安全の既定（生成物でも維持）

- 秘匿情報（パスワード/トークン/キー）を設定ファイルに書かない。環境変数名のみ。
- `active_scan: true`（既定ON。実行時ゲートで担保）／`allow_production: false` を生成物の既定として維持する。
- `allowed_hosts` はローカルを既定とし、非ローカルを勝手に足さない。

## 生成後の流れ

- `--init` で起動した場合：書き出したら停止（スキャンは別途 `/llm-zap-dast:dast` で実行）。
- 自動オファーから生成した場合：新しい `dast.yaml` を使って工程0から続行する。
