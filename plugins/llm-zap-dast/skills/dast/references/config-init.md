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
   - `authentication`：ログイン処理を検出したら**器を埋める**（`method: auto`・`login_url`・
     `username_env`/`password_env`・`max_attempts: 3`・`verification`/`session_management` は
     `auto`・`active_scan: true`）。ただし**生成物の既定は `enabled: false`**（任意アプリでの
     認証成功は保証しないため。利用者が明示的に `true` にして使う）。**平文の資格情報は書かず環境変数名のみ**。
     認証方式候補・ログイン成功/失敗指標の候補はメモとして提示し、`method: auto` のまま残してよい
     （実行時にLLMが解決する）。**ロール/権限の存在を検出したら**（管理者機能・ロール定義など）、
     認可診断には複数アカウントが要る旨をメモし、`authentication.users`（同一ロール2＝水平／
     異ロール＝垂直／3＝両方）の**コメント例を添える**（環境変数名のみ。既定は単一のままでよい）。
   - `scan`：`spider: true`、`playwright: true`、**`active_scan: true`**（既定ON。検出内容に
     かかわらず true。実行時は工程5のゲート条件を満たせば無確認で実行）、`scenario_tests: true`、
     **`destructive: true`**（既定ON。使い捨てローカル対象前提。非ローカル＋`allow_production:false`
     では検証で拒否される。外部副作用は常に禁止）、**`availability_impact: false`**（DoS相当は既定OFF）。
     - `ajax_spider`：**SPA / JS描画依存かどうかを判定して提案する**（下記ヒューリスティック）。
       SPAと判断できれば `true`、そうでなければ `false`。攻撃は送らず遅くなるだけなので、検出時の
       自動 true は安全。**推測である旨と根拠を明示**し、利用者が変えられるようにする。
   - `safety`：`require_local_target: true`、**`allow_production: false`**。
   - `exclude.paths`：`login_url`/`verification_url` は入れない。`/logout` は認証維持のため除外候補に
     挙げる。**データ破壊系（`/admin/delete-all`・`/api/reset` 等）は扱いが分かれる点を明示する**：
     `exclude.paths` は Spider/Ajax/Passive/Active（工程3〜5）**だけでなく工程6のシナリオ診断にも効く**。
     一方、生成物の既定は `scan.destructive: true`（工程6で削除/リセット系を**意図的に検証したい**）。
     したがって「工程4/5 の無秩序なクロール/Active から外すが工程6では個別に検証する」のか「全工程で
     完全に触れない」のかは**別の選択**であり、除外に入れると destructive の主目的が空振りする。両者を
     説明し、**推測である旨を明示**して利用者に選ばせる（既定で一律除外にしない）。
   - `output.directory`：`reports/dast`。
3. 下書きを利用者に提示し、**どの値が検出由来で、どれが既定/推測か**を明確に説明する（**日本語で**）。
4. **検証**：書き出し予定のパスに一旦保存し、`validate_config.py --config <path>` を実行。
   エラーがあれば直してから確定する。
5. **書き出しは確認後のみ。** 既存の `dast.yaml` を**無断で上書きしない** — 差分を見せ、同意を
   得てから書く。
6. **`.gitignore` の整備（この init で行う。通常 run 側で止めないため）**：`reports/` と `.env` が
   `.gitignore` に無ければ、**この init で追記する**（`.gitignore` が無ければ作成）。追記は
   **dast.yaml 書き出しと同じ確認にまとめ、個別の同意を増やさない**（既に両方あれば何もしない）。
   何を追記したかは提示・記録する。これにより通常 run の `.gitignore` 同意停止
   （`references/redaction.md`）は発生しなくなる。認証情報は設定ファイルに書かず、環境変数名で
   参照する旨を改めて伝える。

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
- `active_scan: true`（既定ON。実行時ゲートで担保）／`destructive: true`（既定ON。非ローカルは検証で
  拒否＝本番を構造的に破壊できない）／`availability_impact: false`／`allow_production: false` を生成物の
  既定として維持する。
- `allowed_hosts` はローカルを既定とし、非ローカルを勝手に足さない。

## 生成後の流れ

- `--init` で起動した場合：書き出したら停止（スキャンは別途 `/llm-zap-dast:dast` で実行）。
- 自動オファーから生成した場合：新しい `dast.yaml` を使って工程0から続行する。
