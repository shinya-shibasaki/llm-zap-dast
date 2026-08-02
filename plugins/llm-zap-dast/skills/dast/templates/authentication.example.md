# 認証結果（authentication.md）— 例

工程2.5（認証設定＋認証確認）の成果物の例。**best-effort**。値・資格情報はマスクし、状態は
成功 / 失敗 / 未確定 / 未実施 で明示する。

## サマリ（状態モデル）

| 項目 | 状態 | 理由 / 補足 |
| --- | --- | --- |
| 認証設定 | 成功 | Browser Based Authentication（ZAP 2.16.1）を選択 |
| 認証確認 | 成功 | 差分確認：`/account` に "Sign out" が認証時のみ出現。ユーザー名 `***REDACTED:field***` をエコー |
| 認証後 Spider | 成功 | User指定。到達URL 41（未認証 23） |
| 認証後 Passive Scan | 成功 | 完了 |
| 認証付き Active Scan | 成功 | 二重ゲート充足（`scan.active_scan` かつ `authentication.active_scan`）＋工程5確認済み。User指定で実行 |
| LLM追加診断 | 一部成功 | 水平IDOR（alice→bob）・垂直権限昇格の拒否確認・セッション改ざんを実施。<br>SSO連携部分は未実施 |

## アカウント構成

| label | role | User名 | 認証 | 用途 |
| --- | --- | --- | --- | --- |
| alice | user | `dast-user-alice` | 成功 | 水平IDOR/水平権限昇格（bob と対） |
| bob | user | `dast-user-bob` | 成功 | 水平IDOR/水平権限昇格（alice と対） |
| admin | admin | `dast-user-admin` | 成功 | 垂直権限昇格の拒否確認のベースライン |

- 構成：**3アカウント（同一ロール2＋管理者）** → 水平・垂直の両方を実施可能。
- **相互身元差分**：`/rest/user/whoami` を各 User で取得。alice の応答は alice を、bob の応答は bob を
  反映（別人セッションへの化けなし）。identity markers はマスク。
- アカウント切替は `--user-id` 明示で実行（forced-user は Context 単位で1人固定のため）。

## 採用した認証方式

- 方式：Browser Based Authentication（`method: auto` → `browser` に解決）
- 採用理由：ログインが SPA＋CSRFトークンで、form/json auth では通らない。BBA は実ブラウザで
  ログインし自動再認証を持つため選択。
- Context名：`dast-run`／User：上記アカウント表のとおり（全て同一 Context 内）
- Session Management：cookie ベース（`auto` で判定）

## 認証確認の証拠（差分・マスク済み）

- 認証時 `/account`：`200`、本文に "Sign out" **有り**、ユーザー名 `***REDACTED:field***` を反映。
- 未認証 `/account`：`302 → /login`、"Sign out" **無し**。
- 差分ルール：指標が「認証時に有り・未認証時に無し」を満たす → **認証成功**（身元も一致）。

## カバレッジ差

- 未認証で到達：23 URL
- 認証後に新規到達：18 URL（例：`/account/*`、`/orders/*`、`/api/me` …）

## セッション維持 / 再認証

- forced-user モードで維持。ログアウト誘発プローブ実行中は forced-user を OFF にして実施。
- 再認証：2回（Active Scan は未実施のため長時間区間なし）。

## 制約・失敗事項

- 認可クラスの実施可否は**アカウント構成依存**。本 run は3アカウント構成のため水平・垂直とも実施。
  単一アカウントだった場合は「水平系は単一アカウントのため未実施」と記録する。
- 破壊的検証：`scan.destructive` 有効時は他人リソースへの更新/削除の可否まで確認（何を変更したかは
  scenarios.md に記録）。`false` なら読み取りでの検出止まり。
- MFA/SSO/CAPTCHA：なし（該当時は未実施として記録）。
- teardown：run 終了時に `clear-authentication --user-ids <alice,bob,admin>` で全 User/Context を
  削除済み（removeContext が backstop）。
