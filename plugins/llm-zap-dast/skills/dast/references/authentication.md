# 認証（工程2.5）— 認証付きDAST（best-effort）

この工程は **best-effort** です。目的は「完成した汎用認証スキャナー」ではなく、**LLMが対象を
解析して ZAP の認証機能を選択・設定し、認証後DASTをどこまで自律的に実行できるかを検証**すること。
失敗しても run 全体は止めず（未認証で継続）、**成功したように扱わず**、実施できなかった工程と理由を
`authentication.md`（成果物）とレポートに明記する。

`authentication.enabled: true` のとき、工程2と工程3の間で実行する。

## 二層構造（判断と反映を分ける）

- **LLM**：ソース・ログイン画面・DOM・HTTP履歴を見て、**認証方式・設定値・確認指標を判断**する。
- **`scripts/zap_auth.py`**：LLMが決めた値を **ZAP API へ機械的に反映するだけ**（判断しない）。
  対象固有のログイン処理をハードコードしない。

## 手順

1. **能力検出**：`zap_auth.py detect-capabilities` で、使用中ZAPが対応する認証／セッション方式を取得。
   未対応方式は選ばない。**ZAP Browser Based Authentication は 2.16.1+ ＋ Firefox が必要**
   （BBAはZAPがSelenium経由で実ブラウザを起動するため。`references/zap-integration.md` の
   「ブラウザ前提」を参照）。`detect-capabilities` は ZAP の対応方式しか見ないので、**Firefox の
   有無は工程0の `check_environment.py`（`browser_firefox`）の結果で判断する**こと。
2. **方式の解決（`auto` を解決する）**：`method: auto` の場合、LLMがソース/画面から具体方式
   （browser / form / json / basic / script）へ**解決してから**スクリプトを呼ぶ。
   **`zap_auth.py` に `auto` を渡さない**（`configure-authentication` は `auto` を拒否する）。
   - primary は **Browser Based Authentication**（SPA/CSRF/JSに対応しつつ ZAP が自動再認証を持つ）。
   - ZAP が扱えないフローは **Playwright ログイン**を fallback とする（下記「退化の帰結」）。
3. **Context 作成** → **認証方式設定** → **Session Management 設定** → **Verification 設定** →
   **User 作成** → **資格情報設定**（`set-credentials`：env 変数名から読む。**値は印字・保存しない**）
   → **User を有効化**（`set-user-enabled`）→ 必要なら **forced-user ON**。

### 複数アカウント（`authentication.users`）

`authentication.users` が複数ある場合、**同一 Context 内に User をアカウントごとに作成**する
（ZAP は1 Context に複数 User を持てる）。各アカウントについて **create-user →（認証方式設定後に）
set-credentials → set-user-enabled** を繰り返す。`create-user` の戻り値 `userId` はグローバル連番なので
**アカウントごとに控える**。

- **アカウント数の目安**（`references/scenario-testing.md`）：水平IDOR/水平権限昇格には**同一ロール2**、
  垂直には**異ロール（低権限＋管理者）**、両方を綺麗にやるなら**3（同一ロール2＋管理者）**。
- **forced-user は Context 単位で1人だけ**。アカウントを跨ぐ検証（A→B）は forced-user を張り替えるか、
  **`--user-id` を明示**した `spider-as-user`／`active-scan-as-user` で行う。未認証スキャンの前は
  `set-forced-user off`（どのアカウントで走ったか取り違えないため）。
- **後方互換**：`authentication.users` が無ければ、従来どおり単一 `username_env`/`password_env` を
  1アカウントとして扱う。

### 実機（ZAP 2.17.0）で確認済みの落とし穴

スパイクで実測した、間違えると**静かに失敗する**点：

- **順序**：`set-credentials` は**認証方式を設定した後**に呼ぶ。先に呼ぶと ZAP は manual auth の
  資格情報を期待して `Missing Parameter` で失敗する。
- **User は既定で無効**（`enabled: false`）。`set-user-enabled` を呼ばないと **forced-user は
  何もしない**（エラーも出ない）。
- **`userId` はグローバル連番**（コンテキストごとに0始まりではない）。`create-user` の戻り値の
  `userId` を必ず使う。
- **ConfigParams は値を個別にURLエンコード**する必要がある。`--param k=v` を使えばスクリプトが
  エンコードする（生の文字列を渡すと `Missing Parameter`）。
- **検証戦略は `context/action/setContextCheckingStrategy`**（`authentication` 側には無い）で、
  **コンテキスト名**を取る。値は `EACH_REQ` / `EACH_RESP` / `EACH_REQ_RESP` / `AUTO_DETECT` /
  `POLL_URL`。
- **ajaxSpider の User 指定は名前**（`contextName`/`userName`）。spider/ascan は id。
- **teardown の順序**：forced-user を OFF → User 削除 → **Context 削除（名前指定）**。forced-user が
  ONのままだと User 削除は `Result: FAIL`（HTTP 200）になる。
- **`users/view/usersList` はパスワードを平文で返す。** `auth-status` は必ずマスクしてから出力する
  （`zap_auth.py` の `scrub_users_list`）。生の応答をログ・成果物に流さない。
4. **差分による認証確認（安全の急所。必須）** — `test-authentication` は**生の証拠のみ**を返す。
   判定は **LLM ＋ 下記の固定差分ルール**が行う：
   - 認証済み User として **認証後にのみ到達できる URL/API** を取得し、**同じ対象への未認証**取得と
     比較する。
   - **必須の差分ルール**：認証成功の指標が「**認証時の応答に有り、かつ未認証の応答に無し**」で
     あること。次は**誤合格**なので禁止：
     - **ステータスのみ**での合格（200＋ログイン画面本文、ソフトリダイレクトで誤合格）。
     - **指標の存在のみ**での合格（未認証時にも同じ指標が出るなら判別力なし）。
     - **SPAで指標がJS側にある**場合（ZAPが見る本文が認証/未認証で同一）→ 認証後専用の
       XHR/JSON など、差が出る対象で確認する。
   - **身元確認**：プローブが身元に依存する場合（権限昇格/IDOR等）、応答が**意図したユーザー**を
     反映しているか（エコーされたユーザー名/ロール等）を確認する。「何かのセッション」では不十分。
   - **複数アカウント時の相互身元差分**：各アカウントを forced-user にして同じ検証URLを
     `test-authentication --identity-markers <A印>,<B印>` で取得し、**A の応答には A の印が有り
     B の印が無い／B の応答には B の印が有る**ことを確認する。両アカウントが同じ身元を返すなら
     セッションが取り違わっており、IDOR 判定の土台が崩れるので認証済みとして扱わない。
5. **確認できた場合だけ**認証後工程（3/5/6）へ進む。**曖昧・失敗なら「認証済み」として扱わない。**

## 状態モデル（工程7へ渡す）

各項目を 成功 / 失敗 / 未確定 / 未実施 ＋ 理由 ＋ 診断できなかった範囲 で記録：
認証設定・認証確認・認証後Spider・認証後Passive・認証付きActive Scan・LLM追加診断。

- **認証成功が曖昧なら認証済みとして扱わない。**
- **`max_attempts` 枯渇・認証失効は「認証失敗（decayed）→認証部分を停止」**として分類する
  （＝静かに匿名継続しない）。未認証診断の継続は妨げない。

## Playwright fallback の「退化の帰結」（明記する）

「Playwright でログインできた」と「ZAP User として認証付き Spider/Active Scan できる」は**別**。
BBA/ZAP-User 認証が使えず **Playwright ログインだけ成功**した場合：

- User指定 Spider（工程3）と User指定 Active Scan（工程5）は **未実施** に落ちる。
- **認証後は工程6の LLM 駆動プローブのみ**が認証付きで動く（ブラウザ/プロキシのセッション上で）。

この端末状態を `authentication.md` とレポートに書く。

## forced-user の明示制御（結果の取り違え防止）

forced-user は **Context 単位**の設定。放置すると「未認証のつもりの Active Scan」がログイン済み
ユーザーとして走り、**認証済み走査と未認証走査を取り違える**。

- **認証付きでないスキャン（既定の未認証 Active Scan 含む）を呼ぶ前に `set-forced-user off`** する。
- 認証付きスキャンは **User を明示指定**（`spider-as-user` / `active-scan-as-user`）。

## 認証情報の衛生（teardown）

- 資格情報は env 変数名からのみ読み、**値を run.log・stdout・stderr・成果物・スクショに出さない**。
- **ZAPの `usersList` は平文パスワードを返す**（実測）。`auth-status` はマスク済みを返すので、
  **生の ZAP API 応答を直接ログ・成果物に貼らない**こと。
- **ZAP User に保存された資格情報は redaction では消せない**（バイナリセッションに届かない）。
  対策は削除：**run 終了時と中断時に必ず `zap_auth.py clear-authentication`** を呼び、一時
  User/Context を消す。**複数アカウント時は全 User を削除**する（`--user-ids <id1,id2,...>` で
  まとめて指定。`--context` を渡せば removeContext が User ごと消す backstop になる）。**ZAP
  セッションをリポジトリ配下に置かない。** 消せなければ成果物に警告。

## 成果物 `authentication.md`

採用した認証方式／採用理由／Context名／**アカウント一覧（label・ロール・User名。資格情報は出さない）**／
アカウント別の認証成功/失敗の証拠／**相互身元差分の結果**／未認証時に到達したURL数／認証後に到達した
URL数／認証後に新しく到達したURL／セッション維持状況／再認証の有無／制約と失敗事項。
**アカウント構成に応じて実施可否が変わる**ので（水平＝同一ロール2／垂直＝異ロール／両方＝3）、
どの認可クラスを実施できたか・できなかったかを状態モデルで明示する。**機微はマスク**。
