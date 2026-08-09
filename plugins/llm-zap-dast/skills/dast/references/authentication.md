# 認証（工程2.5）— 認証付きDAST

`authentication.enabled: true` のとき、工程2と工程3の間で実行する。

**この設定は「認証付きで診断する」という約束です。** 認証付きで診断できないと分かった時点で
**run を停止**します（未認証で継続しない）。未認証の結果が欲しい場合は
`authentication.enabled: false` を指定してください — 設定が結果の種類を決めます。

理由：認証付きを指定した run が黙って未認証に落ちると、出てくるレポートは「認証状態が不明な結果」に
なります。到達範囲も、検出できる脆弱性の種類も違うのに、見た目は同じレポートです。
これは静かな偽陰性そのものなので、続けるより止めた方が安全です。

**停止条件（いずれも「認証付きで診断できない」）**：

| 条件 | 判定方法 |
|---|---|
| ZAPの認証機能が使えない | `detect-capabilities` ＋ 工程0の `browser_firefox` |
| 認証確認が曖昧／失敗 | `test-authentication` の差分ルール |
| 再認証ストーム／検証が一度も走っていない | `verify-canary` |
| セッション失効・`max_attempts` 枯渇 | 認証付きスキャンの拒否、または実行中の検知 |
| 認証有効中に ZAP が到達不能になった | 工程3以降。fail-soft のスキップにしない |

**停止しても `clear-authentication` は必ず実行する**（ZAP User に平文の資格情報が残るため）。
停止時は、検知した内容（カウンタの実数）・実施済みの範囲・次に直すべき点を成果物に記録する。

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
   - **ZAP が扱えないフローなら停止する。** Playwright ログインへ退避しない
     （下記「Playwright ログインへ退避しない」）。
3. **Context 作成** → **スコープ登録（`include-in-context`）** → **認証方式設定** →
   **Session Management 設定** → **Verification 設定** → **User 作成** →
   **資格情報設定**（`set-credentials`：env 変数名から読む。**値は印字・保存しない**）
   → **User を有効化**（`set-user-enabled`）→ 必要なら **forced-user ON**。

   **スコープ登録は省略できない。** ZAP は「Context に含まれる URL」にしか認証を適用しないため、
   include が空だと**認証設定はすべて無効**になる。実測（同一手順で include の有無だけを変えた比較）:

   | | include なし | include あり |
   |---|---|---|
   | ログイン試行 | **0回** | 1回 |
   | 実際の応答 | **401（未認証で送信）** | 200 |
   | `spider-as-user` | `url_not_in_context` | 正常 |

   1行目・2行目に**エラーは出ない**（黙って未認証になる）。include 正規表現は工程3のスコープ制御と
   同じもの（`references/zap-integration.md`「スコープ制御」）を使う。
   **この順序は必須**：`setAuthenticationMethod` は検証設定を既定へリセットするため
   （実測：POLL_URL＋指標が EACH_RESP＋指標なしに戻る）、認証方式を後から設定し直すと
   検証設定が黙って消える。やり直す場合は `configure-verification` も必ず再実行する。

### 検証設定（Verification）の決め方

**方式は POLL_URL を第一候補にする。** 認証専用エンドポイント（未ログインでは返らない
API）を1つ選び、そこを定期的にポーリングさせる。理由は、POLL_URL では ZAP が
**ポーリング応答だけ**を見るため、指標の正しさをその1つの応答についてだけ保証すればよいから。
毎回チェック（`EACH_RESP` 等）は**アプリの全応答に対して**指標が正しいことを要求し、それは
検証しようがない。認証専用エンドポイントが無い場合のみ `EACH_RESP` を使う。

**`AUTO_DETECT` は使わない**（`configure-verification` が拒否する）。実測では ZAP が
全応答を未認証と判定し、毎リクエスト再ログイン＋自分の成功ログインを失敗計上して、
10リクエストで認証失敗率100%に達し insights がデーモンを停止した。ブラウザ系ログインでは
ZAP が実行時に解決する建前だが、実測では解決せず、再認証ごとにブラウザが起動して更に悪化した。

**指標は「ポーリング先の応答」から選ぶ。** ソースは場所を見つける手がかりであって、
最終判断は実際の応答で行う。手順:

1. ソースから認証専用エンドポイントを特定する。
2. **セッションが有効な状態**でそこを取得し、応答を見る。
3. **トークン/クッキーを外した状態**で同じところを取得し、応答を見る。
4. 2 にあって 3 に無い文字列を `logged_in` にする。3 にあって 2 に無い文字列があれば
   `logged_out` にする。

**指標を1つも設定しないことはできない**（`configure-verification` が拒否する）。実測では、
両方未設定だと ZAP は「指標なし」と判断して**確認自体を省略**し、ポーリング先に一度も
アクセスしないまま「認証済み」を返し続ける（＝セッション失効を永久に検知しない）。

**最も危険なのは「設定したのに、失効時の応答に一致しない `logged_out`」**。実測では、
セッションが切れた後も**再認証が一度も起きず、401 を返し続けた**。エラーは出ない。
逆に「広すぎる `logged_out`」は POLL_URL では無害（ポーリング応答しか見ないため）。
広さより**失効時に一致するか**を確認すること。

指標の型は概ね3つ。いずれも対象の実応答で確認すること（フレームワーク名から推測しない）:
応答本文の固定文字列（401/403）／ログイン画面へのリダイレクトの `Location` ヘッダ／
`WWW-Authenticate` ヘッダ。

`configure-verification` は設定後に ZAP へ問い合わせて**実際に入ったか**を確認し、
`applied` で返す（`false` なら終了コード1）。**`applied: false` のときは検証設定が
存在しないので、認証済みとして扱わない。**

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
  `POLL_URL`。**新規コンテキストの既定は `EACH_RESP`＋指標なし**（＝常に認証済み扱い）。
- **POLL_URL は5パラメータ全て必須**（`pollUrl` / `pollData` / `pollHeaders` /
  `pollFrequency` / `pollFrequencyUnits`）。`pollUrl` だけだと `illegal_parameter`、
  5つ中4つだと `internal_error`。`pollData`/`pollHeaders` は**空文字が有効**なので、
  空だからと省いてはいけない（これを省いていたのが再認証ストームの発端）。
  `pollFrequency` は正の整数のみ（0・負は `illegal_parameter`）。
- **`setAuthenticationMethod` は検証設定を既定へリセットする**（実測：POLL_URL＋指標が
  EACH_RESP＋指標なしに戻る）。認証方式は検証設定より**先**に設定する。
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
5. **カナリア（`verify-canary`）** — 差分確認を通ったら、スパイダーに入る前に ZAP 自身の判定
   カウンタを確認する（下記「カナリア」）。異種のURLを3本以上渡す。
6. **確認できた場合だけ**認証後工程（3/5/6）へ進む。**曖昧・失敗・カナリア異常なら「認証済み」と
   して扱わず、run を停止する。**

## 状態モデル（工程7へ渡す）

各項目を 成功 / 失敗 / 未確定 / 未実施 ＋ 理由 ＋ 診断できなかった範囲 で記録：
認証設定・認証確認・認証後Spider・認証後Passive・認証付きActive Scan・LLM追加診断。

- **認証成功が曖昧なら認証済みとして扱わず、run を停止する。**
- **`max_attempts` 枯渇・認証失効は「認証失敗（decayed）→ run を停止」**として分類する
  （＝静かに匿名継続しない）。

## カナリア（`verify-canary`）— スパイダー前の確認

指標が正しいかを応答文字列から自前で判定するのはやめ、**ZAP自身が数えている判定カウンタ**
（`stats.auth.state.*`）を読む。ZAPがどう判断したかを直接聞くので推測が入らない。

`verify-canary` は少量の認証済みリクエストを流し、その前後のカウンタ差分を返す。

**異種のURLを3本以上渡すこと**（HTML画面／認証後のJSON API／認証と無関係なエラー）。実測では、
同種のURLだけを流すと**壊れた設定と正常な設定が同一の数値**になる（JSONのみ：どちらも
`logins=1, loggedout=0`。同じ壊れた設定をHTML画面に流すと `logins=11, loggedout=10`）。
本数が足りなければスクリプトが実行を拒否する。

検知する状態（実測に基づく）:

| 症状 | 数値 | 意味 |
|---|---|---|
| 再認証ストーム | ログイン回数 > 1 | 健全な設定は**ちょうど1回**（2回目のカナリアでは0回） |
| 検証が一度も走っていない | POLL_URL で `loggedin + assumedin == 0` | ポーリング0回＝失効を永久に検知できない |
| 指標なしで判定 | `noindicator > 0` | ZAPが無条件に「認証済み」と答える分岐 |

**限界を成果物に書くこと**：カナリアが綺麗でも、**流さなかった応答形については何も言えない**。
特に毎回チェック方式（EACH_*）では、`loggedout == 0` は健全の証明にならない。

なお認証付きスキャン（`spider-as-user` / `ajax-spider-as-user` / `active-scan-as-user`）は、
実行時に自分でカウンタを読み、ストーム中なら**起動を拒否**する。呼び出し側がフラグで「確認済み」と
申告する形にはしない（設定を選んだ本人が自分で通せてしまうため）。

## Playwright ログインへ退避しない（停止する）

「Playwright でログインできた」と「ZAP User として認証付き Spider/Active Scan できる」は**別**。
ZAP の認証機能が使えないなら、Playwright でログインできても：

- User指定 Spider（工程3）と User指定 Active Scan（工程5）は**実行できない**。
- 認証付きで動くのは工程6の LLM 駆動プローブだけになる。

これは「認証付きDAST」と呼べる状態ではないので、**Playwright へ退避せず、ZAP の認証機能が
使えないと分かった時点で停止する**。何が使えなかったのか（対応方式・Firefox の有無）を記録し、
利用者に提示する。

**早期に判定する**：主方式の Browser Based Authentication は Firefox を要求し、その有無は
工程0の `check_environment.py`（`browser_firefox`）で既に分かる。認証が有効なのに前提が
欠けているなら、**工程2.5 まで進まず工程0 で停止**してよい（同じルールを早い段階に当てるだけ）。

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
