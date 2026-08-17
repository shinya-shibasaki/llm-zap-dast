---
name: dast
description: 現在のリポジトリ内のWebアプリに対し、ソース解析＋OWASP ZAP＋ブラウザ操作でLLM支援型グレーボックスDASTを実施する。手動実行のみ・自動起動しない。
disable-model-invocation: true
---

# /llm-zap-dast:dast

あなたは、Claude Codeで現在開いているリポジトリをソースコードとする Web アプリケーションに
対して、**LLM支援型のグレーボックスDAST**を実行します。この SKILL.md は**フロー制御に徹する
ファイル**です。詳細な手順は `references/` に、機械的な処理は `scripts/` にあります。大きな手順を
ここに展開せず、各ステップに達したら該当ファイルを読んでください。

**何かを始める前に、まず `references/safety-policy.md` を全文読むこと。** 安全と進行が衝突した
場合は、常にこのファイルが優先されます。安全が勝ちます。

`${CLAUDE_PLUGIN_ROOT}` はプラグインのルートです。スクリプトは
`${CLAUDE_PLUGIN_ROOT}/scripts/` にあります。`python3` で実行してください。

**出力言語**：利用者向けの説明・提案・確認・チェックポイントのサマリ、`--init` の説明、レポート
本文などは**日本語で行うこと**（利用者が別の言語を望む場合はそれに合わせる）。スクリプトの
コード出力やログのキー名など、機械的な文字列はそのままでよい。

---

## 引数（`$ARGUMENTS`）

`$ARGUMENTS` をパースする（空の場合もある）。サポートする形式：

- 位置引数のURL（例：`http://localhost:3000`）— `target.base_url` を上書き。
- `--config <path>` — 設定ファイルのパス（既定：リポジトリ直下の `dast.yaml`）。
- `--init` — リポジトリ解析から `dast.yaml` の下書きを生成し、確認後に書き出して**停止**する
  （スキャンは実行しない）。詳細は `references/config-init.md`。
- `--only <step>` — その工程**のみ**実行して停止。
- `--from <step>` — その工程**から**工程7まで再開。
- `--keep-raw` — マスク前の生データを保持する（既定：保持しない）。警告を出すこと。

工程名／番号：`0` 安全確認、`1` source-analysis、`2` target-map、`2.5` 認証（`authentication.enabled`
時のみ）、`3` zap-explore、`4` playwright、`5` active-scan、`6` scenarios、`7` report。

`--only` / `--from` は、Skillを分割せずに「一部だけ」「途中から」を実現する手段です。どちらも
指定がなければ工程0→7を順に実行します。`--only`/`--from` を指定した場合でも、まず工程0の安全
チェックを通す必要があります（工程をスキップして先に進む場合も、工程0を必ずゲートとして再実行し、
安全ゲートを飛ばさないこと）。

開始前に、パースした引数を利用者に返して確認できるようにしてください。

---

## fail-soft の原則

各工程：**機能（capability）の前提**が満たせない場合（ZAP不達、対象ダウン、Playwright不在、
任意設定の欠落）は、**その工程を安全にスキップ**し、全体を停止しない。スキップ理由を `run.log`
とレポートの両方に記録する。

ただし**安全（safety）の前提**が満たせない場合（許可外ホスト、設定不整合、非ローカル対象＋APIキー
なし、ATTACKモード指定）は**停止**する — スキップしない。fail-soft は「機能が欠けている」ときの
挙動であり、「安全が担保できない」ときには適用しない。`references/safety-policy.md` を参照。

**fail-soft の例外：`authentication.enabled: true`。** 認証付きで診断できないと分かったら
（ZAPの認証機能が使えない／確認が曖昧／ストーム検知／セッション失効）**停止する** — 未認証へ
degrade しない。認証有効中に **ZAPが到達不能になった場合も同様**（「ZAP不達」を機能の欠落として
スキップ扱いにしない。差し替えのZAPを自動起動して匿名のまま続行しない）。理由：利用者は認証付きの
結果を求めており、未認証の結果は別物だから。工程2.5 を参照。

---

## 実行準備（工程0の作業の前に）

1. `run-id` を決定：`YYYYMMDD-HHMMSS-<6桁hex>`（`date` ＋短い乱数/ハッシュを使い、重複しにくく
   すること）。例：`20260720-143000-a1b2c3`。
2. 設定の `output.directory`（既定 `reports/dast`）から出力先を決定し、
   `reports/dast/<run-id>/` を作成する。
3. その中に `run.log` を開始する。実行したツール／コマンド、採用した方法、そして**その理由**を
   すべて記録する（`references/zap-integration.md` に従い、方法を場当たり的に変えず、採用した
   アプローチと理由を残す）。
4. 成果物を書き出す前に、`references/redaction.md` の `.gitignore` チェックを行う
   （`reports/` と `.env` が無視対象か確認。無ければ利用者に確認してから追記 — 同意なく
   `.gitignore` を編集しない）。**`--init` を通していれば通常は追記済みで、ここでは止まらない。**

---

## 設定生成（`--init` と自動オファー）（`references/config-init.md`）

- `--init` が指定されたら：リポジトリを解析して `dast.yaml` の下書きを生成 → 提示 →
  `validate_config.py` で検証 → **確認後に書き出して停止**（スキャンは実行しない）。既存
  `dast.yaml` を無断上書きしない。
- `--init` なしで、かつ `dast.yaml`（または `--config` 指定先）が**存在しない**場合：工程0で
  「生成しますか？」と提案する。生成すればそれを使って続行、断れば既定値で続行する。

手順の詳細は `references/config-init.md` に従うこと。生成物でも安全既定
（`allow_production: false` / `allowed_hosts` はローカル）を維持する（`active_scan` は既定ON。
実行時は工程5のゲート条件を満たせば無確認で実行）。

---

## 工程0 — 実行条件・安全確認（`references/safety-policy.md`）

この工程はハードゲートです。安全上の失敗があれば、ここから先へ進まないでください。

1. `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/validate_config.py --config <path> --json` と
   `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/check_environment.py --config <path> --json` を実行。
   環境チェック結果を `environment-check.json` に保存する。これらの出力を**判断の一次情報**として
   使い、設定を目視で代替しないこと。
2. これらの結果と設定から次を確認：
   - 現在のディレクトリがGitリポジトリか／対象URL・対象ホスト／ZAP API接続先＋疎通／対象アプリの
     疎通／ここでActive Scanを実施してよいか／出力先／**認証の要否と `authentication.enabled`**／
     除外すべきURL・機能。
   - 認証有効時は追加で確認：認証情報用の環境変数が設定されているか／設定に平文の資格情報が
     書かれていないこと（`validate_config.py` が拒否）／`authentication.active_scan` の値／
     `login_url`・`verification_url` が `exclude.paths` に飲まれていないこと。**認証情報の値は
     出力しない。** 環境変数が Claude のシェルに無く `./.env` にある場合は、**Claude が同一 Bash
     呼び出しで `set -a; [ -f ./.env ] && . ./.env; set +a` して確認する**（ユーザーに `source .env`
     を頼まない。値は出さない。`references/authentication.md`「資格情報の環境変数の読み込み」）。
   - **認証の前提をここで判定して早期に停止する。** `authentication.enabled: true` で
     認証付きの診断が成立しないと分かっているなら（主方式 Browser Based Authentication に
     必要な `browser_firefox` が無い、ZAP不達で認証設定自体ができない等）、工程2.5 まで
     進まず**ここで停止**する。認証有効時の失敗は fail-soft の対象外（工程2.5 と
     `references/safety-policy.md`）。無駄な工程を走らせてから止めるより早い。
3. 設定が不足・不十分な場合：**推測せず、Active Scanを開始しない。** 不足項目を列挙する。
   ギャップが安全に関わるなら停止する。`dast.yaml` が存在しない場合は、上記「設定生成」に従って
   生成を提案する（断られたら既定値で続行）。
4. チェックポイントのサマリを出力して継続する。

---

## 工程1 — ソースコード解析（`references/source-analysis.md`）

現在のリポジトリを解析し、次を抽出する：Webフレームワークとアプリの起動方法／画面URL、API
エンドポイント、HTTPメソッド、入力パラメータ／フォームとファイルアップロード／認証・認可・
セッション処理／管理者機能、外部通信、DBアクセス／セキュリティ上重要な処理。

**ソース由来の事実と、推測した情報を明確に分ける**（各項目にラベルを付ける）。

---

## 工程2 — 診断対象マップ（`references/methodology.md`、テンプレート `templates/target-map.example.md`）

工程1をもとに診断対象マップを構築する。各エントリに含める：URL/エンドポイント＋メソッド／認証
要否＋必要な権限／入力箇所＋想定データ形式／セキュリティ上の注目点・想定脆弱性／優先度／根拠
（ソース由来か推測か）＋未確認事項。

`reports/dast/<run-id>/target-map.md` に保存。チェックポイント。

---

## 工程2.5 — 認証設定と認証確認（`authentication.enabled` 時のみ）（`references/authentication.md`、テンプレート `templates/authentication.example.md`）

**`authentication.enabled: true` は「認証付きで診断する」という約束である。** 工程2と工程3の
間で実行し、**認証付きで診断できないと分かった時点で run を停止する**（未認証で継続しない）。
未認証の結果が欲しい場合は `authentication.enabled: false` を指定する — 設定が結果の種類を決める。

停止する条件（いずれも「認証付きで診断できない」）：
- ZAPの認証機能が使えない（対応方式が無い／前提のFirefoxが無い等）。**Playwrightログインへ
  退避しない** — それはZAP User としての認証付きSpider/Active Scanができないということ。
- 認証確認が曖昧、または失敗。
- `verify-canary` が再認証ストーム／検証が一度も走っていない状態を検知（下記）。
- スキャン中にセッションが失効し回復できない（`max_attempts` 枯渇を含む）。

**停止しても後始末（`clear-authentication`）は必ず実行する** — ZAP User には平文の資格情報が
残るため。停止時は、何を検知したか（カウンタの実数）・どこまで実施したか・次に何を直すべきかを
`authentication.md` と `run.log` に記録し、利用者に提示する。

- **判断はLLM、反映は `scripts/zap_auth.py`**（判断しない薄いラッパ）。方式は `detect-capabilities`
  で対応を確認し、`method: auto` は**具体方式へ解決してから**スクリプトへ渡す（`auto` は拒否される）。
- Context/**スコープ登録**/認証方式/Session Management/Verification/User を設定し、資格情報を
  env 変数名から読む（`set-credentials`：**値は印字・保存しない**）。**認証方式 → Verification の
  順を守る**（逆順・やり直しは検証設定を消す）。
- **資格情報の環境変数は Claude が自分で読み込む。ユーザーに `source .env` を頼まない。** Bash 呼び出し
  間で環境変数は保持されないので、`.env` があれば `set-credentials` と**同じ 1 回の Bash 呼び出し**で
  `set -a; [ -f ./.env ] && . ./.env; set +a; python3 …set-credentials …` と前置きする（値は出さない）。
  詳細は `references/authentication.md`「資格情報の環境変数の読み込み」。
- **スコープ登録（`include-in-context`）を省略しない。** ZAP は Context 内のURLにしか認証を
  適用しないため、省くと**エラーも出ずに未認証でスキャンが進む**（実測：ログイン試行0回・401）。
  ここで作った Context は**工程3でもそのまま使う**（作り直さない）。
- **検証（Verification）は POLL_URL ＋ 認証専用エンドポイントを第一候補にする。** 指標は
  そのエンドポイントの「セッション有効時／無効時」の実応答を見て選ぶ（ソースは場所の手がかり）。
  `configure-verification` が返す **`applied: false` は「検証設定が入っていない」**を意味するので、
  認証済みとして扱わない。`AUTO_DETECT` と「指標ゼロ」はスクリプトが拒否する。
- **差分確認（安全の急所・必須）**：`test-authentication` は**生の証拠のみ**を返す。判定はLLM＋
  固定差分ルール——**指標が「認証時に有り・未認証時に無し」**であること（ステータスのみ／存在のみで
  合格にしない）。身元依存のプローブは**意図したユーザーか**も確認する。
  両側は**応答ヘッダ＋本文**を照合し、**リダイレクトは両側とも追従**する（セッション型では両側が
  3xxになる）。**`evidence_complete: false` は「証拠が揃っていない」＝合格にしない**（出力の
  `null` は「未観測」であって「無い」ではない）。
- **カナリア（`verify-canary`）で、スパイダー前にZAP自身の判定を確認する。** 応答文字列を
  自前で判定するのではなく、ZAPが数えている判定カウンタ（`stats.auth.state.*`）を読む。
  **異種のURLを3本以上**渡すこと（HTML画面／認証後のJSON API／認証と無関係なエラー）— 同種だけだと
  壊れた設定と正常な設定が同じ数値になる（実測）。ストーム／検証が一度も走っていない状態を検知したら
  **run を停止**する。
- **確認できた場合だけ**認証後工程へ進む。**曖昧・失敗なら認証済みとして扱わず run を停止する。**
  `max_attempts` 枯渇・認証失効も停止（静かに匿名継続しない）。
- 認証付きスキャン（`spider-as-user` / `ajax-spider-as-user` / `active-scan-as-user`）は、
  実行時に自分でカウンタを確認し、ストーム中なら**起動を拒否**する（呼び出し側の申告ではない）。
- 成果物 `reports/dast/<run-id>/authentication.md` に、方式・根拠・認証成否の証拠・未認証/認証後の
  カバレッジ差・制約を記録（機微はマスク）。チェックポイント。

詳細な手順・差分ルール・「Playwright ログインへ退避しない（停止する）」・teardown は
`references/authentication.md`。

---

## 工程3 — ZAPによる初期探索（`references/zap-integration.md`）

**ZAPの起動確認／自動起動**：まず `zap_control.py status` で疎通を見る。
- 到達可能 → 既存のZAPを使う（自動起動しない、後で停止もしない）。
- 不達 かつ `zap.autostart` 有効（既定true）→
  `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/zap_control.py --config <path> start --json` を実行。
  起動は必ず 127.0.0.1。`started: true` なら**「スキルが起動した」フラグを立てる**（後始末で停止する）。
- 不達 かつ 自動起動が無効／ZAPが見つからない／起動失敗 → **スキップ（fail-soft）**。手動起動コマンド
  （`references/zap-integration.md` 参照）を案内し、理由を `run.log` とレポートに記録。

ZAPが利用可能になったら：

1. 対象URLをZAPへ登録。
2. **ZAP Contextとスコープ制御** — **工程2.5で作成済みのContextがあれば、それを使う**
   （Contextを作り直さない：認証設定はContextに紐づくため、別Contextを作ると認証が効かなくなる）。
   無ければここで作成する。include正規表現を `allowed_hosts` に限定；スコープ外はスキャンしない；
   `exclude.paths` を Spider/Ajax/Passive/Active に適用。
   **Protectedモード**を設定（ATTACKは決して使わない）。
3. Traditional Spider。4. Passive Scan の完了を待つ。5. `scan.ajax_spider: true` なら
   Ajax Spider。6. 到達URL、HTTP履歴、アラートを取得。

**認証が成功している場合（工程2.5）**：認証済み User として実行する（`zap_auth.py spider-as-user`
／`ajax-spider-as-user`）。**認証済みで実行した探索と未認証の探索を明示的に区別**して記録する
（カバレッジ差は `authentication.md` に残す）。ZAP User として認証付き Spider が実行できないなら、
それは工程2.5 の停止条件であって未認証での続行ではない（`references/authentication.md`）。

フロー制御・ポーリング・JSON処理は Python ＋ `requests` で行う（reference参照）。アラートを
エクスポートしたら、保存前に redaction を通す（`zap-alerts.json` はマスク済みであること）。

---

## 工程4 — Playwrightによる探索補完（`references/scenario-testing.md`、`references/zap-integration.md`）

1. ソース抽出URLと、ZAPが実際に到達したURLを比較し、未到達を分類する（ログイン必須／JS操作
   必須／特定の画面遷移／特定のデータ／管理者権限／URLは存在するが未使用／APIが画面から直接
   呼ばれない／クローラーでは到達困難）。`reports/dast/<run-id>/coverage-analysis.md` に保存。
2. **Playwright が使えるかは、工程0の `check_environment.py` の `playwright` チェック結果を
   一次情報とする**（工程0と同じ原則。自分で `import playwright` を試して判断しない）。
   このチェックは「使えるかどうか」だけでなく**どのインタプリタで使えるか**を返すので、
   報告されたインタプリタをそのまま使う。**素の `python3` に入っていると仮定しない** — 対象
   リポジトリに `.venv` があると、`pip install --user` で入れた Playwright は見えず、誤って
   「無い」と判定してしまう。
3. Playwright が使えるなら、**ZAP Proxy経由で**ブラウザを操作し（ZAP履歴へ記録される）、未到達
   画面へ遷移する。HTTPS：ZAPのルートCAを信頼させるか、証明書エラーを無視する（reference参照）。
   利用不可 → スキップ（fail-soft）。**スキップした場合は工程0のチェック結果を理由として
   引用する**（「見つからなかった」で終わらせない）。

許可される操作：ログイン、メニュー操作、フォーム送信、JS生成画面、複数ステップ遷移、権限別画面
確認。工程4は**カバレッジ拡大（到達）が目的**。**破壊は工程6で意図的に行う**ものであり、工程4の
ナビゲーション中に一括削除・ユーザー削除・パスワード変更等を**巻き込みで発火させない**（データを
壊すと以降のカバレッジを失う）。`scan.destructive` が有効でも、この工程では回避する。**8C
（外部メール送信・課金・外部登録・実在内部インフラへの副作用）は常に禁止**（`references/safety-policy.md`）。

---

## 工程5 — Active Scan（`references/safety-policy.md` — ゲート）

**このゲートはZAPのモードとは独立です。** Protectedモードは「スコープ外URLを触らない」を守る
だけで、下記のゲート条件がすべて揃うまで Active Scan API を呼んではいけません — スコープ内URLで
あっても、です。

**次のすべてが成立する場合のみ** Active Scanを実行：
- 対象環境が許可されている／対象ホストが `allowed_hosts` に含まれる／
  `scan.active_scan` が true（既定ON。`false` で明示的に無効化されていない）／危険なURLが除外されている／
  本番でない、または明確な許可（`safety.allow_production`）がある。

実行前に、次を**提示・記録**する（対話確認は取らない — ゲート条件充足が実行許可）：対象URL/ホスト、
除外URL、使用するZAPポリシー、想定される影響。

曖昧な点があれば → Passive Scanまでで停止（Active Scanしない）。判断を記録する。

**認証付き Active Scan（`authentication.enabled` かつ認証成功時）**：
- **二重ゲート**。`scan.active_scan` **かつ** `authentication.active_scan` が true、**かつ**工程5の
  ゲート条件を満たしたときだけ実行（`zap_auth.py active-scan-as-user` は `--gate-passed` を要求する。
  `--gate-passed` は「ゲート条件を満たした」ことを表し、対話確認は不要）。
- **認証済みか＝明示パラメータ**。認証付きは User を明示指定。**未ゲート／未認証のつもりの Active
  Scan を呼ぶ前に `set-forced-user off`** する（forced-user は Context 単位のため、放置すると
  未認証スキャンがログイン済みユーザーとして走り結果が濁る）。
- **提示・記録**する内容に「**認証済みゆえ未認証スキャンより影響範囲が広い**」旨と、認証後に到達した
  状態変更URLを含める。認証後に発見した危険URLは `exclude.paths` 追加候補として提示（**`login_url`/`verification_url`
  は除外候補に入れない**）。Active Scan中に認証失効の可能性があれば成功と断定しない。

---

## 工程6 — シナリオベース診断（能動探索）（`references/scenario-testing.md`、テンプレート `templates/scenario-list.example.md`）

LLMがソース解析とZAP履歴から仮説を立て、対象固有のペイロード／リクエストを組み立てて送信し、
応答を観察して調整・再送し、脆弱性を確認または否定する。`scan.scenario_tests: true`（既定）のとき
実行し、ZAP Active Scan とは独立に動く（Active Scan が無効でも実行する）。

診断対象マップの優先度順に、各ターゲットへ「仮説→ペイロード作成→ZAP Proxy経由で送信→観察→
調整・再送→確認/否定」を適用する。対象はロジック系（IDOR、水平/垂直権限昇格、認証回避、セッション
不備、CSRF、業務ロジック、パラメータ改ざん、Mass Assignment、メソッド改ざん、隠しパラメータ、
リダイレクト、APIの認可不足、レート制限）と注入系（XSS、SQLi、テンプレート注入/SSTi、XXE、
ファイルアップロード、SSRF）の両方。クラス別のプローブ手順は `references/scenario-testing.md` に従う
（逆シリアライズはソース検出中心・確認は要人間のノート扱い）。

安全制約を守る：`allowed_hosts` のみ送信・`exclude.paths` 除外。**破壊は `scan.destructive`
（既定ON・使い捨てローカル対象）で解禁**され、対象アプリ内部の不可逆な状態変更まで踏み込んで確認して
よい（削除・更新・権限昇格の実行など）。ただし **8C（外部メール・課金・外部登録・実在内部インフラ
SSRF）は常に禁止**、**8B（DoS相当・重い time-based・大量負荷）は `scan.availability_impact`
（既定OFF）でのみ許可**。`scan.destructive: false` のときは検出止まり（悪用・状態変更は
要人間）。**ただし 8A には下限がある**：アプリが意図した保存先への良性・一意マーカーの**新規追加**は
8A ではなく `destructive: false` でも実行してよい（`references/safety-policy.md` ルール8A）。
**8C は手法ではなく宛先で決まる**（OOB 自体は 8C でない。宛先の線引きと外部送信機能の事前判定は
`references/scenario-testing.md`）。安全制約は送信してよい範囲と行ってはならない操作を定めるものであり、制約の内側であれば
ペイロードを能動的に組み立てて送信する。**破壊的に確認した項目は「何を不可逆に変えたか」を記録**する
（後続カバレッジへの影響のため）。詳細は `references/scenario-testing.md`。

**認証が成功している場合（工程2.5）**、認証後のZAP履歴とソースを使って認可・セッション系も診断する。
- **実施できる範囲はアカウント構成で決まる**（`authentication.users`）。**同一ロール2アカウント**が
  あれば水平IDOR・水平権限昇格・「別人のトークン」系が可能。**異なるロール**（低権限＋管理者）が
  あれば垂直権限昇格の拒否確認が明確化。**3アカウント**（同一ロール2＋管理者）なら水平＋垂直の両方。
  **単一アカウント**では水平系は構造的に不可能なので「単一アカウントのため未実施」と記録する（垂直昇格の
  拒否確認・認証回避・強制ブラウズ・同一ユーザーのセッション/JWT改ざん・CSRF・自分へのMass Assignment
  等は単一でも可能）。**どのプローブをどの User で実行したかを明示**し、アカウントを跨ぐ検証は
  `--user-id` 明示の scan/プローブで行う（forced-user は1人しか固定できない）。
- **ログアウトを誘発するプローブ（セッション無効化・ログアウト後・別トークン）の実行中は
  自動再認証（forced-user）をOFF**にし、終了後に意図的に張り直す。さもないと再ログイン連打で
  ロックアウト＋`max_attempts` 枯渇 → 以降が静かに匿名化する。詳細は `references/scenario-testing.md`。

**工程6の完了条件（無言の打ち切り禁止）**：診断対象マップの**優先度 高／中**の各エントリに、該当する
プローブクラスの「実行済みプローブ＋判定、または未実施＋理由」が揃うまで完了としない（高価値プローブ
数本での自己判断の切り上げを禁じる）。`scenarios.md` に「対象×クラス→判定」のカバレッジ行列を残し、
**未実施を第一級で明示**する。該当しないクラスまで総当たりはしない（文脈適合を崩さない）。DoD は安全停止に
劣後し、行列を埋めるために 8B／`scan.destructive` を有効化しない。詳細は `references/scenario-testing.md`。
**「要人間」は例外**：判定は `references/scenario-testing.md` の決定木で一意に決める——①安全かつフラグの
範囲で確認できるなら**実行**（手持ちの Playwright/ZAP/curl で確認できる項目を格下げしない。自己検証は
8Cでない）／②越えられない安全境界（8C要・8B要・8Aだが `destructive:false`・人間判断）なら**要人間**／
③それ以外で撃てない（能力欠如・運用上の回避・除外パス・時間切れ）なら**未実施（理由）**。
詳細は `references/scenario-testing.md`・`references/safety-policy.md`。

各シナリオに記録：ID、対象機能、想定脆弱性、根拠／前提条件、組み立てたペイロード（機微はマスク）・
試した反復／期待される安全な挙動と脆弱時の挙動／実行可否、実行結果、証拠、追加確認事項。
`reports/dast/<run-id>/scenarios.md` に保存。チェックポイント。

---

## 工程7 — 結果整理・レポート（`references/report-format.md`、テンプレート `templates/report.example.md`）

ZAPアラート＋シナリオ結果を分析。次を分ける：
- ツール検出の事実／HTTPで確認できた事実／ソースで確認できた事実／LLMの推測
- 再現できた／再現できなかった／誤検知の可能性／人間の確認が必要

**根拠のない断定をしない。** `findings.md` を書き、次に `references/report-format.md` に列挙した
15セクションからなる最終 `report.md` を作成する（概要、対象、日時、ツール、実行工程＝スキップ＋
理由を含む、探索範囲、未到達範囲、検出結果、再現確認、証拠、リスク、修正案、未確認事項、制約、
免責）。

さらに `execution-summary.json`（実行/スキップした工程＋理由、run-id、所要時間）を書く。

---

## チェックポイント

各工程の終了時：短いサマリを出し、**確認は取らずそのまま次工程へ進む**（対象は使い捨てローカルの
テストアプリ前提。内容に問題が無ければ工程ごとに手を止めない）。工程ごとの成果物は
`reports/dast/<run-id>/` 配下に個別ファイルとして残し、人間が工程単位で後から読み返せるようにする。

**全工程を無確認で進む（Active Scan＝工程5 を含む）。** Active Scan は破壊的なので、実行前に対象/除外/
ZAPポリシー/想定影響を**提示・記録**するが、**対話確認は取らない** — ゲート条件（`allowed_hosts`・
`scan.active_scan: true`・危険URL除外・非本番または許可）を満たすこと自体が実行の許可となる
（使い捨てローカルのテストアプリ前提）。ゲート条件が未充足・曖昧なら Passive までで停止する（下記の安全判定）。

**安全上の停止条件は「確認」とは別**：許可外ホスト、本番なのに許可なし、設定不整合、認証有効での
認証失敗・ZAP不達・再認証ストーム・`max_attempts` 枯渇などに該当したら、確認の有無に関わらず
**停止**する（これは対話確認ではなく安全判定なので、無確認モードでもスキップしない）。

途中で redaction 工程がスキップされたり `--keep-raw` が指定された場合は、マスク前データが含まれ得る
旨を `run.log` とレポートの両方で強く警告する。

## 実行後の後始末（クリーンアップ）

工程7の後、または途中で中断する場合も：

1. **認証を設定していたら（工程2.5）、必ず `zap_auth.py clear-authentication` を呼ぶ** — 一時
   User/Context を削除する。ZAP User には**平文の資格情報が残る**ため、これは redaction では
   代替できない（削除が唯一の対策）。ZAP セッションをリポジトリ配下に置かない。消せなければ
   `run.log` と成果物に警告を残す。中断時も必ず実行する。
2. **スキルがZAPを起動していたとき（工程3のフラグ）だけ**、
   `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/zap_control.py --config <path> shutdown --json` で停止し、
   `run.log` に記録する。**利用者が事前に起動していたZAPは停止しない**（フラグが立っていなければ
   何もしない）。

