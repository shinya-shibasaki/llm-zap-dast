---
name: DAST (LLM + OWASP ZAP)
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

工程名／番号：`0` 安全確認、`1` source-analysis、`2` target-map、`3` zap-explore、
`4` playwright、`5` active-scan、`6` scenarios、`7` report。

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
   `.gitignore` を編集しない）。

---

## 設定生成（`--init` と自動オファー）（`references/config-init.md`）

- `--init` が指定されたら：リポジトリを解析して `dast.yaml` の下書きを生成 → 提示 →
  `validate_config.py` で検証 → **確認後に書き出して停止**（スキャンは実行しない）。既存
  `dast.yaml` を無断上書きしない。
- `--init` なしで、かつ `dast.yaml`（または `--config` 指定先）が**存在しない**場合：工程0で
  「生成しますか？」と提案する。生成すればそれを使って続行、断れば既定値で続行する。

手順の詳細は `references/config-init.md` に従うこと。生成物でも安全既定
（`active_scan: false` / `allow_production: false` / `allowed_hosts` はローカル）を維持する。

---

## 工程0 — 実行条件・安全確認（`references/safety-policy.md`）

この工程はハードゲートです。安全上の失敗があれば、ここから先へ進まないでください。

1. `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/validate_config.py --config <path> --json` と
   `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/check_environment.py --config <path> --json` を実行。
   環境チェック結果を `environment-check.json` に保存する。これらの出力を**判断の一次情報**として
   使い、設定を目視で代替しないこと。
2. これらの結果と設定から次を確認：
   - 現在のディレクトリがGitリポジトリか／対象URL・対象ホスト／ZAP API接続先＋疎通／対象アプリの
     疎通／ここでActive Scanを実施してよいか／出力先／認証の要否（v1では認証を実行せず、要否のみ
     記録）／除外すべきURL・機能。
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
2. **ZAP Contextを作成し、スコープ制御を適用** — include正規表現を `allowed_hosts` に限定；
   スコープ外はスキャンしない；`exclude.paths` を Spider/Ajax/Passive/Active に適用。
   **Protectedモード**を設定（ATTACKは決して使わない）。
3. Traditional Spider。4. Passive Scan の完了を待つ。5. `scan.ajax_spider: true` なら
   Ajax Spider。6. 到達URL、HTTP履歴、アラートを取得。

フロー制御・ポーリング・JSON処理は Python ＋ `requests` で行う（reference参照）。アラートを
エクスポートしたら、保存前に redaction を通す（`zap-alerts.json` はマスク済みであること）。

---

## 工程4 — Playwrightによる探索補完（`references/scenario-testing.md`、`references/zap-integration.md`）

1. ソース抽出URLと、ZAPが実際に到達したURLを比較し、未到達を分類する（ログイン必須／JS操作
   必須／特定の画面遷移／特定のデータ／管理者権限／URLは存在するが未使用／APIが画面から直接
   呼ばれない／クローラーでは到達困難）。`reports/dast/<run-id>/coverage-analysis.md` に保存。
2. Playwright／利用可能なブラウザ操作があれば、**ZAP Proxy経由で**ブラウザを操作し（ZAP履歴へ
   記録される）、未到達画面へ遷移する。HTTPS：ZAPのルートCAを信頼させるか、証明書エラーを無視
   する（reference参照）。利用不可 → スキップ（fail-soft）。

許可される操作：ログイン、メニュー操作、フォーム送信、JS生成画面、複数ステップ遷移、権限別画面
確認。**破壊的操作は自動実行しない**（一括削除、ユーザー削除、パスワード変更、外部メール送信、
課金、外部サービス登録、本番データ変更、その他復旧不能な操作）。

---

## 工程5 — Active Scan（`references/safety-policy.md` — ゲート）

**このゲートはZAPのモードとは独立です。** Protectedモードは「スコープ外URLを触らない」を守る
だけで、下記のゲート条件がすべて揃うまで Active Scan API を呼んではいけません — スコープ内URLで
あっても、です。

**次のすべてが成立する場合のみ** Active Scanを実行：
- 対象環境が許可されている／対象ホストが `allowed_hosts` に含まれる／
  `scan.active_scan: true` が明示的に設定されている／危険なURLが除外されている／
  本番でない、または明確な許可（`safety.allow_production`）がある。

実行前に、次を表示し**利用者の明示的な確認を取る**：対象URL/ホスト、除外URL、使用するZAP
ポリシー、想定される影響。

曖昧な点があれば → Passive Scanまでで停止（Active Scanしない）。判断を記録する。

---

## 工程6 — シナリオベース診断（能動探索）（`references/scenario-testing.md`、テンプレート `templates/scenario-list.example.md`）

**本プラグインの中核。ZAP任せにせず、LLM（あなた）が能動的に探索する工程です。** 既定
（`scan.scenario_tests: true`）で常に実行し、**ZAP Active Scan とは独立**（無効でも実行する）。

診断対象マップの優先度順に、**仮説→対象固有のペイロード/リクエストを自分で組み立て→ZAP Proxy
経由で送信→応答を観察→調整・再送→確認/否定**、という能動探索ループを回す。1発で諦めない。対象例：
IDOR、水平/垂直権限昇格、認証回避、セッション不備、CSRF、業務ロジック不備、パラメータ改ざん、
Mass Assignment、HTTPメソッド変更、隠しパラメータ、アップロード制御、リダイレクト、SSRF、
注入（XSS/SQLi/テンプレート）、APIの認可不足、レート制限不足。**クラス別の安全なプローブ手順は
`references/scenario-testing.md` に従うこと。**

**重要：安全レールと能動探索は別物。** 安全レール（`allowed_hosts` 限定・`exclude.paths` 厳守・
非破壊・検出止まり・DoS相当なし・不可逆な状態変更や悪用は自動実行せず要人間）を守ったまま、
ペイロードを積極的に組み立てて探索する。安全レールは「探索するか否か」ではなく「何を壊さないか」を
縛るもの。

各シナリオに記録：ID、対象機能、想定脆弱性、根拠／前提条件、**組み立てたペイロード（機微はマスク）
・試した反復**／期待される安全な挙動 vs 脆弱時の挙動／実行可否、実行結果、証拠、追加確認事項。
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

各工程の終了時：短いサマリを出し、`--only`/`--from` のスコープ指定がない限り、次工程の前に確認を
取る。**Active Scan（工程5）の前は確認が必須。** 工程ごとの成果物は `reports/dast/<run-id>/`
配下に個別ファイルとして残し、人間が工程単位で後から読み返せるようにする。

途中で redaction 工程がスキップされたり `--keep-raw` が指定された場合は、マスク前データが含まれ得る
旨を `run.log` とレポートの両方で強く警告する。

## 実行後の後始末（クリーンアップ）

工程7の後、または途中で中断する場合も、**スキルがZAPを起動していたとき（工程3のフラグ）だけ**、
`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/zap_control.py --config <path> shutdown --json` で停止し、
`run.log` に記録する。**利用者が事前に起動していたZAPは停止しない**（フラグが立っていなければ何もしない）。

