# 安全ポリシー（最優先・権威）

このファイルは、**安全と進行が衝突したとき**の権威です。迷ったら停止してください。工程のスキップ
は許容されますが、**許可外ホストへの送信・スコープ拡大・サンドボックス外への副作用**は許容されません。

**前提（対象の位置づけ）**：このプラグインは**自分が所有する使い捨てのローカル脆弱アプリ**を対象と
した**実験**です。対象が使い捨てなので「対象アプリ内部を壊す」検証は既定で許可されます
（`scan.destructive`、下記ルール8A）。ただし「使い捨てだから許される」のは**対象の内部状態を壊す
場合だけ**です。サンドボックスの外（外部メール・課金・外部登録・実在の内部インフラ）に副作用が漏れる
操作（8C）と、可用性を損なう操作（8B）は別の関心事であり、破壊フラグでは解禁されません。

## 譲れないルール

1. **許可ホストのみ診断する。** `target.allowed_hosts` に無いホストへは、いかなるリクエストや
   ペイロードも送らない。実際の境界は ZAP Context のスコープ＋「スコープ外URLを叩かない」実装で
   担保し、設定検証は入口側の一次チェックとする。
2. **スコープを自動拡大しない。** 外部リンクをたどって対象化しない、発見したホストを追加しない。
   ZAP Context の `include` は `allowed_hosts` に限定し、スコープ外はスキャンしない。
3. **Active Scan は既定でON、ただしゲート制御。** 既定値が true でも、工程5のゲートを満たし、
   **かつ**利用者が明示的に確認した場合のみ実行する。無確認では走らせない。`active_scan: false`
   を明示すれば無効化できる。このゲートは**ZAPのモードとは独立**。
   **注意：Active Scan（と工程3 Spider/Ajax）は本質的に破壊的で、その破壊性は `scan.active_scan`
   ゲート＋ZAPポリシーで制御する。`scan.destructive` とは独立**であり、`scan.destructive: false` に
   しても `active_scan` を切らない限り Active Scan は破壊しうる（`scan.destructive` が制御するのは
   LLM主導の工程4・6のみ）。基本方針は「破壊OK（使い捨てローカル対象）」なので Active Scan 用の
   非破壊フラグは設けていない。
4. **ZAPはProtectedモードで動かす。ATTACKモードは禁止。** ATTACKはスコープ内の新規ノードを発見と
   同時にActive Scanするため、Active Scanゲートと衝突する。
5. **本番は既定で拒否**（`safety.allow_production: false`）。本番診断には明示的な許可が必要。
6. **APIキーが無ければローカル限定。** `zap.api_url` または `target.base_url` のホストが
   `localhost` / `127.0.0.1` / `::1` 以外なら、キーなし運用を拒否する。
7. **秘匿情報を成果物へ平文で書かない。** Cookie / Authorization / Set-Cookie / セッションID /
   CSRFトークン / JWT / PII はマスクする（`redaction.md` 参照）。認証情報やトークンをログ・
   レポートへ出力しない。
8. **破壊の扱いは3つに分ける。** かつては「破壊は一律禁止」だったが、対象が使い捨てローカルなので
   次のように分割する：
   - **8A（対象内部の破壊）＝`scan.destructive` で解禁**（既定ON、ローカル/使い捨て対象のみ）。
     ファイル/ユーザー削除、一括削除、パスワード変更、実 `DELETE`、実際に権限が上がる Mass
     Assignment、対象アプリ内部データの変更など。**非ローカル対象＋`allow_production:false` では
     `validate_config.py` が拒否**（＝本番は構造的に破壊できない）。`scan.destructive: false` を
     明示すれば従来どおり検出止まりに戻せる。破壊した場合は**何を不可逆に変えたかを記録**する
     （後続工程のカバレッジに影響するため）。
   - **8B（可用性・DoS相当）＝別軸 `scan.availability_impact`（既定OFF）**。重い time-based 探索・
     大量リクエスト・可用性を損なう負荷。使い捨て対象でも既定オフ（run 途中でアプリが落ちると以降の
     カバレッジを失うため）。レート確認は上限を決めた小さなバーストのみ（これは 8B ではない）。
   - **8C（サンドボックス外への副作用）＝破壊フラグに関係なく常に禁止**。外部メール送信、課金、
     外部サービス登録、**実在の内部インフラおよび任意の外部サービスへの SSRF**、オープンリダイレクトで
     被害者を外部へ飛ばす操作など、サンドボックスの外へ副作用が出るもの。これは「使い捨て」で
     正当化できない（境界の話であって破壊/非破壊の話ではない）。**注意：`allowed_hosts`／ZAP Context
     スコープが縛るのは「スキャナ自身が能動的に送る宛先」だけで、8C は担保しない** — SSRF は
     対象サーバ側が、オープンリダイレクトは被害者ブラウザが宛先へ到達し、宛先URLはペイロード（本文/
     パラメータ/Location）に乗るため許可リストに掛からない。8C の担保は**フラグでも allowed_hosts でも
     なく、プロンプト上の規律**：SSRF/リダイレクト/取得系の宛先を**良性のループバック／制御マーカーのみ**に
     限定し、外部メール/課金/外部登録を**発火させない**こと（`references/scenario-testing.md`）。
9. **推測と確認済み事実を、あらゆる箇所で分離する。**

## fail-soft と 停止 の区別

| 状況 | 挙動 |
| --- | --- |
| ZAP不達、Playwright不在、任意設定の欠落、対象が一時的にダウン | 工程を**スキップ**、理由を `run.log`＋レポートに記録（fail-soft） |
| ホストが `allowed_hosts` に無い／非ローカル対象・ZAPでAPIキーなし／ATTACKモード指定／設定不整合／許可のない本番／**非ローカル対象で `scan.destructive`・`scan.availability_impact` が true かつ `allow_production:false`** | **停止** — スキップしない（`validate_config.py` が拒否） |
| サンドボックス外への副作用（外部メール・課金・外部登録・実在内部インフラSSRF＝8C） | **実行しない** — 破壊フラグでも解禁されない |

fail-soft は「機能が欠けている」への答えです。「安全を担保できない」への答えではありません。後者は
実行を停止しなければなりません。

## 工程5 Active Scan ゲート（チェックリスト）

**すべて**真の場合のみ Active Scan を実行し、その後で利用者に確認する：

- [ ] 対象環境が許可されている
- [ ] 対象ホストが `allowed_hosts` に含まれる
- [ ] `scan.active_scan` が true（既定ON。`false` で明示的に無効化されていない）
- [ ] 危険なURLが `exclude.paths` に入っている
- [ ] 本番でない、または `safety.allow_production: true` かつ明示的な許可がある
- [ ] 対象URL/ホスト、除外URL、ZAPポリシー、想定される影響を提示した上で利用者が確認した

曖昧な点があれば ⇒ Passive Scanまでで停止。

**認証付き Active Scan**（`authentication.enabled` かつ認証成功時）は上記に加え、**二重ゲート**：
`scan.active_scan` **かつ** `authentication.active_scan` が true、かつ工程5確認を通ること
（`zap_auth.py active-scan-as-user` は `--gate-passed` を要求）。

## 認証（認証付きDAST時の固定ルール・`references/authentication.md`）

認証は best-effort だが、次は **LLMの都度判断に委ねず固定**（安全と、実験結果の妥当性のため）：

1. **認証情報は環境変数「名」からのみ**。設定に平文の資格情報を書かない（`validate_config.py` が
   拒否）。**値を run.log・stdout・stderr・成果物・スクショ・Playwright trace に出さない。**
2. **ZAP User の資格情報は削除で対処**（redaction では消せない）。run 終了時と中断時に必ず
   `clear-authentication`。ZAP セッションをリポジトリ配下に置かない。
3. **認証成功が曖昧なら認証済みとして扱わない。** 確認は**差分必須**（指標が認証時に有り・未認証時に
   無し。ステータス／存在のみで合格にしない）。身元依存のプローブは意図したユーザーかも確認。
4. **`max_attempts` 枯渇・認証失効 → 認証部分を停止**（fail-soft で未認証は継続、静かに匿名継続しない）。
5. **ログアウト誘発プローブ中は自動再認証（forced-user）をOFF**（ロックアウト＝可用性影響を避ける）。
6. **未ゲート／未認証のスキャン前に forced-user を明示OFF**（Context単位のため放置すると結果が濁る）。
7. **`login_url`/`verification_url` を `exclude.paths` で塞がない**（認証・再認証が壊れる。検証で拒否）。
8. **複数アカウント時（`authentication.users`）は、どのスキャン/プローブがどの User で走るかを常に
   明示**。forced-user は **Context 単位で1人しか固定できない**ため、アカウントを跨ぐ検証（水平IDOR等）
   は forced-user の張り替えではなく `--user-id` 明示の `spider/active-scan-as-user` で行う。**各
   アカウントの応答が「そのアカウント自身の身元」を反映しているか**を差分で確認する（別人のセッションに
   なっていないこと）。teardown では**全 User を削除**（`clear-authentication --user-ids`／
   removeContext が backstop）。

## 安全がどこで担保されるか

多層防御 — SKILLのプロンプトだけに依存しない：

- `validate_config.py` — 入口側の静的チェック（ホスト許可リスト、キーなし＝ローカル限定、
  ATTACKモード拒否、Active Scan安全性、**破壊（`scan.destructive`）と可用性（`scan.availability_impact`）の
  非ローカル拒否**、認証env名の有無・**`authentication.users` の各アカウント検証**、除外パス形式）。
- `check_environment.py` — 実行時チェック。ZAPが `0.0.0.0` にバインドされていないかの検知を含む。
- `redact.py` — エクスポートしたZAP JSON全体をマスク（許可リスト＋既知秘匿パターン除去）。
- ZAP Context のスコープ — 実行時の実境界。
