# sast.yaml の生成支援（`--init`）

**このファイルを読んだサブエージェントは、先に
`${CLAUDE_PLUGIN_ROOT}/references/safety-core.md` と `../references/safety-policy.md` を全文読むこと。**

`sast.yaml` は無くても動きます（全キー任意）。したがってこの init の目的は「動かすために必要な設定を
作る」ことではなく、**いまどの設定で動いているのかを、読める形でリポジトリに残す**ことです。
既定値のまま動く箇所も**省略せず明示的に書き出します**——省略された既定は、設定ファイルを見ても
分からないからです。

## 起動条件

- `/llm-zap-dast:sast --init` が指定されたとき。
- **生成したら停止します。** 診断は実行しません（続けたい場合は改めて `/llm-zap-dast:sast` を実行）。
- **`--init` なしで `sast.yaml` が存在しなくても、生成を提案しません。** 設定なしで正しく動くのが
  既定の姿なので、毎回の提案はノイズになります（`dast.yaml` は必須キーがあるため提案しますが、
  こちらは事情が違います）。

## 生成手順

1. **既存ファイルの確認。** `sast.yaml`（または `--config` の指定先）が既にあれば、**無断で上書き
   しません。** 現在の内容と生成案の差分を提示し、上書き／別名で保存／中止を選んでもらいます。
2. **対象の特定。** リポジトリを軽く下見して `target.source_dir` と `target.app_kind` を決めます。
   - モノレポや `backend/` `frontend/` のような構成なら、**リポジトリ直下 `./` を既定**にします
     （両ティアを同等に見るのが攻撃マップの前提なので、片方に絞らない）。
   - アプリ本体が単一のサブディレクトリにあることが明確な場合のみ、そこを指します。
   - **リポジトリの外は指しません。** `safety.allow_outside_repo` は init では常に `false` で
     書き出します（外を読むのは事故ではなく決定であるべきなので、利用者が自分で書き換える）。
   - `app_kind` は検出できたものを書き、判断がつかなければ `auto` のままにします。
3. **既定値を明示的に書き出す。** 下記「生成物の形」のとおり、実際に効いている値を省略せずに書きます。
4. **semgrep のパックは固定しない。** `tools.semgrep.configs` は**コメントのまま**にします。
   毎回 profiling が検出した言語から選ぶ運用なので、ここで固定すると言語構成が変わったときに
   古い選定が残り続けます。**実際に使ったパックは毎回レポートの「実施したスキャン設定」に記録される**
   ので、事後に何で走ったかは追えます。
5. **`.gitignore` の整備（この init で行う）。** 出力先（既定 `reports/`）と `.env` が `.gitignore` に
   無ければ**この init で追記**します（`.gitignore` が無ければ作成）。追記は **`sast.yaml` 書き出しと
   同じ確認にまとめ、個別の同意を増やしません**（既に両方あれば何もしない）。何を追記したかは提示・
   記録します。これにより通常 run 側の `.gitignore` 同意停止（共通則 §4）は発生しなくなります。
6. **検証してから書く。** 生成案を
   `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/validate_sast_config.py --config <path> --json` に通し、
   エラーがあれば直してから確定します。**検証を通らない設定ファイルを残しません。**
7. **提示 → 確認 → 書き出し → 停止。** 何を書いたか（特に `.gitignore` への追記）を利用者に示します。

## 生成物の形

```yaml
# /llm-zap-dast:sast --init が生成。既定値も省略せず明示している。
target:
  source_dir: ./
  app_kind: web              # 検出結果。判断がつかなければ auto

safety:
  allow_outside_repo: false  # リポジトリの外は読まない

standard:
  # asvs_csv: 省略時は同梱の OWASP ASVS 5.0 を使う

tools:
  semgrep:
    required: true           # 使えない／ルールを取得できないなら停止
    # configs: 省略。毎回 profiling が検出言語から選ぶ（実際に使ったパックはレポートに記録される）

analysis:
  exclude: []                # semgrep は git 管理下のみ走査し node_modules 等は既定で除外

agents:
  model: opus

output:
  directory: reports/sast
```

コメントは**その値がなぜそうなのか**を書きます（値の言い換えは書かない）。生成物のコメントは
`examples/sast.yaml` ほど詳しくする必要はありません——手元の設定として読めれば十分です。

## 安全の既定（生成物でも維持）

- `safety.allow_outside_repo: false`（読み取り境界を既定で閉じる）
- `tools.semgrep.required: true`（静かな偽陰性を防ぐ停止条件を既定で有効に）
- `output.directory` はリポジトリ内（`.gitignore` 済み）

**init がこれらを緩めた状態で書き出すことはありません。** 緩めるのは利用者が自分で編集したときだけです。
