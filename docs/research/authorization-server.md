# AS モード実機検証ログ(v0.6、2026-07-23)

> DESIGN §19 の受け入れ実測。環境: Windows 11 / Python 3.14 / uvicorn 0.51 /
> mcp SDK 1.28 系(examples/mcp-oauth の uv.lock が正確な版)。

## 1. 公式 MCP SDK クライアントでの OAuth 完全一周(自動 E2E、CI 常設)

`examples/mcp-oauth/tests/test_e2e.py`。実 HTTP(uvicorn 子プロセス、port 8931)で
SDK の `OAuthClientProvider` + `streamable_http_client` を使用 — MCP Inspector /
Claude Code と同じ実装が同じ経路を踏む。**2 テストとも緑**:

1. `test_unauthenticated_request_points_at_the_metadata`
   - 素の POST /mcp → **401** + `WWW-Authenticate: Bearer resource_metadata="…"`
   - GET `/.well-known/oauth-protected-resource` → resource / authorization_servers が期待値
   - GET `/.well-known/oauth-authorization-server` → issuer 一致(RFC 8414)
2. `test_official_client_full_oauth_round_trip`
   - SDK が **RFC 7591 DCR で自己登録** → authorize へ。browser hop は httpx
     セッションで代行(サインイン済み cookie で GET /authorize → 302 /consent →
     POST /oauth2/consent {accept:true} → redirect_uri から code/state 取得)
   - SDK が PKCE(S256)検証つきで token 交換 → Bearer 付き initialize →
     `tools/list` → `tools/call("echo")` まで**フル一周成功**

要点: 401 からの discovery チェーン(RFC 9728 → RFC 8414)、open DCR、
S256 PKCE、RFC 8707 resource バインドのすべてを公式クライアント実装が踏破した。

## 2. MCP Inspector CLI 実測(手動)

デモアプリを uvicorn で起動し、フル OAuth フロー(sign-up → DCR → authorize →
consent → token)をスクリプトで回して実トークンを取得、Inspector CLI に注入:

```sh
npx @modelcontextprotocol/inspector --cli http://127.0.0.1:8931/mcp \
  --transport http --header "Authorization: Bearer hat_…" --method tools/list
# → {"tools": [{"name": "echo", …}]}

npx … --method tools/call --tool-name echo --tool-arg text="inspector over oauth"
# → {"content": [{"type": "text", "text": "echo: inspector over oauth"}], "isError": false}
```

- トークンなしの同コマンドは **401 `{"title":"Authorization required"}`** で拒否
  (Inspector 側エラー表示も確認)。
- 既知のノイズ: Windows の Node 24 で Inspector CLI 終了時に libuv の
  `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING)` が出るが、
  結果出力後のプロセス終了時 assert であり測定には無関係。

## 3. workerd + D1 実測(2026-07-23、spike/as-workers、0.6.0 公開後)

環境: ローカル workerd(`pywrangler dev`、workers-py 1.15.0)+ wrangler ローカル D1
(miniflare SQLite)。**PyPI の hayate-auth 0.6.0 を vendor**(pylock が PyPI 解決 —
0.0.x 早期公開が検証インフラを兼ねる、の実利がここでも効いた)。

- `generate --dialect d1` の DDL が `wrangler d1 execute AUTH_DB --local --file` で
  そのまま通り、AS の 4 テーブルが作成された。
- **フル一周 ALL GREEN**(httpx スクリプト、実測タイミング):

  | ステップ | 実測 |
  |---|---|
  | sign-up(wasm `hashlib.scrypt`、OWASP N=2^17) | 497.9 ms |
  | DCR(RFC 7591) | 12.8 ms |
  | authorize → 302 consent(署名 cookie) | 18.5 ms |
  | consent → code | 20.1 ms |
  | token 交換(PKCE 検証 + D1 書き込み) | 19.7 ms |
  | GET /protected(Bearer 検証、resource 束縛) | 11.1 ms |
  | refresh rotation | 20.3 ms |

- 無トークンは 401。**refresh reuse → `invalid_grant` + family 失効**(rotation 後の
  access token も 401)が workerd + D1 上でも成立(RFC 9700 防御の実機確認)。
- **プロセス再起動をまたいで access token が有効のまま**(再起動後、発行済みトークンで
  /protected → 200)。本番実測(kdf.md 発見 5)の isolate 揮発問題が、AS モードでは
  D1 永続で解決されていることの直接の証拠。
- Windows の pywrangler 罠 2(vendor の静かな失敗 → `ModuleNotFoundError`)は
  **workers-py 1.15.0 でも残存**。kdf.md の手動 vendor 手順(`uv pip install --python
  .venv --target python_modules --no-build -r pylock.toml --preview-features pylock` +
  `.synced` touch)で回避。罠 1(UV env 前置)も引き続き必要。

## 4. MCP + AS を 1 つの Worker で(2026-07-23、同 spike に mcp を統合)

spike/as-workers に hayate-mcp 0.5.0 を追加し、**単一の workerd isolate で
「AS(トークン発行)+ MCP RS(検証・実行)+ D1」を実測**:

- pylock は Pyodide index 込みで期待どおり解決: **mcp 1.12.4**(Workers の既知フロア)+
  `pydantic_core 2.27.2` wasm wheel。手動 vendor は wasm platform 指定
  (mcp research/pyodide.md の手順、`.synced` は `printf '1.15.0'` — 空 touch 不可)。
- mcp の遅延 import 規律(グローバルスコープの entropy 禁止)は
  hayate-mcp examples/workers のパターンをそのまま流用。
- 実測結果(すべて workerd 上):
  - GET `/.well-known/oauth-protected-resource` → RFC 9728 PRM(resource=/mcp、
    authorization_servers=[同一 origin])
  - 未認証 POST /mcp → **401** + `WWW-Authenticate: Bearer resource_metadata="…"`
  - AS フロー(resource=/mcp)で取得した Bearer 付き initialize → **200**、
    `protocolVersion: 2025-06-18`(SDK 1.12.4 — ランタイム依存の documented subset どおり)
  - **MCP Inspector CLI の `tools/call` が成功**(`echo: one worker, oauth + mcp`)
  - バンドル: Total 4226 modules / ~44.1 MiB(mcp research/pyodide.md の ~43.5 MiB と整合)

**発見(要修正、hayate-mcp 側)**: `WWW-Authenticate` の `resource_metadata` URL が
`{resource}/.well-known/oauth-protected-resource`(パス後置)になる一方、実際に PRM を
serve するのは常にルートの `/.well-known/oauth-protected-resource`。**RFC 9728 §3.1 の
正規形式は path-insertion**(resource にパスがある場合
`/.well-known/oauth-protected-resource/mcp`)であり、ヘッダと serve パスが互いにも
仕様にも一致していない。クライアント(SDK / Inspector)はフォールバック探索で PRM を
見つけるため実害が出ていなかった。→ **hayate-mcp 0.6.0 で是正・PyPI 公開済み**
(metadata_url / serve パス / register を path-insertion に統一)。workerd 上で再実測:
`/.well-known/oauth-protected-resource/mcp` が 200、401 の広告 URL が serve パスと一致、
是正前に発行したトークンも D1 経由で有効のまま(vendor 更新 + 再起動をまたいだ)。
uvicorn 側も examples/mcp-oauth の E2E を mcp 0.6.0 で再実行して緑
(SDK クライアントの一周 + 広告 URL 一致のアサーション追加)。

## 5. Workers 本番 deploy 実測(2026-07-23、AS-only)

`pywrangler deploy` 相当を実アカウント(無料プラン)で実施。
URL: https://hayate-auth-as-spike.digiman-haya-labs.workers.dev(実 D1
`hayate-as-spike`、schema は `wrangler d1 execute --remote --file` で適用)。

**本番でだけ判った罠 4 つ**(いずれもローカル workerd では顕在化しない):

1. **deploy 時の validator はグローバルスコープを bindings / vars なしで実行する**。
   モジュールトップの `D1Adapter(env.DB)` は `AttributeError: DB` で validation 失敗
   (vars も同様に未接続で、`getattr(env, "ISSUER", None)` は None に落ちる)。
   → Auth / mount の構築は**初回リクエスト時に遅延**が必須。ローカル dev は
   グローバルアクセスを許すため、dev 緑 → deploy 赤の罠になる。
2. **無料プランの Worker サイズ上限 3 MiB に mcp 込み bundle は載らない**
   (wasm `pydantic_core` .so 単体で 4 MiB、全体 44 MiB / gzip 前)。
   AS-only(hayate + hayate-auth + hayate-fetch、pure wheel、python_modules 588 KiB)
   は問題なく載る。**MCP+AS 込みの本番は Workers Paid(上限 10 MiB)で要再検証**
   (gzip 後に収まるかは未検証のまま)。
3. **pywrangler deploy は `.venv` / `.venv-workers` を bundle に巻き込む**
   (AS-only でも 1995 modules / 18 MiB になり 3 MiB 超過)。回避: entry.py +
   wrangler.toml + python_modules だけのクリーンディレクトリから素の
   `npx wrangler deploy`。
4. workers.dev のサブドメインはアカウント毎(このアカウントは
   `digiman-haya-labs`)。`[vars] ISSUER` は初回 deploy で URL を確認してから確定。

**フル AS フロー ALL GREEN(本番 edge、実 D1、HTTPS)**:

| ステップ | 実測(初回、cold start 含む) |
|---|---|
| sign-up(wasm scrypt **log_n=14** — 無料プラン CPU 対策の spike 用低コスト) | 1940.6 ms |
| DCR | 37.8 ms |
| authorize → 302 consent | 62.0 ms |
| consent → code | 98.4 ms |
| token 交換(PKCE + 実 D1 書き込み) | 94.5 ms |
| GET /protected(Bearer) | 25.3 ms |
| refresh rotation | 88.9 ms |

- 無トークン 401 / refresh reuse → family 失効も実 D1 上で成立。
- HTTPS なので **`__Host-` プレフィックス + Secure cookie の経路が初めて本物**
  (セッション cookie・authorize の署名 pending cookie とも)。httpx の jar 経由で
  全フローが通った = 属性が正しく機能。
- KDF の本番既定コスト(N=2^17)は無料プランで確率的 exceededCpu(kdf.md 実測済み)
  のため、この spike は log_n=14 で AS フロー自体の検証に集中した。
  **認証エンドポイントの本番は有料プラン前提**という docs の前提は変わらない。

## 6. 未実測(正直に)

- **Inspector Web UI のブラウザ内 OAuth フロー**は未実測(2 セッションで再試行したが
  ブラウザ操作パネルが表示されない環境のため CLI + Bearer で代替)。ただしブラウザ相当の
  hop(login → consent → callback)は §1 の SDK E2E が同一プロトコル実装で通している。
  UI での目視一周は人間の手で 5 分の宿題(起動手順: `uv run uvicorn app:app --port 8931`
  + `npx @modelcontextprotocol/inspector`、demo@example.com / demo password 42)。
- **MCP+AS 込みの本番 deploy**: AS-only は §5 で本番緑。mcp 込み bundle は無料プランの
  3 MiB を超える(§5 罠 2)。Workers Paid(10 MiB)にすれば試せるが、gzip 後に
  収まるかは未検証 — プラン変更は課金判断なので保留。
