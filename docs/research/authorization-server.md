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

## 4. 未実測(正直に)

- **Inspector Web UI のブラウザ内 OAuth フロー**は未実測(このセッションの環境では
  ブラウザ操作パネルが使えなかったため CLI + Bearer で代替)。ただしブラウザ相当の
  hop(login → consent → callback)は §1 の SDK E2E が同一プロトコル実装で通している。
  UI での目視一周は次回セッションの宿題(起動手順: `uv run uvicorn app:app --port 8931`
  + `npx @modelcontextprotocol/inspector`、demo@example.com / demo password 42)。
- **mcp SDK 込みの 1 アプリを workerd に載せる統合**(examples/mcp-oauth 相当の Workers 版)
  は未実測。AS 側(§3)と mcp の Workers stateless 経路(mcp research/pyodide.md)は
  それぞれ実証済みなので、残るのは bundle 統合のみ。証拠が要るのは D1 共有と依存サイズ。
