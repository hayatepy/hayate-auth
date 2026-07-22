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

## 3. 未実測(正直に)

- **Inspector Web UI のブラウザ内 OAuth フロー**は未実測(このセッションの環境では
  ブラウザ操作パネルが使えなかったため CLI + Bearer で代替)。ただしブラウザ相当の
  hop(login → consent → callback)は §1 の SDK E2E が同一プロトコル実装で通している。
  UI での目視一周は次回セッションの宿題(起動手順: `uv run uvicorn app:app --port 8931`
  + `npx @modelcontextprotocol/inspector`、demo@example.com / demo password 42)。
- **workerd(Workers)上の AS モード**は未実測。コアは stdlib のみ
  (hashlib/hmac/secrets/json)なので KDF spike(kdf.md)の結果から動く見込みだが、
  D1 adapter との組み合わせ実測をしてから README で謳う。
