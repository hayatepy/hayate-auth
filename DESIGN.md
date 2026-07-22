# hayate-auth 設計ドキュメント

> better-auth(TypeScript)が確立した「マウントする認証ハンドラ」を、hayate の
> WHATWG Request / Response の上に Python で再設計する内部設計メモ(日本語)。
> 公開ドキュメントは英語先行(hayate 本体 DESIGN §15 と同じ)。
> 各節は「決定 / 理由 / 却下した代替案」の形を基本とする。

## TL;DR

- **コンセプトは一文で「認証を `fetch(Request) -> Response` の純関数として提供する」**。
  hayate アプリに 2 ルート(GET/POST の catch-all)を登録するだけで
  `/api/auth/*` 以下に認証 API 一式が生える better-auth 型。
- **コアはゼロ依存**(依存は hayate のみ。hayate 自体ゼロ依存なので推移的にもゼロ)。
  DB は `Adapter` protocol(最小 CRUD)、パスワード KDF は `CryptoBackend` protocol、
  メール送信はコールバック protocol で差し替える。
- **スキーマ(user / session / account / verification の 4 モデル)は hayate-auth が所有**。
  マイグレーション SQL は CLI が生成し、適用はユーザーが行う。
- **標準ファースト・ゲートを継承**: RFC / W3C / WHATWG / NIST に対応物のある機能だけを
  コアに入れる(§2)。標準が存在しないのはスキーマとセッション永続化だけで、
  そこが唯一の「明示的な独自部分」。
- 段階: v0.1 email/password + セッション + CSRF → v0.2 メール検証 / リセット +
  OAuth(PKCE)→ v0.3 プラグイン機構 + TOTP / magic link → passkey は extra(§18)。

```python
import os
from hayate import Hayate
from hayate_auth import Auth
from hayate_auth.adapters.sqlite import SQLiteAdapter

auth = Auth(
    secret=os.environ["AUTH_SECRET"],
    adapter=SQLiteAdapter("app.db"),
)

app = Hayate()
auth.register(app)  # app.on("GET"/"POST", "/api/auth/*") を登録するだけの糖衣

@app.get("/me", auth.require_session())
async def me(c):
    return c.json(c.get("user"))
```

---

## 1. なぜ作るか

### 1.1 Python 側の空白(2026-07-22 調査)

| 種別 | 現状 | 問題 |
|---|---|---|
| FW 結合型 | django-allauth / Flask-Security-Too / fastapi-users | 最有力の fastapi-users は公式にメンテナンスモード(新機能なし)。allauth は Django 専用 |
| プロトコル部品 | Authlib / pyjwt / py_webauthn | user management・スキーマ・セッションを持たない「材料」 |
| 別プロセス型 | Keycloak / Ory / Authentik / SuperTokens | ライブラリではなくサーバー。運用コストが別枠 |
| ホスト型 | Auth0 / Clerk / WorkOS | SaaS。自己ホストできない |
| 直接競合 | qulf(2026-05 開始、better-auth inspired) | Pydantic + argon2 + SQLAlchemy 必須、FW ごとのアダプタ量産型。edge で動かない |

PyPI 名 `better-auth` は「TS 版サーバーを叩く OpenAPI 生成クライアント」に取得済み。
better-auth 公式 org に Python 計画はない。

### 1.2 構造的理由 — better-auth の本体は「fetch ハンドラ 1 個」

better-auth が全 JS フレームワークで動くのは、コアが fetch の
`Request -> Response` ハンドラだから(Hono へは
`app.on(["GET","POST"], "/api/auth/*", c => auth.handler(c.req.raw))` の 3 行)。
Python には共通の Request/Response が無いため、認証ライブラリは FW ごとに分裂してきた。
**WHATWG Request/Response を表面に持つ hayate の上でだけ、この設計が 1:1 で成立する。**

### 1.3 hayate 側の動機

- 「standards-first は DX に変換される」という本体テーゼの最大の実証物になる
  (better-auth が Hono の採用を牽引したのと同じ構図)。
- 本体 v1.0(API 凍結)前のドッグフーディング: 公開 API の上に建てる
  最初の大型建造物として、API の欠陥を炙り出す。

### 1.4 勝負しない領域

hosted UI / enterprise IdP(SAML・LDAP)/ 他 FW アダプタの先行整備 / 管理画面。
土俵は「標準準拠」「edge で動く唯一の Python 認証」「ゼロ依存」。

---

## 2. 規範とする標準(Normative References)

本体 §2 の門番ルールを継承する: **標準文書に対応物がない機能はコアに入れない**。

| 機能 | 標準 | 対応 |
|---|---|---|
| パスワード KDF | RFC 7914(scrypt)/ RFC 8018(PBKDF2)+ OWASP Password Storage | `CryptoBackend`(§8) |
| 資格情報ポリシー | NIST SP 800-63B §5.1.1(8 文字以上・複雑性強制なし) | コアの既定バリデーション |
| セッション cookie | RFC 6265bis(`__Host-` / SameSite / HttpOnly / Secure) | §6。hayate の cookie ヘルパーを利用 |
| CSRF | W3C Fetch Metadata(`Sec-Fetch-Site`)+ RFC 6454(Origin) | §9 |
| 乱数・トークン | `secrets`(CSPRNG) | opaque token(§6) |
| ID | RFC 9562(UUIDv7、時系列ソート可能) | 全モデルの主キー。3.14 は stdlib `uuid.uuid7`、3.12/13 は同梱の準拠実装 |
| OAuth | OAuth 2.1 draft + RFC 6749 / 6750 / 7636(PKCE 必須)/ 9700(Security BCP) | v0.2(§7) |
| OIDC | OpenID Connect Core 1.0 | v0.2。id_token 検証方式は §17-2 |
| TOTP / HOTP | RFC 6238 / RFC 4226 | プラグイン(stdlib `hmac` で完結) |
| passkey | W3C WebAuthn Level 3 | プラグイン(`[passkey]` extra) |
| JWT | RFC 7519 / 7515 | **コアでは使わない**(§6 却下案)。将来の `bearer` プラグインの余地のみ |
| メール検証 / magic link | 標準なし | opaque token + 有効期限。**明示的な独自部分** |

---

## 3. アーキテクチャ

### 3.1 層構造

```
hayate アプリ:  auth.register(app) / auth.require_session()
─────────────────────────────────────────────
hayate-auth コア:  Auth.fetch(Request) -> Response   ← 本体 app.fetch と同型の純関数
                   エンドポイント表(§7)/ 各フロー実装
─────────────────────────────────────────────
protocols:  Adapter(DB CRUD) | CryptoBackend(KDF) | EmailSender
─────────────────────────────────────────────
実装:  sqlite3 / d1 / (外部: asyncpg, SQLAlchemy) | scrypt / WebCrypto | ユーザー提供
```

### 3.2 心臓部は `Auth.fetch`

コアの唯一のエントリポイントは `async def fetch(self, request: Request) -> Response`。
I/O は protocol 経由のみ。テストは Request を渡して Response を検証するだけで、
サーバーも hayate アプリも不要(本体 §13 と同じ DX)。
`auth.register(app)` は `app.on("GET"/"POST", f"{base_path}/*")` に
`await auth.fetch(c.req)` を登録するだけの糖衣で、**hayate 本体への変更要求はゼロ**。

### 3.3 better-auth から採るもの / 捨てるもの

| 採る | 捨てる | 理由 |
|---|---|---|
| スキーマ所有 + adapter protocol | Kysely 相当の内蔵クエリビルダ | protocol だけで足りる。ゼロ依存 |
| 単一ハンドラ + エンドポイント互換パス | TS 型推論前提の client SDK | Python はサーバー側。需要の証拠が出たら別配布 |
| opaque セッション + cookie cache(将来) | rate limiting 内蔵 | hayate ミドルウェア / インフラの責務(§9) |
| プラグインでコア凍結(v0.3) | 50+ プラグインの網羅 | 証拠駆動で 1 個ずつ |

---

## 4. スキーマ(所有データモデル)

better-auth と同型の 4 モデル。email/password も「credential プロバイダの account」
として保存する(social 追加時にスキーマ変更が不要になるため)。

| モデル | 主なフィールド |
|---|---|
| `user` | id, email(unique), email_verified, name?, image?, created_at, updated_at |
| `session` | id, token_hash(unique), user_id, expires_at, ip_address?, user_agent?, created_at |
| `account` | id, user_id, provider_id("credential" / "google" / …), account_id, password_hash?, access_token?, refresh_token?, expires_at?, created_at, updated_at |
| `verification` | id, identifier, value_hash, expires_at, created_at |

- 表記はテーブル / カラムとも snake_case。主キーは UUIDv7 文字列。
- **マイグレーション**: `python -m hayate_auth generate --dialect sqlite|postgres` が
  CREATE TABLE 文を stdout に出す(CLI は argparse)。自動適用はしない。
  - 理由: 本番 DB を書き換えるツールは信頼境界が別。better-auth も generate / migrate を分けている。

---

## 5. Adapter protocol

```python
class Where(NamedTuple):
    field: str
    value: Any
    op: Literal["eq", "lt", "gt", "in"] = "eq"

class Adapter(Protocol):
    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]: ...
    async def find_one(self, model: str, where: Sequence[Where]) -> dict[str, Any] | None: ...
    async def find_many(self, model: str, where: Sequence[Where], *,
                        limit: int | None = None, sort: tuple[str, str] | None = None) -> list[dict[str, Any]]: ...
    async def update(self, model: str, where: Sequence[Where], data: dict[str, Any]) -> dict[str, Any] | None: ...
    async def delete(self, model: str, where: Sequence[Where]) -> int: ...
```

- **決定**: better-auth の adapter interface と同構造の「モデル名 + dict」。ORM 非依存。
- **同梱は 2 つ**: `sqlite3`(stdlib、`asyncio.to_thread` ラップ、参照実装)と
  `d1`(Workers の JS FFI 経由。guarded import — 本体 `adapters/workers.py` と同型)。
  asyncpg / SQLAlchemy は別配布とし、需要の証拠が出てから。
- **却下**: SQLAlchemy を必須基盤にする(qulf 型)— ゼロ依存が崩れ、Workers で動かない。

---

## 6. セッションモデル

- **決定**: opaque token(`secrets.token_urlsafe(32)`)を cookie に置き、
  **DB には SHA-256 ハッシュのみ保存**。既定 cookie は
  `__Host-hayate_auth.session`(HttpOnly / Secure / SameSite=Lax / Path=/)。
  非 HTTPS(ローカル開発)では `__Host-` 接頭辞なしに自動フォールバック。
- **理由**: 即時失効ができる(JWT の構造的弱点を持たない)、DB 流出時に
  セッションを乗っ取れない(ハッシュ保存)、実装が単純。
- **却下**: JWT ステートレスセッション — RFC 対応物はあるが失効不能・トークン肥大。
  better-auth も既定は opaque。`bearer` / `jwt` はプラグインの余地のみ残す。
- better-auth の cookie cache(署名 cookie で DB 読みを回避)は将来プラグイン。
  hayate v0.2 の署名 cookie 実装をそのまま使う。

---

## 7. ハンドラ API(エンドポイント表)

パスは better-auth の API surface に揃える(概念・ドキュメントの互換、
将来 JS client を流用できる可能性のため)。`base_path` 既定は `/api/auth`。

| メソッド / パス | 機能 | 版 |
|---|---|---|
| POST `/sign-up/email` | email + password 登録 | v0.1 |
| POST `/sign-in/email` | ログイン(セッション発行) | v0.1 |
| POST `/sign-out` | セッション失効 | v0.1 |
| GET `/get-session` | 現在のセッション + user | v0.1 |
| POST `/forget-password` / `/reset-password` | リセットフロー | v0.2 |
| GET `/verify-email` | メール検証 | v0.2 |
| POST `/sign-in/social` → GET `/callback/:provider` | OAuth(PKCE) | v0.2 |

Python 側 API(表記は PEP 8):

- `auth.fetch(request)` — 純関数コア
- `auth.register(app)` — ルート登録の糖衣
- `auth.require_session()` — ミドルウェア(未認証は 401 Problem Details)。
  認証済みなら `c.set("user", …)` / `c.set("session", …)`
- `auth.get_session(request)` — ミドルウェア外での手動検証

---

## 8. CryptoBackend protocol(Workers 制約が設計を決める)

**背景(2026-07-22 spike で更新 — research/kdf.md)**: 当初調査の「Pyodide は OpenSSL 依存の
hashlib 関数を提供しない」は現行 workerd(Pyodide 3.13.2)では**誤り**と実測で判明。
`hashlib.scrypt` / `hashlib.pbkdf2_hmac` とも存在・動作し、OWASP パラメータの scrypt
(N=2^17, 64 MiB)が ~1.0 s で完走、RFC 7914 §11 ベクタが CPython / wasm hashlib /
WebCrypto の 3 実装で一致した。`hmac` + sha2 も従来どおり動く(TOTP・HMAC 署名は無事)。

```python
class CryptoBackend(Protocol):
    async def hash_password(self, password: str) -> str: ...        # PHC string format
    async def verify_password(self, password: str, stored: str) -> bool: ...
```

- **async である理由**: Workers の WebCrypto(`js.crypto.subtle`)は Promise ベース。
  CPython 実装も KDF は CPU 数十 ms かかるため `asyncio.to_thread` でラップし、
  イベントループを塞がない。
- **既定バックエンド(2026-07-22 spike で決定): 全ランタイムで `hashlib.scrypt`
  (OWASP 推奨 N=2^17, r=8, p=1, 64 MiB)に統一**。実測は research/kdf.md
  (CPython ~0.6 s / workerd ~1.0 s、同一ハッシュを相互 verify 可能)。
  - CPython: `asyncio.to_thread` でラップ。Workers: 直接呼び出し(リクエスト分離)。
  - `hashlib.scrypt` が無い環境(古い compatibility_date の Pyodide)は
    WebCrypto `deriveBits` PBKDF2-HMAC-SHA256 へ自動フォールバック。
    **ただし本番実測(2026-07-23)で Cloudflare の WebCrypto は反復 100k が上限と判明** —
    フォールバックは「互換経路(OWASP 600k 未達)」であり、OWASP 水準は hashlib 経路のみ。
  - 無料プランの CPU limit ではどの KDF も成立しない(本番実測: 0.5–2 s が確率的に
    exceededCpu)。認証エンドポイントは有料プラン(標準 30 s CPU)前提と docs に明記する。
  - 本番の isolate 揮発により in-memory ストレージは実用不可 — **D1 adapter は v0.2 スコープ**
    (research/kdf.md 本番実測 5)。
- 保存形式は PHC string format(`$scrypt$…`)。アルゴリズム識別子付きなので
  バックエンド混在でも verify 先を選べる(相互運用の残課題は §17-3)。
- **却下**: argon2-cffi 必須 — C 拡張で Workers 不可、ゼロ依存崩壊。`[argon2]` extra の余地は残す。
- **鉄則: 暗号プリミティブを自作しない**。stdlib / WebCrypto / 審査済みライブラリのみ。

---

## 9. CSRF とセキュリティ既定

- **CSRF**: SameSite=Lax が第一防衛線。加えて cookie を伴う状態変更(POST)は
  `Origin` を trusted_origins と照合し、`Origin` 欠落時は `Sec-Fetch-Site` で補助判定。
  トークン埋め込み方式は採らない(better-auth と同じ判断。標準ヘッダで足りる)。
- **open redirect**: callback / redirect 先は trusted_origins に限定。
- **列挙攻撃**: sign-in / sign-up の失敗応答とタイミングを均質化
  (`hmac.compare_digest`、存在しないユーザーにもダミー KDF 実行)。
- **rate limiting はコアに入れない**。hayate ミドルウェア / インフラの責務。
  ただしブルートフォース対策として必須構成であることを docs で明記し、サンプルを置く。

## 10. メール送信

`EmailSender` = ユーザー提供の async コールバック
(`send(to, subject, text, html=None)`)。SMTP / SES / Resend 等の実装は持たない。
理由: 送信手段は環境依存の極み。ゼロ依存維持。

## 11. プラグイン機構(v0.3 で抽出)

プラグイン = 追加エンドポイント + 追加スキーマ + before/after フック、という
better-auth の骨格は採る。ただし **v0.1–0.2 は直書きし、v0.3 で TOTP / magic link を
移植する過程で API を抽出する**(本体の validator フックと同じ実例駆動)。
先に抽象を固定しない理由: better-auth のプラグイン API は client 型推論と対で
設計されており、client を持たない Python では形が変わるはずだから。

## 12. 実行モデル

- async 単一経路(本体と同じ)。sync 版 API は作らない。
- sqlite3 / KDF など blocking 処理は `asyncio.to_thread`。
- Workers: FFI 境界(proxy lifecycle / `_js_bytes`)は本体 research §5 の知見を継承。
  構築時の secret は `from workers import env` で参照できる。

## 13. テスト戦略

- コアが純関数なので `await auth.fetch(Request(...))` を直接検証(サーバー不要)。
- **OWASP ASVS v5 の V6(認証)/ V7(セッション)を docs/asvs.md で表管理**し、
  対応済み項目数をラチェットにする(本体の wpt MIN_PASS と同型: 上げるのみ)。
- 攻撃リグレッションテスト: session fixation / 列挙タイミング / open redirect /
  CSRF / トークン再利用 / 期限切れ。
- 3 ランタイム実証: pytest 直接 / uvicorn / workerd(examples/workers)。

## 14. リポジトリ構成

```
hayate-auth/
  src/hayate_auth/
    __init__.py  auth.py  session.py  password.py  csrf.py
    routes/          # エンドポイント実装(§7)
    adapters/        # sqlite.py, d1.py
    crypto/          # scrypt.py, webcrypto.py
  tests/  docs/  examples/
```

- 依存: `hayate` のみ。extras: `[passkey]`(+ `[oidc]` は §17-2 次第)。
- Python 3.12+、uv + ruff + pytest(本体とツールチェーン共通)。
- 公開ドキュメント・docstring・コメントは英語。この DESIGN.md と research メモは日本語。

## 15. スコープ外(YAGNI リスト)

| やらないこと | 理由 |
|---|---|
| ログイン画面 / hosted UI | API のみ。hayate はテンプレート非搭載 |
| organization / RBAC / multi-tenancy | v1 まで見送り。証拠駆動 |
| SAML / LDAP | enterprise SSO は OIDC で足りる範囲のみ |
| rate limiting 内蔵 | §9。hayate ミドルウェアの責務 |
| JS client SDK | 需要の証拠待ち。パス互換により better-auth client 流用の調査余地あり |
| admin API / ダッシュボード | better-auth ですら別製品(Infrastructure)にした領域 |
| SMTP 等メール送信実装 | §10 |
| パスワード漏洩 DB 照合(HIBP) | 将来プラグイン |

## 16. リスクと対応

| リスク | 対応 |
|---|---|
| 脆弱性 = CVE 級の責任 | ASVS 駆動テスト + 攻撃リグレッション + 暗号自作禁止(§8)+ SECURITY.md + ゼロ依存(サプライチェーン面は本質的に強い)+ stable 前は beta を明示 |
| PyPI 名スクワット(`better-auth` の前例) | `hayate-auth` は 2026-07-22 時点で空きを確認済み。形になり次第 0.0.x を早期公開して確保(本体 §17 と同じ手順) |
| qulf 等の先行 | 土俵を変える: 標準準拠・edge・ゼロ依存。汎用 FW アダプタ競争はしない |
| Workers CPU limit に KDF が収まらない | 最初の spike で実測(§18)。不成立なら「ログインは CPython、検証は Workers」等の分担構成を設計してから v0.1 に進む |
| 保守の二正面(本体と並行) | コア最小 + プラグイン境界で凍結しやすくする。v1.0 は本体 v1.0 より後 |

## 17. 未決事項(要判断)

1. ~~**OAuth トークン交換の HTTP クライアント**~~ **解決(2026-07-23)**: 案 (a) を採用し、
   その実装置き場を **hayate-fetch**(WHATWG fetch 表面 + FetchBackend protocol、
   CPython=urllib+to_thread / Workers=JS fetch)として切り出す(hayate-fetch DESIGN 参照)。
   auth v0.2 は hayate-fetch に依存する(mcp クライアント等の将来消費者と実装を共有するため)。
2. ~~**OIDC id_token 検証**~~ **決定・実装(2026-07-23、v0.3)**: OIDC Core §3.1.3.7
   に依拠し **code flow 限定 + 署名検証省略**(Token Endpoint から TLS 直接受信のため
   TLS サーバー認証が JWS の代わりになる)。id_token の claims は base64 デコードのみで読む
   (`oauth.py::_decode_jwt_claims`)。JWKS 署名検証は将来 `[oidc]` extra に残す。
3. ~~**デュアルランタイムの KDF 相互運用**: scrypt ハッシュは Workers で verify できない。
   同一 DB を両ランタイムで使う構成では KDF を PBKDF2 に固定する設定が要るか。~~
   **解決(2026-07-22 spike)**: 前提が崩れた — 現行 workerd の Pyodide には
   `hashlib.scrypt` があり CPython と同一ハッシュを verify できる(research/kdf.md)。
   固定設定は不要。既定は全ランタイム scrypt 統一(§8)。
4. ~~**実装本格化のタイミング**: 本体 v1.0(API 凍結)前にドッグフーディングとして
   v0.1 を作るか、凍結後にするか。~~ **解決(2026-07-22)**: 凍結前に作った。
   本体 API の欠陥を v1.0 前に炙り出すという目的どおりの成果は下記 5。
5. hayate 本体への要望が出た場合の扱い(例: サブアプリ mount API)。
   現仮説: catch-all `app.on` で足りるため不要。
   **v0.1 実装の実測(2026-07-22)**: ルーティング・ミドルウェア・Response 構築は
   公開 API だけで足りた(catch-all 仮説は実証)。唯一の要望候補:
   `hayate.cookies` の `parse_cookies` / `serialize_set_cookie` を import して
   使ったが、これは本体の**非公開モジュール**(`__all__` 外)。本体 v1.0 凍結前に
   公開 API へ昇格するか判断を仰ぐ(凍結対象監査に載らないままだと将来壊れうる)。

## 18. マイルストーン

| 版 | 内容 | 受け入れ基準 |
|---|---|---|
| ~~**spike**~~ | **完了(2026-07-22)**: WebCrypto PBKDF2 に加え wasm hashlib.scrypt / pbkdf2_hmac を実測 | ✅ research/kdf.md に全数値。§17-3 解決(全ランタイム scrypt 統一)。本番 CPU 課金の確認だけ v0.1 の deploy 検証に持ち越し |
| ~~**v0.1**~~ | **完了(2026-07-22)**: Adapter + sqlite3 / セッション / email+password / CSRF / `require_session` | ✅ ログイン付き TODO(examples/todo)が **uvicorn とローカル workerd で無変更動作を実測**(workerd 側は wasm scrypt + sqlite + 401 ガードまで確認。vendor は Windows 回避の手動、アプリコードは無変更)。✅ ASVS V6/V7 表を docs/asvs.md に初回公開(17 covered)。テスト 41 + example 2。本番 deploy(CPU 課金実測)は公開判断時に実施 |
| v0.2 | **出荷(2026-07-23)**: verification(メール検証 / リセット)+ generate CLI + D1 adapter | メール検証 / リセットの攻撃リグレッション(単回・期限・トークン混同・全セッション失効)緑。ASVS 17→20 |
| v0.3 | **出荷(2026-07-23)**: OAuth 2.1 authorization-code + PKCE(Google / GitHub、S256)。state+verifier は HMAC 署名 cookie(DB レス、isolate 揮発耐性)。id_token は OIDC Core §3.1.3.7 で署名検証省略(§17-2)。HTTP は hayate-fetch backend 注入 | モックプロバイダで全フロー緑(PKCE challenge / state 照合 / アカウント再利用 / 未検証メール非リンク / open-redirect 拒否)。ASVS 20→23。9 テスト追加 |
| v0.3 | プラグイン機構 + TOTP + magic link | コア外のプラグインが書ける |
| v0.4 | passkey(`[passkey]` extra) | — |
| v1.0 | API 凍結 | 本体 v1.0 より後。基準は本体に倣い外部利用の証拠を要件化 |

### 決定済み(2026-07-22)

| 項目 | 決定 |
|---|---|
| 名前 | **hayate-auth**。配布名 `hayate-auth`、import 名 `hayate_auth` |
| リポジトリ | `hayatepy/hayate-auth`。**private 開始**、公開は v0.1 完成時に判断(本体と同じ戦略) |
| ライセンス / 体制 | MIT、個人名義(Yusuke Hayashi)。本体と同じ |
| 依存 | `hayate` のみ。暗号・DB・メールはすべて protocol |
| 最低 Python | 3.12(本体に合わせる) |
