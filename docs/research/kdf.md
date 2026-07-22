# KDF spike: workerd 上のパスワード KDF 実測(DESIGN §18 spike)

> 2026-07-22 実施。spike コードは `spike/kdf-workers/`(使い捨て、entry.py + baseline.py)。
> 結論は DESIGN §8 / §17-3 に反映済み。

## 結論(TL;DR)

1. **DESIGN §8 の前提「Pyodide に hashlib.scrypt / pbkdf2_hmac は存在しない」は現行 workerd では誤り**。
   Pyodide 3.13.2(workers-py 1.15 / wrangler 4.113 / compatibility_date 2026-07-01)には
   OpenSSL バックの `hashlib.scrypt` / `hashlib.pbkdf2_hmac` が存在し、呼び出しも成功する。
2. **OWASP 推奨パラメータの scrypt(N=2^17, r=8, p=1, 64 MiB)が workerd 上で完走する**: 約 1.0 s。
   wasm 化による遅化は CPython ネイティブ比 約 1.8x に留まる。
3. **RFC 7914 §11 の PBKDF2-HMAC-SHA256 既知ベクタが 3 実装すべてで一致**
   (CPython `hashlib` / Pyodide wasm `hashlib` / WebCrypto `deriveBits`)。
   → 同一パスワードから同一ハッシュを検証でき、**KDF のデュアルランタイム相互運用は成立する**。
4. よって §17-3 の「同一 DB を両ランタイムで使う場合に KDF を PBKDF2 に固定する設定」は**不要**。
   既定は全ランタイムで scrypt に統一できる(§17-3 は解決済みとして DESIGN を更新)。

## 実測値

環境: ローカル workerd(`pywrangler dev`、Windows 11 / Ryzen 系ラップトップ)。
比較値の CPython は同一マシンの 3.14 ネイティブ。時間は 3 回計測の範囲。

| KDF | パラメータ | CPython ネイティブ | workerd |
|---|---|---|---|
| WebCrypto PBKDF2-HMAC-SHA256 | 600k 反復 | —(N/A) | 496–824 ms |
| wasm `hashlib.pbkdf2_hmac` | 600k 反復 | 188–212 ms | 1276–1602 ms |
| wasm `hashlib.pbkdf2_hmac` | 100k 反復 | 30–33 ms | 123–139 ms |
| wasm `hashlib.scrypt` | N=2^17, r=8, p=1(64 MiB) | 539–582 ms | 971–1121 ms |

- 相互運用 KAT: RFC 7914 §11 の 2 ベクタ(c=1, c=80000, dkLen=64)が 3 実装で全一致。
- `hmac` + SHA-2(TOTP / セッショントークンハッシュに必要)も従来どおり動作。
- タイマー挙動: ローカル workerd では `time.perf_counter()`(= performance.now())と
  `js.Date.now()` が一致して素直に進む。**本番の Spectre 対策タイマー凍結下での CPU 時間
  課金の実測は未実施** — auth v0.1 の workerd 受け入れ検証(deploy)時に確認する。

## 判断への影響

- **既定 KDF は全ランタイムで `hashlib.scrypt`(OWASP N=2^17, r=8, p=1)に統一**。
  - CPython: `asyncio.to_thread` でラップ(~0.6 s の CPU 処理)。
  - Workers: 同じ scrypt がそのまま動く(~1.0 s)。イベントループは単一リクエスト内なので
    to_thread 不可でも実害なし(Workers は リクエスト分離)。
- WebCrypto PBKDF2(600k, ~0.6 s)は「Workers で速度優先」の代替バックエンドとして残す。
  PHC 文字列にアルゴリズム識別子があるため混在 verify は常に可能。
- フォールバック規則: `hashlib.scrypt` が無い環境(古い compatibility_date の Pyodide)では
  WebCrypto PBKDF2 を自動選択。既定動作は「実行環境で最良の標準 KDF」。
- 無料プラン(CPU 10 ms)ではどの KDF も成立しない。docs に「認証エンドポイントは
  有料プラン(標準 30 s CPU)前提」と明記する。
- 列挙攻撃対策のダミー KDF 実行(§9)は Workers 上で ~1 s のコストになる。
  タイミング均質化の実装はこの数値を前提に設計する。

## 再現手順と環境の罠(Windows)

spike の再現は `spike/kdf-workers/` の README 冒頭コメント参照。**このマシン(Windows 11 +
D: Dev Drive)では pywrangler が 2 つの理由でそのまま動かない**:

1. **uv のグローバル設定**(`python-downloads = "never"` / `python-preference = "only-system"`)が
   Pyodide 用 emscripten インタープリタの取得を阻む
   → コマンド単位で `UV_PYTHON_DOWNLOADS=automatic UV_PYTHON_PREFERENCE=managed` を前置して回避。
2. **uv は Windows で emscripten venv を inspect できない**(`pyodide-venv/Scripts/python.exe` の
   trampoline が子プロセス起動に失敗する。D: 上ではさらに pyvenv.cfg の home の
   ドライブレターが化ける)。workers-py の `_install_requirements_to_vendor` は
   `VIRTUAL_ENV=pyodide-venv` での `uv pip install` が**静かにプロジェクトの .venv へ
   フォールバックして exit 0** になるため、「Packages installed in python_modules.」と
   表示しつつ `python_modules/` が空になる → workerd 起動時に `ModuleNotFoundError`。
   - 回避: 依存が pure wheel のみなら手動 vendor で足りる。
     `uv pip install --python .venv --target python_modules --no-build -r pylock.toml
     --preview-features pylock` → `touch python_modules/.synced .venv-workers/.synced`
     → `pywrangler dev`(sync がスキップされ wrangler が直接起動する)。
   - 本体 CLAUDE.md の Known traps にも追記済み。upstream への報告候補
     (workers-py: フォールバック検知なし / uv: Windows の emscripten venv)。
