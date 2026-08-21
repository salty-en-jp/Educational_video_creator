"""
動画学習プロトタイプ - バックエンド (FastAPI)

設計の核心:
- 動画はRange対応で配信(シーク・部分読み込みが正しく動く)
- 視聴の連続性をサーバー側で検証する(クライアントの自己申告を信用しない)
- 動画を一定幅のセグメントに区切り、「連続再生で通過した区間」だけを視聴済みにする
- シーク飛ばし・極端な早送りは視聴済みにカウントしない
- 視聴済みセグメントが閾値を超えたら修了
"""

import json
import os
import re
import sqlite3
import time
import hashlib
import secrets
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).parent
VIDEO_DIR = BASE_DIR / "videos"
DB_PATH = BASE_DIR / "viewing.db"
CATALOG_PATH = BASE_DIR / "videos.json"
QUIZ_PATH = BASE_DIR / "quizzes.json"

# --- 視聴判定のパラメータ -------------------------------------------------
SEGMENT_SECONDS = 5          # 動画を何秒刻みで区切って視聴管理するか
MAX_SPEED_FACTOR = 2.5       # 実時間に対してこの倍率を超える進み方は「早送り」とみなしカウントしない
COMPLETION_RATIO = 0.9       # 全セグメントのうち、この割合を視聴したら修了
HEARTBEAT_MAX_GAP = 30       # 前回ハートビートからこれ以上空いたら「離席」とみなし区間を埋めない(秒)

# 管理者にするユーザー名(ここに書いた名前で登録・ログインすると管理画面が使える)
ADMIN_USERNAMES = {"admin"}
# -------------------------------------------------------------------------


def load_catalog():
    """videos.json から動画カタログ(id, タイトル, ファイル名, 長さ)を読む"""
    if not CATALOG_PATH.exists():
        return {}
    with open(CATALOG_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {v["id"]: v for v in data}


CATALOG = load_catalog()


def load_quizzes():
    """quizzes.json を読む。正解(answer)と解説(explanation)はサーバー内だけで保持する。"""
    if not QUIZ_PATH.exists():
        return {}
    with open(QUIZ_PATH, encoding="utf-8") as f:
        return json.load(f)


QUIZZES = load_quizzes()


def save_catalog():
    """CATALOG を videos.json に書き戻す。"""
    with open(CATALOG_PATH, "w", encoding="utf-8") as f:
        json.dump(list(CATALOG.values()), f, ensure_ascii=False, indent=2)


def save_quizzes():
    """QUIZZES を quizzes.json に書き戻す。"""
    with open(QUIZ_PATH, "w", encoding="utf-8") as f:
        json.dump(QUIZZES, f, ensure_ascii=False, indent=2)


# --- DB -------------------------------------------------------------------
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        # ユーザーごと・動画ごとの視聴済みセグメントを記録
        # segment_index = position // SEGMENT_SECONDS
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watched_segments (
                user_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                segment_index INTEGER NOT NULL,
                PRIMARY KEY (user_id, video_id, segment_index)
            )
            """
        )
        # 直近のハートビート状態(連続性の検証に使う)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS last_heartbeat (
                user_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                position REAL NOT NULL,
                server_time REAL NOT NULL,
                PRIMARY KEY (user_id, video_id)
            )
            """
        )
        # クイズの正解記録(誰がどのクイズに正解したか)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quiz_results (
                user_id TEXT NOT NULL,
                video_id TEXT NOT NULL,
                quiz_id TEXT NOT NULL,
                PRIMARY KEY (user_id, video_id, quiz_id)
            )
            """
        )
        # ユーザー(パスワードはハッシュ化して保存。平文では保存しない)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                pw_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        # ログインセッション(token -> username)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )


def ensure_admin_accounts():
    """
    ADMIN_USERNAMES に列挙した名前のアカウントを用意する。
    重要: この名前は /api/register からは作れない(下記参照)。ここでDBに
    存在しなければ作成することで、「早い者勝ちでadminを名乗る」なりすましを防ぐ。
    パスワードは環境変数 ADMIN_PASSWORD があればそれを使い、無ければランダム生成して
    起動時に一度だけコンソールに表示する(現状パスワード変更機能はないため必ず控えること)。
    """
    password = os.environ.get("ADMIN_PASSWORD")
    generated = password is None
    if generated:
        password = secrets.token_urlsafe(12)

    with get_db() as conn:
        for name in ADMIN_USERNAMES:
            exists = conn.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone()
            if exists:
                continue
            salt = secrets.token_hex(16)
            pw_hash = hash_password(password, salt)
            conn.execute(
                "INSERT INTO users (username, pw_hash, salt, created_at) VALUES (?,?,?,?)",
                (name, pw_hash, salt, time.time()),
            )
            if generated:
                print(f"[初回起動] 管理者アカウント '{name}' を作成しました。初期パスワード: {password}")
                print("           このパスワードは今しか表示されません。控えてからログインしてください。")


# --- 認証ヘルパー ---------------------------------------------------------
def hash_password(password: str, salt: str) -> str:
    """pbkdf2-sha256 でパスワードをハッシュ化(標準ライブラリのみ)。"""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return dk.hex()


def current_user(request: Request) -> str:
    """
    セッションCookieからログイン中のユーザー名を取り出す。
    重要: 受講者の識別はここ(サーバー側)で行い、ブラウザが送るIDは信用しない。
    未ログインなら 401。
    """
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="ログインが必要です")
    with get_db() as conn:
        row = conn.execute(
            "SELECT username FROM sessions WHERE token=?", (token,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="ログインが必要です")
    return row["username"]


def current_admin(username: str = Depends(current_user)) -> str:
    """管理者のみ通す。受講者がアクセスしたら 403。"""
    if username not in ADMIN_USERNAMES:
        raise HTTPException(status_code=403, detail="管理者権限が必要です")
    return username


# --- 動画配信 (Range対応) --------------------------------------------------
def ranged_response(path: Path, request: Request):
    """HTTP Range リクエストに対応した動画配信。シークと部分読込のために必須。"""
    file_size = path.stat().st_size
    range_header = request.headers.get("range")

    if range_header is None:
        return FileResponse(path, media_type="video/mp4")

    # "bytes=START-END" をパース
    m = re.match(r"bytes=(\d+)-(\d*)", range_header)
    if not m:
        raise HTTPException(status_code=416, detail="Invalid Range header")
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else file_size - 1
    end = min(end, file_size - 1)
    if start > end:
        raise HTTPException(status_code=416, detail="Range not satisfiable")

    chunk_size = end - start + 1

    def iterfile():
        with open(path, "rb") as f:
            f.seek(start)
            remaining = chunk_size
            while remaining > 0:
                block = f.read(min(65536, remaining))
                if not block:
                    break
                remaining -= len(block)
                yield block

    headers = {
        "Content-Range": f"bytes {start}-{end}/{file_size}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(chunk_size),
        "Content-Type": "video/mp4",
    }
    return StreamingResponse(iterfile(), status_code=206, headers=headers)


# --- アプリ ---------------------------------------------------------------
app = FastAPI(title="動画学習プロトタイプ")


@app.on_event("startup")
def startup():
    init_db()
    ensure_admin_accounts()


# --- 認証エンドポイント ---------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


@app.post("/api/register")
def register(cred: Credentials):
    """新規ユーザー登録。プロトタイプでは誰でも登録可(本番では管理者発行などに変える)。"""
    username = cred.username.strip()
    if not username or not cred.password:
        raise HTTPException(status_code=400, detail="ユーザー名とパスワードを入力してください")
    if username in ADMIN_USERNAMES:
        # 管理者名は自己登録では作れない(誰でも管理者を名乗れてしまうのを防ぐ)。
        # 管理者アカウントはサーバー起動時に ensure_admin_accounts() が自動で用意する。
        raise HTTPException(status_code=403, detail="このユーザー名は登録できません")
    if len(cred.password) < 4:
        raise HTTPException(status_code=400, detail="パスワードは4文字以上にしてください")
    salt = secrets.token_hex(16)
    pw_hash = hash_password(cred.password, salt)
    with get_db() as conn:
        exists = conn.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="そのユーザー名は既に使われています")
        conn.execute(
            "INSERT INTO users (username, pw_hash, salt, created_at) VALUES (?,?,?,?)",
            (username, pw_hash, salt, time.time()),
        )
    return {"ok": True, "username": username}


@app.post("/api/login")
def login(cred: Credentials, response: Response):
    """ログイン。成功するとセッションCookieを発行する。"""
    username = cred.username.strip()
    with get_db() as conn:
        row = conn.execute(
            "SELECT pw_hash, salt FROM users WHERE username=?", (username,)
        ).fetchone()
        # ユーザーの有無に関わらず同じエラーにして、存在を漏らさない
        if not row or hash_password(cred.password, row["salt"]) != row["pw_hash"]:
            raise HTTPException(status_code=401, detail="ユーザー名またはパスワードが違います")
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, username, created_at) VALUES (?,?,?)",
            (token, username, time.time()),
        )
    # HttpOnly: JSから盗まれにくくする。LANのHTTPなのでSecureは付けない(本番のHTTPSでは付ける)
    response.set_cookie("session", token, httponly=True, samesite="lax", max_age=60 * 60 * 24 * 7)
    return {"ok": True, "username": username}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    """ログアウト。セッションを破棄する。"""
    token = request.cookies.get("session")
    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    response.delete_cookie("session")
    return {"ok": True}


@app.get("/api/me")
def me(username: str = Depends(current_user)):
    """ログイン中のユーザー名と管理者フラグを返す(未ログインなら401)。"""
    return {"username": username, "is_admin": username in ADMIN_USERNAMES}


# --- 管理者用 -------------------------------------------------------------
@app.get("/api/admin/overview")
def admin_overview(admin: str = Depends(current_admin)):
    """
    全受講者 × 全動画の進捗一覧を返す(管理者のみ)。
    各セル: 視聴割合・修了フラグ・通過したクイズ数。
    """
    # 動画ごとのメタ(総セグメント数・総クイズ数)
    video_meta = []
    for v in CATALOG.values():
        total_segments = max(1, int(v["duration"] // SEGMENT_SECONDS) + 1)
        video_meta.append({
            "id": v["id"],
            "title": v["title"],
            "total_segments": total_segments,
            "total_quizzes": len(QUIZZES.get(v["id"], [])),
        })

    with get_db() as conn:
        users = [r["username"] for r in conn.execute(
            "SELECT username FROM users ORDER BY username"
        ).fetchall()]
        seg_rows = conn.execute(
            "SELECT user_id, video_id, COUNT(*) c FROM watched_segments GROUP BY user_id, video_id"
        ).fetchall()
        quiz_rows = conn.execute(
            "SELECT user_id, video_id, COUNT(*) c FROM quiz_results GROUP BY user_id, video_id"
        ).fetchall()

    seg_map = {(r["user_id"], r["video_id"]): r["c"] for r in seg_rows}
    quiz_map = {(r["user_id"], r["video_id"]): r["c"] for r in quiz_rows}

    result_users = []
    for u in users:
        per_video = {}
        for vm in video_meta:
            watched = seg_map.get((u, vm["id"]), 0)
            ratio = watched / vm["total_segments"]
            per_video[vm["id"]] = {
                "ratio": round(ratio, 3),
                "completed": ratio >= COMPLETION_RATIO,
                "quizzes_passed": quiz_map.get((u, vm["id"]), 0),
            }
        result_users.append({"username": u, "per_video": per_video})

    return {
        "videos": video_meta,
        "users": result_users,
        "completion_ratio": COMPLETION_RATIO,
    }


# --- コンテンツ管理(動画・クイズの追加/削除。管理者のみ) -----------------
ALLOWED_VIDEO_EXT = {".mp4", ".webm", ".ogg", ".mov", ".m4v"}


@app.post("/api/admin/video")
async def add_video(
    title: str = Form(...),
    duration: float = Form(...),
    file: UploadFile = File(...),
    admin: str = Depends(current_admin),
):
    """動画ファイルをアップロードして登録する。長さ(duration)はブラウザ側で取得して渡す。"""
    if not title.strip():
        raise HTTPException(status_code=400, detail="タイトルを入力してください")
    if duration <= 0:
        raise HTTPException(status_code=400, detail="動画の長さが取得できませんでした")
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_VIDEO_EXT:
        raise HTTPException(status_code=400, detail="対応していない動画形式です")

    # ファイル名は生成IDで固定し、パス・トラバーサルや上書きを防ぐ
    video_id = "vid_" + secrets.token_hex(4)
    safe_name = f"{video_id}{ext}"
    VIDEO_DIR.mkdir(exist_ok=True)
    dest = VIDEO_DIR / safe_name
    with open(dest, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)

    entry = {
        "id": video_id,
        "title": title.strip(),
        "file": safe_name,
        "duration": round(float(duration), 1),
    }
    CATALOG[video_id] = entry
    save_catalog()
    return {"ok": True, "video": entry}


@app.delete("/api/admin/video/{video_id}")
def remove_video(video_id: str, admin: str = Depends(current_admin)):
    """動画を一覧から外す。関連クイズも外す。動画ファイル自体は安全のため消さない。"""
    if video_id not in CATALOG:
        raise HTTPException(status_code=404, detail="動画が見つかりません")
    CATALOG.pop(video_id)
    save_catalog()
    if video_id in QUIZZES:
        QUIZZES.pop(video_id)
        save_quizzes()
    return {"ok": True}


class NewQuiz(BaseModel):
    video_id: str
    at: float
    question: str
    choices: list[str]
    answer: int
    explanation: str = ""
    rewind_to: float | None = None


@app.post("/api/admin/quiz")
def add_quiz(q: NewQuiz, admin: str = Depends(current_admin)):
    """クイズを追加する。正解番号の範囲チェックをサーバー側でも行う。"""
    if q.video_id not in CATALOG:
        raise HTTPException(status_code=404, detail="動画が見つかりません")
    choices = [c.strip() for c in q.choices if c.strip()]
    if len(choices) < 2:
        raise HTTPException(status_code=400, detail="選択肢は2つ以上にしてください")
    if not (0 <= q.answer < len(choices)):
        raise HTTPException(status_code=400, detail="正解の番号が選択肢の範囲外です")
    if not q.question.strip():
        raise HTTPException(status_code=400, detail="問題文を入力してください")

    quiz_id = "q_" + secrets.token_hex(4)
    entry = {
        "id": quiz_id,
        "at": q.at,
        "question": q.question.strip(),
        "choices": choices,
        "answer": q.answer,
        "explanation": q.explanation.strip(),
    }
    if q.rewind_to is not None and q.rewind_to >= 0:
        entry["rewind_to"] = q.rewind_to
    QUIZZES.setdefault(q.video_id, []).append(entry)
    QUIZZES[q.video_id].sort(key=lambda x: x["at"])  # 出題位置の順に並べる
    save_quizzes()
    return {"ok": True, "quiz_id": quiz_id}


@app.get("/api/admin/quizzes/{video_id}")
def list_admin_quizzes(video_id: str, admin: str = Depends(current_admin)):
    """管理者用。編集のため正解・解説も含めて返す。"""
    return QUIZZES.get(video_id, [])


@app.delete("/api/admin/quiz/{video_id}/{quiz_id}")
def delete_quiz(video_id: str, quiz_id: str, admin: str = Depends(current_admin)):
    lst = QUIZZES.get(video_id, [])
    new = [x for x in lst if x["id"] != quiz_id]
    if len(new) == len(lst):
        raise HTTPException(status_code=404, detail="クイズが見つかりません")
    QUIZZES[video_id] = new
    save_quizzes()
    return {"ok": True}


@app.get("/api/videos")
def list_videos():
    """カタログ一覧を返す"""
    return list(CATALOG.values())


@app.get("/video/{video_id}")
def serve_video(video_id: str, request: Request):
    meta = CATALOG.get(video_id)
    if not meta:
        raise HTTPException(status_code=404, detail="動画が見つかりません")
    path = VIDEO_DIR / meta["file"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="動画ファイルがありません")
    return ranged_response(path, request)


class Heartbeat(BaseModel):
    video_id: str
    position: float   # 現在の再生位置(秒)
    playing: bool     # 再生中かどうか


@app.post("/api/heartbeat")
def heartbeat(hb: Heartbeat, user_id: str = Depends(current_user)):
    """
    再生中に定期的に呼ばれる。サーバー側で連続性を検証し、
    妥当な区間だけを視聴済みにする。
    """
    meta = CATALOG.get(hb.video_id)
    if not meta:
        raise HTTPException(status_code=404, detail="動画が見つかりません")

    now = time.time()
    duration = meta["duration"]
    total_segments = max(1, int(duration // SEGMENT_SECONDS) + 1)

    with get_db() as conn:
        prev = conn.execute(
            "SELECT position, server_time FROM last_heartbeat WHERE user_id=? AND video_id=?",
            (user_id, hb.video_id),
        ).fetchone()

        newly_covered = []
        if prev is not None and hb.playing:
            dt = now - prev["server_time"]          # サーバー実時間の経過
            dpos = hb.position - prev["position"]    # 再生位置の進み

            # 妥当な連続再生か判定:
            #  - 離席していない (dt が短い)
            #  - 前進している (dpos > 0)
            #  - 進みすぎていない (早送り/シークでない)
            if 0 < dt <= HEARTBEAT_MAX_GAP and 0 < dpos <= dt * MAX_SPEED_FACTOR:
                start_seg = int(prev["position"] // SEGMENT_SECONDS)
                end_seg = int(hb.position // SEGMENT_SECONDS)
                for seg in range(start_seg, end_seg + 1):
                    if 0 <= seg < total_segments:
                        newly_covered.append(seg)

        # 視聴済みセグメントを記録(重複はPKで無視)
        for seg in newly_covered:
            conn.execute(
                "INSERT OR IGNORE INTO watched_segments (user_id, video_id, segment_index) VALUES (?,?,?)",
                (user_id, hb.video_id, seg),
            )

        # 今回のハートビートを保存
        conn.execute(
            """
            INSERT INTO last_heartbeat (user_id, video_id, position, server_time)
            VALUES (?,?,?,?)
            ON CONFLICT(user_id, video_id) DO UPDATE SET position=excluded.position, server_time=excluded.server_time
            """,
            (user_id, hb.video_id, hb.position, now),
        )

        watched_count = conn.execute(
            "SELECT COUNT(*) AS c FROM watched_segments WHERE user_id=? AND video_id=?",
            (user_id, hb.video_id),
        ).fetchone()["c"]

    ratio = watched_count / total_segments
    return {
        "watched_segments": watched_count,
        "total_segments": total_segments,
        "ratio": round(ratio, 3),
        "completed": ratio >= COMPLETION_RATIO,
    }


@app.get("/api/progress/{video_id}")
def progress(video_id: str, user_id: str = Depends(current_user)):
    meta = CATALOG.get(video_id)
    if not meta:
        raise HTTPException(status_code=404, detail="動画が見つかりません")
    total_segments = max(1, int(meta["duration"] // SEGMENT_SECONDS) + 1)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT segment_index FROM watched_segments WHERE user_id=? AND video_id=?",
            (user_id, video_id),
        ).fetchall()
    watched = sorted(r["segment_index"] for r in rows)
    ratio = len(watched) / total_segments
    return {
        "watched_segments": len(watched),
        "total_segments": total_segments,
        "segment_seconds": SEGMENT_SECONDS,
        "watched_list": watched,
        "ratio": round(ratio, 3),
        "completed": ratio >= COMPLETION_RATIO,
    }


@app.delete("/api/progress")
def reset_progress(user_id: str = Depends(current_user)):
    """
    自分の進捗(視聴セグメント・ハートビート・クイズ正解)を全削除。
    セッション由来のユーザーだけを消すので、他人の進捗には触れない。
    """
    with get_db() as conn:
        c1 = conn.execute("DELETE FROM watched_segments WHERE user_id=?", (user_id,)).rowcount
        conn.execute("DELETE FROM last_heartbeat WHERE user_id=?", (user_id,))
        c2 = conn.execute("DELETE FROM quiz_results WHERE user_id=?", (user_id,)).rowcount
    return {"deleted_segments": c1, "deleted_quiz_results": c2}


# --- クイズ ---------------------------------------------------------------
@app.get("/api/quiz/{video_id}")
def get_quizzes(video_id: str):
    """
    動画のクイズ一覧を返す。
    重要: 正解(answer)と解説(explanation)は含めない。
    フロントには「いつ・何を・どの選択肢で」だけ渡し、採点はサーバーで行う。
    """
    quizzes = QUIZZES.get(video_id, [])
    return [
        {
            "id": q["id"],
            "at": q["at"],
            "question": q["question"],
            "choices": q["choices"],
        }
        for q in quizzes
    ]


class QuizAnswer(BaseModel):
    video_id: str
    quiz_id: str
    choice: int   # 選んだ選択肢のインデックス


@app.post("/api/quiz/answer")
def grade_quiz(ans: QuizAnswer, user_id: str = Depends(current_user)):
    """選択肢の採点をサーバー側で行い、正誤と解説を返す。"""
    quizzes = QUIZZES.get(ans.video_id, [])
    quiz = next((q for q in quizzes if q["id"] == ans.quiz_id), None)
    if quiz is None:
        raise HTTPException(status_code=404, detail="クイズが見つかりません")

    correct = (ans.choice == quiz["answer"])
    if correct:
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO quiz_results (user_id, video_id, quiz_id) VALUES (?,?,?)",
                (user_id, ans.video_id, ans.quiz_id),
            )

    return {
        "correct": correct,
        # 解説は正解したときだけ返す(不正解時は再挑戦をうながす)
        "explanation": quiz["explanation"] if correct else None,
        # 不正解時、巻き戻し先(秒)が設定されていれば返す。なければ None。
        "rewind_to": quiz.get("rewind_to") if not correct else None,
    }


# 静的ファイル(フロント)を配信
app.mount("/", StaticFiles(directory=str(BASE_DIR / "static"), html=True), name="static")
