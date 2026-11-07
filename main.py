import os
import sqlite3
import hashlib
import secrets
import json
import time
import base64
import hmac
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_PATH = os.environ.get("DB_PATH", "soztop.db")

# ─── Reserved / Protected usernames ───────────────────────────────────────────
RESERVED_USERNAMES = {
    "creator", "admin", "soztop", "administrator", "moderator", "mod",
    "root", "superuser", "support", "help", "system", "bot", "official",
    "staff", "soztopuz", "soztop_uz", "owner", "manager", "dev", "developer",
    "test", "api", "null", "undefined", "anonymous", "guest",
}

# Secret key to allow claiming reserved names (keep this private!)
OWNER_SECRET_KEY = os.environ.get("OWNER_SECRET_KEY", "soztop-owner-secret-2024")

app = FastAPI(
    title="So'zTop API",
    description="So'zTop platformasi uchun Python FastAPI backend",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Initialization
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                avatar TEXT DEFAULT '🦁',
                profile_image TEXT,
                token TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS word_sets (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                src TEXT DEFAULT 'auto',
                target_lang TEXT DEFAULT 'uz',
                words_json TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_stats (
                user_id INTEGER PRIMARY KEY,
                stars INTEGER DEFAULT 0,
                games INTEGER DEFAULT 0,
                streak INTEGER DEFAULT 0,
                played_modes_json TEXT DEFAULT '{}',
                known_words_json TEXT DEFAULT '{}',
                unlocked_badges_json TEXT DEFAULT '{}',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

init_db()

# Password helper
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Multi-session Signed Token Helper (supports multiple devices/browsers simultaneously without kicking each other out)
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "soztop-secure-multi-session-secret-2026")

def create_access_token(user_id: int, username: str) -> str:
    payload = {
        "uid": user_id,
        "un": username,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(8)
    }
    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    b64_payload = base64.urlsafe_b64encode(raw).decode('utf-8').rstrip('=')
    sig = hmac.new(TOKEN_SECRET.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig}"

def decode_token(token: str) -> Optional[int]:
    try:
        if "." in token:
            parts = token.split(".")
            if len(parts) == 2:
                b64_payload, sig = parts
                expected_sig = hmac.new(TOKEN_SECRET.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
                if hmac.compare_digest(sig, expected_sig):
                    pad = len(b64_payload) % 4
                    if pad:
                        b64_payload += "=" * (4 - pad)
                    payload_json = base64.urlsafe_b64decode(b64_payload.encode('utf-8')).decode('utf-8')
                    payload = json.loads(payload_json)
                    return payload.get("uid")
    except Exception:
        pass
    return None

# Auth dependency (validates both multi-session signed tokens and legacy DB tokens)
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Avtorizatsiya talab qilinadi")
    token = authorization.split(" ")[1]
    
    uid = decode_token(token)
    with get_db() as conn:
        if uid is not None:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        else:
            # Fallback for legacy random hex tokens stored in DB
            user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Yaroqsiz yoki eskirgan token")
        return dict(user)

# Pydantic Schemas
class RegisterRequest(BaseModel):
    username: str
    password: str
    full_name: str
    avatar: Optional[str] = "🦁"
    owner_key: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    avatar: Optional[str] = None
    profile_image: Optional[str] = None

class WordItemModel(BaseModel):
    id: Optional[str] = None
    w: str
    tr: Optional[str] = None
    lg: Optional[str] = None

class WordSetModel(BaseModel):
    id: str
    name: str
    src: str
    to: str
    words: List[WordItemModel]

class SyncSetsRequest(BaseModel):
    sets: List[WordSetModel]

class SyncStatsRequest(BaseModel):
    stars: int = 0
    games: int = 0
    streak: int = 0
    played_modes: Optional[Dict[str, Any]] = None
    known_words: Optional[Dict[str, Any]] = None
    unlocked_badges: Optional[Dict[str, Any]] = None

# API Endpoints
@app.get("/")
def root():
    return {
        "status": "online",
        "app": "So'zTop API Backend (Python FastAPI)",
        "frontend_url": "http://localhost:5173",
        "docs_url": "/docs",
        "message": "Backend to'liq ishlamoqda. Ilovadan foydalanish uchun brauzerda http://localhost:5173 manzilini oching."
    }

@app.get("/health")
def health_check():
    return {"status": "ok", "app": "So'zTop Python Backend"}

@app.post("/api/auth/register")
def register(data: RegisterRequest):
    username = data.username.strip().lower()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username kamida 3 ta belgidan iborat bo'lishi kerak")
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Parol kamida 8 ta belgidan iborat bo'lishi kerak (harf, son va belgilar)")

    pwd_hash = hash_password(data.password)

    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, full_name, avatar, token) VALUES (?, ?, ?, ?, ?)",
                (username, pwd_hash, data.full_name.strip(), data.avatar or "🦁", "")
            )
            user_id = cur.lastrowid
            token = create_access_token(user_id, username)
            cur.execute("UPDATE users SET token = ? WHERE id = ?", (token, user_id))
            # Init empty stats
            cur.execute(
                "INSERT INTO user_stats (user_id) VALUES (?)",
                (user_id,)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Bu username allaqachon band. Boshqa username tanlang.")

    return {
        "success": True,
        "token": token,
        "user": {
            "id": user_id,
            "username": username,
            "full_name": data.full_name,
            "avatar": data.avatar or "🦁",
            "profile_image": None
        }
    }

@app.post("/api/auth/login")
def login(data: LoginRequest):
    username = data.username.strip().lower()
    pwd_hash = hash_password(data.password)

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, pwd_hash)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=400, detail="Username yoki parol noto'g'ri")

        token = create_access_token(user["id"], user["username"])
        conn.execute("UPDATE users SET token = ? WHERE id = ?", (token, user["id"]))
        conn.commit()

        return {
            "success": True,
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "full_name": user["full_name"],
                "avatar": user["avatar"],
                "profile_image": user["profile_image"]
            }
        }

@app.get("/api/auth/me")
def get_me(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        stats = conn.execute("SELECT * FROM user_stats WHERE user_id = ?", (user["id"],)).fetchone()
        
        parsed_stats = {
            "stars": stats["stars"] if stats else 0,
            "games": stats["games"] if stats else 0,
            "streak": stats["streak"] if stats else 0,
            "played_modes": json.loads(stats["played_modes_json"]) if stats and stats["played_modes_json"] else {},
            "known_words": json.loads(stats["known_words_json"]) if stats and stats["known_words_json"] else {},
            "unlocked_badges": json.loads(stats["unlocked_badges_json"]) if stats and stats["unlocked_badges_json"] else {},
        }

        return {
            "user": {
                "id": user["id"],
                "username": user["username"],
                "full_name": user["full_name"],
                "avatar": user["avatar"],
                "profile_image": user["profile_image"]
            },
            "stats": parsed_stats
        }

@app.put("/api/auth/profile")
def update_profile(data: ProfileUpdateRequest, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        if data.full_name is not None:
            conn.execute("UPDATE users SET full_name = ? WHERE id = ?", (data.full_name.strip(), user["id"]))
        if data.avatar is not None:
            conn.execute("UPDATE users SET avatar = ? WHERE id = ?", (data.avatar, user["id"]))
        if data.profile_image is not None:
            conn.execute("UPDATE users SET profile_image = ? WHERE id = ?", (data.profile_image, user["id"]))
        conn.commit()

        updated = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        return {
            "success": True,
            "user": {
                "id": updated["id"],
                "username": updated["username"],
                "full_name": updated["full_name"],
                "avatar": updated["avatar"],
                "profile_image": updated["profile_image"]
            }
        }

@app.get("/api/sets")
def get_sets(user: dict = Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM word_sets WHERE user_id = ?", (user["id"],)).fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "name": r["name"],
                "src": r["src"],
                "to": r["target_lang"],
                "words": json.loads(r["words_json"])
            })
        return {"sets": result}

@app.post("/api/sets/sync")
def sync_sets(data: SyncSetsRequest, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        active_ids = [s.id for s in data.sets]
        if active_ids:
            # Delete any sets belonging to this user that are NOT in active_ids
            placeholders = ",".join("?" for _ in active_ids)
            conn.execute(
                f"DELETE FROM word_sets WHERE user_id = ? AND id NOT IN ({placeholders})",
                (user["id"], *active_ids)
            )
            for s in data.sets:
                words_str = json.dumps([w.model_dump() for w in s.words], ensure_ascii=False)
                conn.execute("""
                    INSERT INTO word_sets (id, user_id, name, src, target_lang, words_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        src = excluded.src,
                        target_lang = excluded.target_lang,
                        words_json = excluded.words_json,
                        updated_at = CURRENT_TIMESTAMP
                """, (s.id, user["id"], s.name, s.src, s.to, words_str))
        else:
            # If client sets list is empty, delete all sets for this user
            conn.execute("DELETE FROM word_sets WHERE user_id = ?", (user["id"],))

        conn.commit()
    return {"success": True, "count": len(data.sets)}

@app.delete("/api/sets/{set_id}")
def delete_single_set(set_id: str, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("DELETE FROM word_sets WHERE id = ? AND user_id = ?", (set_id, user["id"]))
        conn.commit()
    return {"success": True, "deleted_id": set_id}

@app.post("/api/stats/sync")
def sync_stats(data: SyncStatsRequest, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        current = conn.execute("SELECT * FROM user_stats WHERE user_id = ?", (user["id"],)).fetchone()
        if current:
            # Merge played_modes (keep max count for each game mode)
            curr_played = json.loads(current["played_modes_json"] or "{}")
            if data.played_modes:
                for k, v in data.played_modes.items():
                    try:
                        curr_played[k] = max(curr_played.get(k, 0), int(v))
                    except (ValueError, TypeError):
                        pass

            # Merge known words
            curr_known = json.loads(current["known_words_json"] or "{}")
            if data.known_words:
                for k, v in data.known_words.items():
                    try:
                        curr_known[k] = max(curr_known.get(k, 0), int(v))
                    except (ValueError, TypeError):
                        pass

            # Merge unlocked badges
            curr_badges = json.loads(current["unlocked_badges_json"] or "{}")
            if data.unlocked_badges:
                curr_badges.update(data.unlocked_badges)

            # Monotonic safe updates: NEVER decrement stars or games!
            final_stars = max(current["stars"] or 0, data.stars)
            final_games = max(current["games"] or 0, data.games)
            final_streak = max(current["streak"] or 0, data.streak)

            conn.execute("""
                UPDATE user_stats SET
                    stars = ?,
                    games = ?,
                    streak = ?,
                    played_modes_json = ?,
                    known_words_json = ?,
                    unlocked_badges_json = ?
                WHERE user_id = ?
            """, (
                final_stars,
                final_games,
                final_streak,
                json.dumps(curr_played, ensure_ascii=False),
                json.dumps(curr_known, ensure_ascii=False),
                json.dumps(curr_badges, ensure_ascii=False),
                user["id"]
            ))
        else:
            conn.execute("""
                INSERT INTO user_stats (user_id, stars, games, streak, played_modes_json, known_words_json, unlocked_badges_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user["id"],
                data.stars,
                data.games,
                data.streak,
                json.dumps(data.played_modes or {}, ensure_ascii=False),
                json.dumps(data.known_words or {}, ensure_ascii=False),
                json.dumps(data.unlocked_badges or {}, ensure_ascii=False)
            ))
        conn.commit()
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
