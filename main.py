import os
import sqlite3
import hashlib
import secrets
import json
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

# Auth dependency
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Avtorizatsiya talab qilinadi")
    token = authorization.split(" ")[1]
    
    with get_db() as conn:
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
    stars: int
    games: int
    streak: int
    played_modes: Dict[str, int]
    known_words: Dict[str, int]
    unlocked_badges: Dict[str, str]

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
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="Parol kamida 4 ta belgidan iborat bo'lishi kerak")

    token = secrets.token_hex(24)
    pwd_hash = hash_password(data.password)

    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, full_name, avatar, token) VALUES (?, ?, ?, ?, ?)",
                (username, pwd_hash, data.full_name.strip(), data.avatar or "🦁", token)
            )
            user_id = cur.lastrowid
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

        token = secrets.token_hex(24)
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
        conn.commit()
    return {"success": True, "count": len(data.sets)}

@app.post("/api/stats/sync")
def sync_stats(data: SyncStatsRequest, user: dict = Depends(get_current_user)):
    with get_db() as conn:
        conn.execute("""
            INSERT INTO user_stats (user_id, stars, games, streak, played_modes_json, known_words_json, unlocked_badges_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                stars = excluded.stars,
                games = excluded.games,
                streak = excluded.streak,
                played_modes_json = excluded.played_modes_json,
                known_words_json = excluded.known_words_json,
                unlocked_badges_json = excluded.unlocked_badges_json
        """, (
            user["id"],
            data.stars,
            data.games,
            data.streak,
            json.dumps(data.played_modes, ensure_ascii=False),
            json.dumps(data.known_words, ensure_ascii=False),
            json.dumps(data.unlocked_badges, ensure_ascii=False)
        ))
        conn.commit()
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
