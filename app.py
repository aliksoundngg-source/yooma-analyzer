import os, re, sqlite3, hashlib, hmac, secrets, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

BASE = Path(__file__).parent
DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE / "data" / "analyzer.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
SESSION_MAX_AGE = 60 * 60 * 24 * 7
COOKIE_NAME = "yooma_session"
serializer = URLSafeTimedSerializer(SECRET_KEY) if SECRET_KEY else None

app = FastAPI(title="Yooma Promo Analyzer Pro")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

CODE_RE = re.compile(r"(?<![A-Za-zА-Яа-яЁё0-9])[A-Za-zА-Яа-яЁё0-9_-]{4,32}(?![A-Za-zА-Яа-яЁё0-9])")
WORD_RE = re.compile(r"[A-Za-zА-Яа-яЁё]{3,}|[A-Za-zА-Яа-яЁё0-9_-]{4,}", re.I)

class LoginIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
class TextIn(BaseModel):
    source: str = Field(default="manual", max_length=100)
    content: str = Field(min_length=1, max_length=200_000)
class FetchIn(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
class GenerateIn(BaseModel):
    limit: int = Field(default=1000, ge=1, le=1000)

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS documents(
            id INTEGER PRIMARY KEY, source TEXT NOT NULL, content TEXT NOT NULL,
            created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS code_notes(
            id INTEGER PRIMARY KEY, code TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unknown',
            note TEXT DEFAULT '', updated_at TEXT NOT NULL)""")
init_db()

def is_authed(request: Request):
    if not serializer:
        return False
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("role") == "admin"
    except (BadSignature, SignatureExpired):
        return False

def require_auth(request: Request):
    if not is_authed(request):
        raise HTTPException(401, "Требуется вход")

@app.get("/")
def home():
    return FileResponse(BASE / "static" / "index.html")

@app.get("/api/session")
def session(request: Request):
    return {"authenticated": is_authed(request)}

@app.post("/api/login")
def login(payload: LoginIn):
    if not ADMIN_PASSWORD or not SECRET_KEY:
        raise HTTPException(503, "Сервер не настроен: задайте ADMIN_PASSWORD и SECRET_KEY.")
    if not hmac.compare_digest(payload.password, ADMIN_PASSWORD):
        # Avoid revealing whether username/password configuration is valid.
        raise HTTPException(401, "Неверный пароль")
    token = serializer.dumps({"role": "admin", "nonce": secrets.token_hex(8)})
    response = JSONResponse({"ok": True})
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=True,
                        samesite="strict", max_age=SESSION_MAX_AGE, path="/")
    return response

@app.post("/api/logout")
def logout(request: Request):
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response

@app.post("/api/ingest")
def ingest(payload: TextIn, request: Request):
    require_auth(request)
    with db() as con:
        cur = con.execute("INSERT INTO documents(source,content,created_at) VALUES(?,?,?)",
            (payload.source, payload.content, datetime.now(timezone.utc).isoformat()))
    return {"ok": True, "document_id": cur.lastrowid, "characters": len(payload.content)}

@app.post("/api/fetch-public")
async def fetch_public(payload: FetchIn, request: Request):
    require_auth(request)
    parsed = urlparse(payload.url)
    host = (parsed.hostname or "").lower()
    # Restrict fetching to the intended domain and its subdomains to avoid SSRF.
    if parsed.scheme != "https" or not (host == "yooma.su" or host.endswith(".yooma.su")):
        raise HTTPException(400, "Разрешены только HTTPS-страницы домена yooma.su.")
    robots_url = f"https://{host}/robots.txt"
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=False,
                                     headers={"User-Agent": "YoomaPromoAnalyzer/1.0 (public-page research)"}) as client:
            robots_response = await client.get(robots_url)
            if robots_response.status_code == 200:
                rp = RobotFileParser()
                rp.parse(robots_response.text.splitlines())
                if not rp.can_fetch("YoomaPromoAnalyzer", payload.url):
                    raise HTTPException(403, "robots.txt запрещает автоматический сбор этой страницы.")
            response = await client.get(payload.url)
            if response.status_code >= 400:
                raise HTTPException(502, f"Страница ответила кодом {response.status_code}.")
            if "text/html" not in response.headers.get("content-type", ""):
                raise HTTPException(415, "Поддерживаются только HTML-страницы.")
            soup = BeautifulSoup(response.text, "html.parser")
            for tag in soup(["script", "style", "noscript", "svg"]):
                tag.decompose()
            content = soup.get_text(" ", strip=True)[:200_000]
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Не удалось получить публичную страницу.")
    if not content:
        raise HTTPException(422, "На странице не найден читаемый текст.")
    with db() as con:
        cur = con.execute("INSERT INTO documents(source,content,created_at) VALUES(?,?,?)",
            (payload.url, content, datetime.now(timezone.utc).isoformat()))
    return {"ok": True, "document_id": cur.lastrowid, "characters": len(content),
            "note": "Сохранён видимый текст HTML. Динамический контент чата может быть недоступен."}

def docs():
    with db() as con:
        return con.execute("SELECT * FROM documents ORDER BY id DESC").fetchall()

@app.get("/api/overview")
def overview(request: Request):
    require_auth(request)
    rows = docs()
    code_counts = {}
    word_counts = {}
    for row in rows:
        for token in CODE_RE.findall(row["content"]):
            if any(c.isdigit() for c in token) or token.isupper() or len(token) >= 8:
                key = token.lower()
                code_counts[key] = code_counts.get(key, 0) + 1
        for word in WORD_RE.findall(row["content"]):
            key = word.lower()
            word_counts[key] = word_counts.get(key, 0) + 1
    top_codes = sorted(code_counts.items(), key=lambda x: (-x[1], x[0]))[:100]
    top_words = sorted(word_counts.items(), key=lambda x: (-x[1], x[0]))[:40]
    with db() as con:
        known = con.execute("SELECT COUNT(*) n FROM code_notes").fetchone()["n"]
    return {"documents": len(rows), "characters": sum(len(r["content"]) for r in rows),
            "candidate_count": len(code_counts), "saved_codes": known,
            "codes": [{"code": k, "mentions": v} for k,v in top_codes],
            "words": [{"word": k, "count": v} for k,v in top_words]}

@app.get("/api/documents")
def documents(request: Request):
    require_auth(request)
    return {"items": [{"id":r["id"],"source":r["source"],"created_at":r["created_at"],
                       "characters":len(r["content"])} for r in docs()]}

@app.post("/api/generate")
def generate(payload: GenerateIn, request: Request):
    require_auth(request)
    # Generate synthetic format examples based on the user's supplied samples.
    # These are guesses only; they are not checked against Yooma.
    import random
    import string

    rng = random.SystemRandom()
    latin = string.ascii_lowercase
    cyrillic = "абвгдежзийклмнопрстуфхцчшщэюя"
    words = ["бабки", "деньги", "bonus", "money", "rub", "promo", "zxc", "qwe", "play"]
    patterns = ["latin_digits", "repeat_letters", "repeat_digits", "word_repeat",
                "word_number", "number_rub", "short_mix", "cyrillic_word_number"]
    result, seen = [], set()

    def make_candidate(pattern):
        if pattern == "latin_digits":
            return ''.join(rng.choice(latin) for _ in range(rng.randint(2, 5))) + ''.join(rng.choice(string.digits) for _ in range(rng.randint(2, 4)))
        if pattern == "repeat_letters":
            ch = rng.choice(latin)
            return ch * rng.randint(3, 7)
        if pattern == "repeat_digits":
            ch = rng.choice(string.digits)
            return ch * rng.randint(3, 7)
        if pattern == "word_repeat":
            w = rng.choice(words[:2] + ["бабки"])
            return w + w
        if pattern == "word_number":
            return rng.choice(words) + str(rng.randint(1, 999))
        if pattern == "number_rub":
            return str(rng.choice([10, 20, 30, 50, 100, 150, 200, 500, 1000])) + "rub"
        if pattern == "short_mix":
            return ''.join(rng.choice(latin) for _ in range(rng.randint(3, 5))) + str(rng.randint(1, 999))
        return rng.choice(["бабки", "деньги"]) + str(rng.randint(1, 99))

    attempts = 0
    while len(result) < payload.limit and attempts < payload.limit * 30:
        attempts += 1
        pattern = rng.choice(patterns)
        candidate = make_candidate(pattern)
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append({"candidate": candidate, "basis": "случайная комбинация по формату примеров: " + pattern})

    return {"verified": False,
            "notice": "Случайные гипотезы по формату предоставленных примеров. Они не проверены и не являются подтверждёнными промокодами.",
            "items": result}

@app.post("/api/codes")
def save_code(payload: dict, request: Request):
    require_auth(request)
    code = str(payload.get("code","")).strip()[:64]
    status = str(payload.get("status","unknown"))
    note = str(payload.get("note",""))[:500]
    if not code or status not in {"unknown","published","expired","verified"}:
        raise HTTPException(400, "Проверьте код и статус.")
    with db() as con:
        con.execute("INSERT INTO code_notes(code,status,note,updated_at) VALUES(?,?,?,?)",
            (code,status,note,datetime.now(timezone.utc).isoformat()))
    return {"ok":True}

@app.get("/api/codes")
def list_codes(request: Request):
    require_auth(request)
    with db() as con:
        rows=con.execute("SELECT * FROM code_notes ORDER BY id DESC LIMIT 300").fetchall()
    return {"items":[dict(r) for r in rows]}

@app.post("/api/validate")
def validate(request: Request):
    require_auth(request)
    raise HTTPException(501, "Проверка не подключена: нужен официальный API Yooma и разрешение владельца.")

@app.get("/health")
def health():
    return {"ok":True}
