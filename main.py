import warnings

warnings.filterwarnings("ignore", category=UserWarning)

import sqlite3
from datetime import datetime, timedelta, timezone
import webbrowser
from pydantic import BaseModel, Field
import jwt
import bcrypt
from fastapi import FastAPI, HTTPException, Depends, status, APIRouter
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn


JWT_SECRET = "local_secret_key_penzgtu"
JWT_ALGORITHM = "HS256"
DB_NAME = "calendar.db"

app = FastAPI(title="Локальный Календарь")
security = HTTPBearer()


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS public_holidays (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            holiday_date TEXT UNIQUE NOT NULL
        )""")

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            event_date TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")

        holidays = [
            ('Новый год', '2026-01-01'),
            ('Рождество Христово', '2026-01-07'),
            ('День защитника Отечества', '2026-02-23'),
            ('Международный женский день', '2026-03-08'),
            ('Праздник Весны и Труда', '2026-05-01'),
            ('День Победы', '2026-05-09'),
            ('День России', '2026-06-12'),
            ('День народного единства', '2026-11-04')
        ]
        cursor.executemany("INSERT OR IGNORE INTO public_holidays (title, holiday_date) VALUES (?, ?)", holidays)
        conn.commit()


init_db()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_jwt_token(user_id: int, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный или устаревший токен сессии",
        )


class AuthModel(BaseModel):
    email: str = Field(..., pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password: str = Field(..., min_length=6)


class EventModel(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    event_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")


auth_router = APIRouter(prefix="/api/auth", tags=["Auth"])
events_router = APIRouter(prefix="/api/events", tags=["Events"])


@auth_router.post("/register")
def register(user_data: AuthModel):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        try:
            pwd_hash = hash_password(user_data.password)
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (user_data.email, pwd_hash))
            conn.commit()
            return {"message": "Регистрация успешно завершена!"}
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Этот email уже используется.")


@auth_router.post("/login")
def login(user_data: AuthModel):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (user_data.email,))
        user = cursor.fetchone()

    # Исправлена проверка кортежа: user[2] - хэш пароля, user[0] - ID, user[1] - email
    if not user or not verify_password(user_data.password, user[2]):
        raise HTTPException(status_code=400, detail="Неверная почта или пароль.")

    token = create_jwt_token(user_id=user[0], email=user[1])
    return {"token": token}


@events_router.get("")
def get_events(current_user: dict = Depends(get_current_user)):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id, title, holiday_date FROM public_holidays")
        holidays = [{"id": r[0], "title": r[1], "event_date": r[2], "type": "holiday"} for r in cursor.fetchall()]

        cursor.execute("SELECT id, title, event_date FROM user_events WHERE user_id = ?", (current_user["user_id"],))
        user_events = [{"id": r[0], "title": r[1], "event_date": r[2], "type": "custom"} for r in cursor.fetchall()]

    return holidays + user_events


@events_router.post("")
def add_event(event: EventModel, current_user: dict = Depends(get_current_user)):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO user_events (user_id, title, event_date) VALUES (?, ?, ?)",
            (current_user["user_id"], event.title, event.event_date)
        )
        new_id = cursor.lastrowid
        conn.commit()
    return {"id": new_id, "title": event.title, "event_date": event.event_date, "type": "custom"}


@events_router.delete("/{event_id}")
def delete_event(event_id: int, current_user: dict = Depends(get_current_user)):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_events WHERE id = ? AND user_id = ?", (event_id, current_user["user_id"]))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Событие не найдено.")
        conn.commit()
    return {"message": "Событие удалено."}


app.include_router(auth_router)
app.include_router(events_router)


@app.get("/", response_class=FileResponse)
def index_page():
    return "index.html"


if __name__ == "__main__":
    webbrowser.open_new_tab("http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)

