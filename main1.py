from fastapi import (
    FastAPI,
    HTTPException,
    status,
    Path,
    Query,
    Request,
    Response,
    APIRouter,
)
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import httpx
from datetime import datetime, timedelta
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
from fastapi.responses import JSONResponse
import asyncpg
from asyncpg import Record
from asyncpg.pool import Pool
from typing import Optional, List


app = FastAPI()

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")


router = APIRouter()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080"
    ],  # Разрешает все домены (можно указать конкретные, например ["http://localhost:3000"])
    allow_credentials=True,  # Разрешает куки и авторизацию
    allow_methods=["*"],  # Разрешает все HTTP-методы (GET, POST, PUT и т. д.)
    allow_headers=["*"],  # Разрешает все заголовки
)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Хеширование паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Модель пользователя в БД (пример)
class User(BaseModel):
    id: int
    username: str
    email: str
    hashed_password: str

    @classmethod
    async def get_by_email(cls, email: str, pool: Pool) -> Optional["User"]:
        async with pool.acquire() as conn:
            record = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
            return cls(**record) if record else None

    @classmethod
    async def get_by_username(cls, username: str, pool: Pool) -> Optional["User"]:
        async with pool.acquire() as conn:
            record = await conn.fetchrow(
                "SELECT * FROM users WHERE username = $1", username
            )
            return cls(**record) if record else None


# Модели для запросов
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    password1: str


class UserLogin(BaseModel):
    email: str
    password: str


class WriteArticle(BaseModel):
    author: str
    title: str
    content: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class ArticleResponse(BaseModel):
    id: int
    title: str
    content: str


class RecaptchaRequest(BaseModel):
    token: str


async def get_db_pool() -> Pool:
    return await asyncpg.create_pool(DATABASE_URL)


async def create_tables():
    pool = await get_db_pool()
    async with pool.acquire() as connection:
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """
        )

        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                user_id INTEGER REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """
        )

        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS articles (
                id SERIAL PRIMARY KEY,
                author VARCHAR(50) NOT NULL,
                title VARCHAR(255) NOT NULL,
                content TEXT NOT NULL
            )
        """
        )


@app.on_event("startup")
async def startup():
    await create_tables()


@router.post("/verify-recaptcha")
async def verify_recaptcha(request: RecaptchaRequest):
    """
    Прокси для Google reCAPTCHA API
    """
    url = "https://www.google.com/recaptcha/api/siteverify"
    secret_key = os.getenv("RECAPTCHA_SECRET_KEY")

    async with httpx.AsyncClient() as client:
        data = {"secret": secret_key, "response": request.token}
        response = await client.post(url, data=data)
        result = response.json()

        if not result.get("success"):
            raise HTTPException(
                status_code=400, detail="reCAPTCHA проверка не пройдена"
            )

        headers = {
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Access-Control-Allow-Origin": "*",
        }

        return JSONResponse(content=result, headers=headers)


app.include_router(router, prefix="/api")


# Функции для создания токенов
def create_token(data: dict, expires_delta: timedelta, secret_key: str) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def create_access_token(data: dict) -> str:
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_token(data, expires_delta, SECRET_KEY)


def create_refresh_token(data: dict) -> str:
    expires_delta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return create_token(data, expires_delta, REFRESH_SECRET_KEY)


@app.post("/api/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate, response: Response):
    pool = await get_db_pool()

    # Проверка существующего email
    if await User.get_by_email(user.email, pool):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Пользователь с таким email уже зарегистрирован"},
        )

    # Проверка существующего username
    if await User.get_by_username(user.username, pool):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Пользователь с таким именем уже зарегистрирован"},
        )

    if user.password != user.password1:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Пароли не совпадают"},
        )

    hashed_password = pwd_context.hash(user.password)

    async with pool.acquire() as conn:
        user_id = await conn.fetchval(
            """
            INSERT INTO users (username, email, hashed_password)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            user.username,
            user.email,
            hashed_password,
        )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    # refresh_tokens_db[user.email] = refresh_token
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO refresh_tokens (user_id, token, expires_at)
            VALUES ($1, $2, NOW() + INTERVAL '7 days')
            """,
            user_id, refresh_token
        )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
    )

    return {"success": True, "message": "Успешная регистрация"}


@app.post("/api/login")
async def login(user: UserLogin, response: Response):
    pool = await get_db_pool()
    db_user = await User.get_by_email(user.email, pool)

    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Неверные учетные данные"},
        )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    # refresh_tokens_db[user.email] = refresh_token
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO refresh_tokens (user_id, token, expires_at)
            VALUES ((SELECT id FROM users WHERE email = $1), $2, NOW() + INTERVAL '7 days')
            """,
            user.email, refresh_token
        )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
    )

    return {"success": True, "message": "Успешная авторизация"}


# Эндпоинт обновления токенов
@app.post("/api/refresh")
async def refresh_token(request: Request, response: Response):
    pool = await get_db_pool()
    refresh_token = request.cookies.get("refresh_token")

    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        async with pool.acquire() as conn:
            # Проверяем токен в базе
            user = await conn.fetchrow(
                """
                SELECT u.*, rt.token 
                FROM users u
                JOIN refresh_tokens rt ON u.id = rt.user_id
                WHERE u.email = $1 AND rt.token = $2
                """,
                email,
                refresh_token,
            )

            if not user:
                return {"message": False}

            # Обновляем токены
            new_access_token = create_access_token(data={"sub": email})
            new_refresh_token = create_refresh_token(data={"sub": email})

            # Обновляем токен в базе
            await conn.execute(
                """
                UPDATE refresh_tokens 
                SET token = $1, expires_at = NOW() + INTERVAL '7 days'
                WHERE user_id = $2
                """,
                new_refresh_token,
                user["id"],
            )

            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=False,  # Только для HTTPS
                samesite="strict",
                max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )

            response.set_cookie(
                key="refresh_token",
                value=new_refresh_token,
                httponly=True,
                secure=False,
                samesite="strict",
                max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
            )

            return {"message": True}

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return {"message": False}


@app.get("/api/me")
async def get_current_user(request: Request):
    pool = await get_db_pool()
    access_token = request.cookies.get("access_token")
    if not access_token:
        return {"message": False}

    try:
        # Декодируем токен
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            return {"message": False}

        # Получаем пользователя из базы
        async with pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, username, email FROM users WHERE email = $1", email
            )

            if not user:
                return {"message": False}

            return {
                "message": True,
                "username": user["username"],
                "email": user["email"],
            }

    except jwt.PyJWTError:
        return {"message": False}


@app.get("/api/exit")
async def user_wants_to_exit(request: Request, response: Response):
    pool = await get_db_pool()
    refresh_token = request.cookies.get("refresh_token")

    try:
        if refresh_token:
            # Декодируем токен для получения email
            payload = jwt.decode(
                refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM]
            )
            email = payload.get("sub")

            if email:
                # Удаляем refresh token из базы
                async with pool.acquire() as conn:
                    await conn.execute(
                        """
                        DELETE FROM refresh_tokens 
                        WHERE user_id = (SELECT id FROM users WHERE email = $1)
                        """,
                        email,
                    )

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        pass  # Токен уже невалиден, ничего не делаем

    # Удаляем куки
    response.delete_cookie(
        "access_token", httponly=True, secure=False, samesite="strict"
    )
    response.delete_cookie(
        "refresh_token", httponly=True, secure=False, samesite="strict"
    )

    return {"message": "Вы вышли из аккаунта"}


@app.get("/api/articles")
async def search_articles(
    query: str = Query(..., min_length=1, max_length=100),
    skip: int = 0,
    limit: int = 10,
):
    pool = await get_db_pool()

    async with pool.acquire() as conn:
        results = await conn.fetch(
            """
            SELECT * FROM articles
            WHERE title ILIKE $1
            OFFSET $2 LIMIT $3
            """,
            f"%{query}%",
            skip,
            limit,
        )

    return [dict(record) for record in results]


@app.get("/api/articles/{article_id}", response_model=ArticleResponse)
async def get_article(article_id: int = Path(..., gt=0, title="ID статьи")):
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        article = await conn.fetchrow(
            """
            SELECT id, author, title, content 
            FROM articles 
            WHERE id = $1
            """,
            article_id,
        )

        if not article:
            raise HTTPException(status_code=404, detail="Статья не найдена")

        return {
            "id": article["id"],
            "title": article["title"],
            "content": article["content"],
        }


@app.post("/api/addarticle")
async def addarticle(article: WriteArticle):
    pool = await get_db_pool()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO articles (author, title, content)
            VALUES ($1, $2, $3)
            """,
            article.author,
            article.title,
            article.content,
        )

    return {"success": True}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8081,
        reload=True,
        timeout_keep_alive=60,
        timeout_graceful_shutdown=10,
    )
