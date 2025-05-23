from fastapi import FastAPI, HTTPException, status, Path, Query, Request, Response, APIRouter
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


app = FastAPI()

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

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
    username: str
    email: str
    hashed_password: str


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


# Базы данных (заглушки)
fake_db = {}
username_fake_db = {}
refresh_tokens_db = {}

@router.post("/verify-recaptcha")
async def verify_recaptcha(request: RecaptchaRequest):
    """
    Прокси для Google reCAPTCHA API
    """
    url = "https://www.google.com/recaptcha/api/siteverify"
    secret_key = os.getenv("RECAPTCHA_SECRET_KEY")

    async with httpx.AsyncClient() as client:
        data = {
            "secret": secret_key,
            "response": request.token
        }
        response = await client.post(url, data=data)
        result = response.json()

        if not result.get("success"):
            raise HTTPException(
                status_code=400,
                detail="reCAPTCHA проверка не пройдена"
            )

        headers = {
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Access-Control-Allow-Origin": "*"
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
    if user.email in fake_db:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": "Пользователь с таким email уже зарегистрирован",
            },
        )
    
    if user.username in username_fake_db:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": "Пользователь с таким именем уже зарегистрирован",
            },
        )

    if user.password != user.password1:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "Введённые вами пароли не совпадают"},
        )

    hashed_password = pwd_context.hash(user.password)
    fake_db[user.email] = User(
        username=user.username, email=user.email, hashed_password=hashed_password
    )

    username_fake_db[user.username] = User(
        username=user.username, email=user.email, hashed_password=hashed_password
    )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    refresh_tokens_db[user.email] = refresh_token

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
    db_user = fake_db.get(user.email)

    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "message": "Неверные учетные данные"},
        )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    refresh_tokens_db[user.email] = refresh_token

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
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return {"message": False}
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return {"message": False}
    except jwt.ExpiredSignatureError:
        return {"message": False}
    except jwt.InvalidTokenError:
        return {"message": False}

    # Проверяем наличие токена в базе
    stored_token = refresh_tokens_db.get(email)
    if stored_token != refresh_token:
        return {"message": False}

    # Генерируем новые токены
    new_access_token = create_access_token(data={"sub": email})
    new_refresh_token = create_refresh_token(data={"sub": email})

    # Обновляем refresh токен в базе
    refresh_tokens_db[email] = new_refresh_token

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


@app.get("/api/me")
async def get_current_user(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token:
        return {"message": False}
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return {"message": False}
        db_user = fake_db.get(email)
        if not db_user:
            return {"message": False}
        name: str = fake_db[email]
        return {"message": True, "username": name}
    except jwt.PyJWTError:
        return {"message": False}


@app.get("/api/exit")
async def user_wants_to_exit(
    request: Request,
    response: Response,
):
    refresh_token = request.cookies.get("refresh_token")

    # Извлекаем email из токена, чтобы найти запись в БД
    if refresh_token:
        try:
            payload = jwt.decode(
                refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM]
            )
            email = payload.get("sub")
            if email:
                # Удаляем из базы или добавляем в черный список
                del refresh_tokens_db[email]
        except (jwt.PyJWTError, Exception):
            pass  # можно игнорировать

    # Удаляем куки
    response.delete_cookie(
        "access_token", httponly=True, secure=False, samesite="strict"
    )
    response.delete_cookie(
        "refresh_token", httponly=True, secure=False, samesite="strict"
    )

    return {"message": "Вы вышли из аккаунта"}


fake_db_for_articles = {
    1: {
        "author": "biba",
        "title": "Как работает FastAPI",
        "content": "<p>FastAPI — это современный фреймворк...</p>",
    },
    2: {
        "author": "boba",
        "title": "Введение в PostgreSQL",
        "content": "<p>PostgreSQL — это мощная система...</p>",
    },
}


@app.get("/api/articles")
async def search_articles(
    query: str = Query(..., min_length=1, max_length=100),
    skip: int = 0,
    limit: int = 10,
):
    if not query.strip():
        return []
    results = [
        {"id": id, **data}  # Добавляем ID статьи
        for id, data in fake_db_for_articles.items()
        if query.lower() in data["title"].lower()
    ][skip : skip + limit]

    return results


@app.get("/api/articles/{article_id}", response_model=ArticleResponse)
async def get_article(article_id: int = Path(..., gt=0, title="ID статьи")):
    """Получение статьи по ID"""
    if article_id not in fake_db_for_articles:
        raise HTTPException(status_code=404, detail="Статья не найдена")
    return {"id": article_id, **fake_db_for_articles[article_id]}


@app.post("/api/addarticle")
async def addarticle(user: WriteArticle, response: Response):
    fake_db_for_articles[max(fake_db_for_articles.keys(), default=0) + 1] = {"author": user.author, "title": user.title, "content": user.content}

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
