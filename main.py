from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
from fastapi import Response
from fastapi import Request



app = FastAPI()

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],  # Разрешает все домены (можно указать конкретные, например ["http://localhost:3000"])
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


class UserLogin(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


# Базы данных (заглушки)
fake_db = {}
refresh_tokens_db = {}


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
        raise HTTPException(
            status_code=400, detail="Пользователь с таким email уже зарегистрирован"
        )

    hashed_password = pwd_context.hash(user.password)
    fake_db[user.email] = User(
        username=user.username, email=user.email, hashed_password=hashed_password
    )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    # Сохраняем refresh токен
    refresh_tokens_db[user.email] = refresh_token

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600 
    )

    return {"message": "Успешная регистрация"}

@app.post("/api/login")
async def login(user: UserLogin, response: Response):
    db_user = fake_db.get(user.email)

    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверные учетные данные",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    # Обновляем refresh токен
    refresh_tokens_db[user.email] = refresh_token

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # Только для HTTPS
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600 
    )

    return {"message": "Успешная авторизация"}


# Эндпоинт обновления токенов
@app.post("/api/refresh")
async def refresh_token(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Невалидный токен")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Срок действия токена истёк")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Невалидный токен")

    # Проверяем наличие токена в базе
    stored_token = refresh_tokens_db.get(email)
    if stored_token != refresh_token:
        raise HTTPException(status_code=401, detail="Недействительный refresh токен")

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
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600 
    )

    return {"message": "Успешное обровление токенов"}

@app.get("/api/me")
async def get_current_user(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token:
        return {'message': False}
    else:
        return {'message': True}
    
@app.get("/api/exit")
async def user_wants_to_exit(response: Response):
    response.delete_cookie(
        "access_token",
        httponly=True,
        secure=False,
        samesite="strict"
    )
    response.delete_cookie(
        "refresh_token",
        httponly=True,
        secure=False,
        samesite="strict"
    )
    return {'message': 'tokens are cleared, the client is deauthorised'}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8081,
        reload=True,
        timeout_keep_alive=60,
        timeout_graceful_shutdown=10,
    )
