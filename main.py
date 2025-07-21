from fastapi import (
    FastAPI,
    HTTPException,
    status,
    Path,
    Query,
    Request,
    Response,
    APIRouter,
    UploadFile,
    File,
    Form,
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
import logging
from fastapi.responses import JSONResponse
import asyncpg
from asyncpg.pool import Pool
from typing import Optional, List
from slowapi import Limiter
from slowapi.util import get_remote_address
from contextlib import asynccontextmanager
import asyncio
import uuid
from fastapi.staticfiles import StaticFiles

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения
load_dotenv()

# Конфигурация CORS
origins = [
    "http://localhost:8080",
    "http://localhost:3000",
    "https://your-production-domain.com",
]

# Глобальный пул подключений
db_pool: Optional[Pool] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    
    # Конфигурация пула соединений
    pool_config = {
        "min_size": 10,
        "max_size": 50,
        "max_inactive_connection_lifetime": 60,  # 1 минута
        "max_queries": 50000,
        "command_timeout": 30,  # 30 секунд
        "timeout": 10,  # 10 секунд на получение соединения
    }
    
    try:
        # Создаем пул подключений
        db_pool = await asyncpg.create_pool(
            dsn=os.getenv("DATABASE_URL"),
            **pool_config
        )
        logger.info(f"Пул подключений к БД создан с параметрами: {pool_config}")
        
        # Создаем таблицы
        await create_tables()
        yield
        
    except Exception as e:
        logger.error(f"Ошибка при создании пула подключений: {e}")
        raise
    finally:
        # Закрываем пул при остановке
        if db_pool:
            await db_pool.close()
            logger.info("Пул подключений к БД закрыт")

app = FastAPI(lifespan=lifespan, max_request_size=100 * 1024 * 1024)  # 100 MB

# Настройки лимитера
limiter = Limiter(key_func=get_remote_address, default_limits=["10 per minute"])
app.state.limiter = limiter

# Конфигурация безопасности
SECRET_KEY = os.getenv("SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

router = APIRouter()

# Настройки для загрузки изображений
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Подключение статики
app.mount("/static", StaticFiles(directory="static"), name="static")

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Допустимые типы изображений
ALLOWED_IMAGE_TYPES = [
    "image/jpeg", 
    "image/png", 
    "image/gif", 
    "image/webp",
    "image/svg+xml"
]

# Middleware для обработки ошибок БД
@app.middleware("http")
async def db_errors_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except (asyncpg.PostgresConnectionError, asyncpg.ConnectionDoesNotExistError) as e:
        logger.error(f"Ошибка подключения к БД: {e}")
        return JSONResponse(
            status_code=503,
            content={"message": "Сервис временно недоступен, попробуйте позже"},
        )
    except asyncpg.PostgresError as e:
        logger.error(f"Ошибка базы данных: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Ошибка обработки запроса"},
        )
    except Exception as e:
        logger.error(f"Непредвиденная ошибка: {e}")
        return JSONResponse(
            status_code=500,
            content={"message": "Внутренняя ошибка сервера"},
        )

# Константы
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Инициализация криптоконтекста
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_tables():
    """Создание таблиц при старте приложения"""
    async with db_pool.acquire() as conn:
        try:
            # Создаем таблицы в транзакции
            async with conn.transaction():
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        hashed_password TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)
                
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        token TEXT UNIQUE NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)
                
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS articles (
                        id SERIAL PRIMARY KEY,
                        author VARCHAR(50) NOT NULL,
                        title VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)
                
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS comments (
                        id SERIAL PRIMARY KEY,
                        article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        content TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)
                
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS article_images (
                        id SERIAL PRIMARY KEY,
                        article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
                        image_path TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """)
                
                # Создаем индексы
                await conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_article_images_article_id 
                    ON article_images(article_id)
                """)
                
                await conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
                """)
                await conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)
                """)
                await conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_comments_article_id ON comments(article_id)
                """)
                
            logger.info("Таблицы и индексы созданы/проверены")
            
        except Exception as e:
            logger.error(f"Ошибка при создании таблиц: {e}")
            raise

async def get_db_connection():
    """Получение соединения с БД из пула"""
    if db_pool is None:
        raise HTTPException(
            status_code=503,
            detail="Пул подключений к БД не инициализирован"
        )
    
    try:
        # Получаем соединение с таймаутом
        return await asyncio.wait_for(db_pool.acquire(), timeout=5.0)
    except asyncio.TimeoutError:
        logger.error("Таймаут при получении соединения из пула")
        raise HTTPException(
            status_code=503,
            detail="Сервис временно перегружен, попробуйте позже"
        )

# Модели данных
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

class ArticleResponse(BaseModel):
    id: int
    title: str
    content: str

class RecaptchaRequest(BaseModel):
    token: str

class CommentCreate(BaseModel):
    article_id: int
    content: str

class CommentResponse(BaseModel):
    id: int
    article_id: int
    user_id: int
    content: str
    created_at: datetime
    username: str

class CommentDeleteResponse(BaseModel):
    success: bool
    message: str

@router.post("/verify-recaptcha")
@limiter.limit("5 per second")
async def verify_recaptcha(request: Request, recaptcha: RecaptchaRequest):
    """Прокси для Google reCAPTCHA API"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": RECAPTCHA_SECRET_KEY,
                    "response": recaptcha.token
                }
            )
            result = response.json()
            
            if not result.get("success"):
                logger.warning(f"reCAPTCHA проверка не пройдена: {result.get('error-codes', [])}")
                raise HTTPException(
                    status_code=400, 
                    detail="reCAPTCHA проверка не пройдена"
                )
            
            return JSONResponse(content={"success": True})
            
    except (httpx.TimeoutException, httpx.ConnectError) as e:
        logger.error(f"Ошибка подключения к reCAPTCHA: {e}")
        raise HTTPException(
            status_code=503,
            detail="Сервис проверки reCAPTCHA недоступен"
        )

app.include_router(router, prefix="/api")

# Функции для работы с токенами
def create_token(data: dict, expires_delta: timedelta, secret_key: str) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)

def create_access_token(data: dict) -> str:
    return create_token(data, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), SECRET_KEY)

def create_refresh_token(data: dict) -> str:
    return create_token(data, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), REFRESH_SECRET_KEY)

# Утилиты для работы с БД
async def execute_query(query: str, *params):
    """Выполнить SQL запрос с параметрами"""
    conn = await get_db_connection()
    try:
        return await conn.execute(query, *params)
    finally:
        await db_pool.release(conn)

async def fetch_row(query: str, *params):
    """Получить одну строку из БД"""
    conn = await get_db_connection()
    try:
        return await conn.fetchrow(query, *params)
    finally:
        await db_pool.release(conn)

async def fetch_value(query: str, *params):
    """Получить одно значение из БД"""
    conn = await get_db_connection()
    try:
        return await conn.fetchval(query, *params)
    finally:
        await db_pool.release(conn)

async def fetch_all(query: str, *params):
    """Получить все строки из БД"""
    conn = await get_db_connection()
    try:
        return await conn.fetch(query, *params)
    finally:
        await db_pool.release(conn)

@app.post("/api/signup", status_code=status.HTTP_201_CREATED)
@limiter.limit("5 per minute")
async def signup(request: Request, user: UserCreate, response: Response):
    """Регистрация нового пользователя"""
    # Проверка паролей
    if user.password != user.password1:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Пароли не совпадают"},
        )

    # Проверка существующего email
    if await fetch_value("SELECT 1 FROM users WHERE email = $1", user.email):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Пользователь с таким email уже зарегистрирован"},
        )

    # Проверка существующего username
    if await fetch_value("SELECT 1 FROM users WHERE username = $1", user.username):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"message": "Пользователь с таким именем уже зарегистрирован"},
        )

    # Хеширование пароля
    hashed_password = pwd_context.hash(user.password)

    # Создание пользователя
    conn = await get_db_connection()
    try:
        async with conn.transaction():
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

            # Генерация токенов
            access_token = create_access_token(data={"sub": user.email})
            refresh_token = create_refresh_token(data={"sub": user.email})

            # Сохранение refresh токена
            await conn.execute(
                """
                INSERT INTO refresh_tokens (user_id, token, expires_at)
                VALUES ($1, $2, $3)
                """,
                user_id,
                refresh_token,
                datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            )
    finally:
        await db_pool.release(conn)

    # Установка куки
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # Для разработки, в продакшене должно быть True
        samesite="Lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Для разработки
        samesite="Lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
    )

    return {"success": True, "message": "Успешная регистрация"}

@app.post("/api/login")
@limiter.limit("10 per minute")
async def login(request: Request, user: UserLogin, response: Response):
    """Аутентификация пользователя"""
    db_user = await fetch_row(
        "SELECT id, username, hashed_password FROM users WHERE email = $1", 
        user.email
    )
    
    # Проверка пользователя
    if not db_user or not pwd_context.verify(user.password, db_user["hashed_password"]):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"message": "Неверные учетные данные"},
        )

    # Генерация токенов
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})

    # Сохранение refresh токена
    conn = await get_db_connection()
    try:
        await conn.execute(
            """
            INSERT INTO refresh_tokens (user_id, token, expires_at)
            VALUES ($1, $2, $3)
            """,
            db_user["id"],
            refresh_token,
            datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )
    finally:
        await db_pool.release(conn)

    # Установка куки
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="Lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="Lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
    )

    return {"success": True, "message": "Успешная авторизация"}

@app.post("/api/refresh")
@limiter.limit("10 per minute")
async def refresh_token(request: Request, response: Response):
    """Обновление токенов доступа"""
    refresh_token_value = request.cookies.get("refresh_token")
    if not refresh_token_value:
        # return JSONResponse(
        #     status_code=status.HTTP_401_UNAUTHORIZED,
        #     content={"message": "Refresh token отсутствует"},
        # )
        return {"message": False}

    try:
        payload = jwt.decode(refresh_token_value, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        
        # Исправленный запрос - убран id
        token_record = await fetch_row(
            """
            SELECT user_id, expires_at 
            FROM refresh_tokens 
            WHERE token = $1
            """,
            refresh_token_value,
        )
        
        if not token_record or token_record["expires_at"] < datetime.utcnow():
            # return JSONResponse(
            #     status_code=status.HTTP_401_UNAUTHORIZED,
            #     content={"message": "Недействительный refresh token"},
            # )
            return {"message": False}
        
        # Генерация новых токенов
        new_access_token = create_access_token(data={"sub": email})
        new_refresh_token = create_refresh_token(data={"sub": email})
        
        # Обновление токена в базе
        await execute_query(
            """
            UPDATE refresh_tokens 
            SET token = $1, expires_at = $2
            WHERE token = $3
            """,
            new_refresh_token,
            datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            refresh_token_value,
        )
        
        # Установка новых куки
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        )
        
        # return {"success": True, "message": True}
        return {"message": True}

    except jwt.ExpiredSignatureError:
        # return JSONResponse(
        #     status_code=status.HTTP_401_UNAUTHORIZED,
        #     content={"message": "Срок действия refresh token истек"},
        # )
        return {"message": False}
    except jwt.InvalidTokenError:
        # return JSONResponse(
        #     status_code=status.HTTP_401_UNAUTHORIZED,
        #     content={"message": "Недействительный refresh token"},
        # )
        return {"message": False}

@app.get("/api/me")
@limiter.limit("20 per minute")
async def get_current_user(request: Request):
    """Получение информации о текущем пользователе и количестве его статей"""
    access_token = request.cookies.get("access_token")
    if not access_token:
        return {"message": False}
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            return {"message": False}
        # Получение данных пользователя
        user = await fetch_row(
            "SELECT id, username, email FROM users WHERE email = $1", 
            email
        )
        if not user:
            return {"message": False}
        # Получение количества статей пользователя
        article_count = await fetch_value(
            "SELECT COUNT(*) FROM articles WHERE author = $1",
            user["username"]
        )
        return {
            "message": True,
            "username": user["username"],
            "email": user["email"],
            "article_count": article_count
        }
    except jwt.PyJWTError:
        return {"message": False}

@app.get("/api/exit")
@limiter.limit("20 per minute")
async def user_wants_to_exit(request: Request, response: Response):
    """Выход из системы"""
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        try:
            payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
            email = payload.get("sub")
            
            if email:
                await execute_query(
                    """
                    DELETE FROM refresh_tokens 
                    WHERE user_id = (SELECT id FROM users WHERE email = $1)
                    """,
                    email,
                )
        except jwt.PyJWTError:
            pass  # Токен уже невалиден

    # Удаление куки
    response.delete_cookie("access_token", httponly=True, secure=False, samesite="Lax")
    response.delete_cookie("refresh_token", httponly=True, secure=False, samesite="Lax")

    return {"success": True, "message": "Вы вышли из аккаунта"}

@app.get("/api/articles")
@limiter.limit("30 per minute")
async def search_articles(
    request: Request, 
    query: Optional[str] = Query(None, min_length=1, max_length=100),
    author: Optional[str] = Query(None, min_length=1, max_length=50),
    skip: int = 0,
    limit: int = 10,
):
    """Поиск статей по заголовку или автору"""
    try:
        conditions = []
        params = []
        
        if query:
            conditions.append("a.title ILIKE ${}".format(len(params)+1))
            params.append(f"%{query}%")
            
        if author:
            conditions.append("a.author = ${}".format(len(params)+1))
            params.append(author)
            
        if not conditions:
            raise HTTPException(
                status_code=400, 
                detail="Требуется параметр query или author"
            )
            
        where_clause = " AND ".join(conditions)
        params.extend([skip, limit])

        results = await fetch_all(
            f"""
            SELECT 
                a.id, 
                a.author,
                a.title, 
                a.content,
                COALESCE(
                    (SELECT json_agg(json_build_object('id', ai.id, 'path', ai.image_path))
                    FROM article_images ai
                    WHERE ai.article_id = a.id
                    ),
                    '[]'::json
                ) AS images
            FROM articles a
            WHERE {where_clause}
            OFFSET ${len(params)-1} LIMIT ${len(params)}
            """,
            *params,
        )
        return [dict(record) for record in results]
    except Exception as e:
        logger.error(f"Ошибка поиска статей: {e}")
        raise HTTPException(status_code=500, detail="Ошибка выполнения запроса")

@app.get("/api/articles/{article_id}")
@limiter.limit("30 per minute")
async def get_article(request: Request, article_id: int = Path(..., gt=0)):
    """Получение статьи по ID с изображениями"""
    article = await fetch_row(
        """
        SELECT 
            a.id,
            a.author, 
            a.title, 
            a.content,
            COALESCE(
                (SELECT json_agg(json_build_object('id', ai.id, 'path', ai.image_path))
                FROM article_images ai
                WHERE ai.article_id = a.id
                ),
                '[]'::json
            ) AS images
        FROM articles a
        WHERE a.id = $1
        """,
        article_id,
    )
    
    if not article:
        raise HTTPException(status_code=404, detail="Статья не найдена")

    return dict(article)

@app.delete("/api/articles/{article_id}")
@limiter.limit("10 per minute")
async def delete_article(
    request: Request,
    article_id: int = Path(..., gt=0),
):
    """Удаление статьи"""
    # Проверка аутентификации
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Недействительный токен")

    # Получение пользователя
    user = await fetch_row("SELECT username FROM users WHERE email = $1", email)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Получение статьи
    article = await fetch_row(
        "SELECT author FROM articles WHERE id = $1", 
        article_id
    )
    if not article:
        raise HTTPException(status_code=404, detail="Статья не найдена")
    
    # Проверка прав доступа
    if article["author"] != user["username"]:
        raise HTTPException(status_code=403, detail="Нет прав для удаления")

    # Удаление связанных изображений
    images = await fetch_all(
        "SELECT image_path FROM article_images WHERE article_id = $1",
        article_id
    )
    
    # Удаление статьи (каскадное удаление комментариев и изображений из БД)
    await execute_query("DELETE FROM articles WHERE id = $1", article_id)
    
    # Физическое удаление файлов изображений
    for image in images:
        file_path = os.path.join(UPLOAD_DIR, image["image_path"])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Ошибка удаления файла {file_path}: {e}")

    return {"success": True, "message": "Статья удалена"}

@app.get("/api/articles/by-author/{author}")
@limiter.limit("30 per minute")
async def get_articles_by_author(
    request: Request,
    author: str = Path(..., min_length=1, max_length=50),
    skip: int = 0,
    limit: int = 10,
):
    """Получение статей по автору"""
    try:
        results = await fetch_all(
            """
            SELECT 
                a.id, 
                a.author,
                a.title, 
                a.content,
                COALESCE(
                    (SELECT json_agg(json_build_object('id', ai.id, 'path', ai.image_path))
                    FROM article_images ai
                    WHERE ai.article_id = a.id
                    ),
                    '[]'::json
                ) AS images
            FROM articles a
            WHERE a.author = $1
            ORDER BY a.created_at DESC
            OFFSET $2 LIMIT $3
            """,
            author,
            skip,
            limit,
        )
        return [dict(record) for record in results]
    except Exception as e:
        logger.error(f"Ошибка получения статей автора {author}: {e}")
        raise HTTPException(status_code=500, detail="Ошибка выполнения запроса")

@app.post("/api/addarticle")
@limiter.limit("10 per minute")
async def addarticle(
    request: Request,
    author: str = Form(...),
    title: str = Form(...),
    content: str = Form(...),
    images: list[UploadFile] = File([]),
):
    """Добавление новой статьи с изображениями"""
    
    # Логирование входящих данных
    logger.info(f"Received addarticle request")
    logger.info(f"Author: {author}")
    logger.info(f"Title: {title}")
    logger.info(f"Content length: {len(content)}")
    logger.info(f"Images count: {len(images)}")
    
    # Логирование файлов
    for i, image in enumerate(images):
        logger.info(f"Image {i+1}: {image.filename}, size: {image.size}, type: {image.content_type}")
    
    # Проверка аутентификации
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    
    try:
        jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Недействительный токен")

    errors = []
    saved_files = []
    conn = await get_db_connection()
    
    try:
        async with conn.transaction():
            # Сохраняем статью
            article_id = await conn.fetchval(
                "INSERT INTO articles (author, title, content) VALUES ($1, $2, $3) RETURNING id",
                author,
                title,
                content,
            )

            # Обрабатываем изображения
            for image in images:
                # Проверка типа изображения
                if image.content_type not in ALLOWED_IMAGE_TYPES:
                    errors.append(f"Недопустимый тип файла: {image.filename}")
                    continue
                
                # Проверка размера (максимум 10 МБ)
                if image.size > 10 * 1024 * 1024:
                    errors.append(f"Файл слишком большой: {image.filename}")
                    continue
                
                # Генерация уникального имени файла
                file_ext = os.path.splitext(image.filename)[1]
                file_name = f"{uuid.uuid4().hex}{file_ext}"
                file_path = os.path.join(UPLOAD_DIR, file_name)
                
                # Сохранение файла
                try:
                    contents = await image.read()
                    with open(file_path, "wb") as f:
                        f.write(contents)
                    saved_files.append(file_path)
                except Exception as e:
                    errors.append(f"Ошибка сохранения файла: {image.filename}")
                    continue
                
                # Сохранение информации о файле в БД
                await conn.execute(
                    "INSERT INTO article_images (article_id, image_path) VALUES ($1, $2)",
                    article_id,
                    file_name,
                )
                
    except Exception as e:
        # Удаляем сохраненные файлы при ошибке
        for file_path in saved_files:
            try:
                os.remove(file_path)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Ошибка сервера: {str(e)}")
    
    finally:
        await db_pool.release(conn)

    # Формируем ответ
    response = {"success": True, "message": "Статья успешно добавлена"}
    if errors:
        response["warnings"] = errors
        
    return response

@app.post("/api/comments")
@limiter.limit("20 per minute")
async def add_comment(request: Request, comment: CommentCreate):
    """Добавление комментария к статье"""
    # Проверка аутентификации
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Недействительный токен")

    # Получение пользователя
    user = await fetch_row("SELECT id, username FROM users WHERE email = $1", email)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверка существования статьи
    article_exists = await fetch_value("SELECT 1 FROM articles WHERE id = $1", comment.article_id)
    if not article_exists:
        raise HTTPException(status_code=404, detail="Статья не найдена")

    # Добавление комментария
    conn = await get_db_connection()
    try:
        comment_record = await conn.fetchrow(
            """
            INSERT INTO comments (article_id, user_id, content)
            VALUES ($1, $2, $3)
            RETURNING id, created_at
            """,
            comment.article_id,
            user["id"],
            comment.content,
        )
    finally:
        await db_pool.release(conn)

    return {
        "id": comment_record["id"],
        "content": comment.content,
        "created_at": comment_record["created_at"].isoformat(),
        "username": user["username"],
    }

@app.get("/api/comments/{article_id}")
@limiter.limit("30 per minute")
async def get_comments(request: Request, article_id: int = Path(..., gt=0)):
    """Получение комментариев для статьи"""
    comments = await fetch_all(
        """
        SELECT c.id, c.content, c.created_at, u.username 
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.article_id = $1
        ORDER BY c.created_at DESC
        """,
        article_id,
    )
    
    return [
        {
            "id": comment["id"],
            "content": comment["content"],
            "created_at": comment["created_at"].isoformat(),
            "username": comment["username"],
        }
        for comment in comments
    ]

@app.delete("/api/comments/{comment_id}")
@limiter.limit("20 per minute")
async def delete_comment(
    request: Request,
    comment_id: int = Path(..., gt=0),
):
    """Удаление комментария"""
    # Проверка аутентификации
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Недействительный токен")

    # Получение пользователя
    user = await fetch_row("SELECT id FROM users WHERE email = $1", email)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверка прав на удаление
    comment = await fetch_row(
        "SELECT user_id FROM comments WHERE id = $1", 
        comment_id
    )
    if not comment:
        raise HTTPException(status_code=404, detail="Комментарий не найден")
    
    if comment["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Нет прав для удаления")

    # Удаление комментария
    await execute_query("DELETE FROM comments WHERE id = $1", comment_id)
    
    return {"success": True, "message": "Комментарий удален"}

if __name__ == "__main__":
    # Конфигурация сервера для высокой нагрузки
    uvicorn_config = {
        "app": "main:app",
        "host": "0.0.0.0",
        "port": 8000,
        "reload": True,
        "workers": 4,  # Используем 4 воркера
        "timeout_keep_alive": 30,  # 30 секунд
        "limit_concurrency": 100,  # Максимум 100 одновременных соединений
        "backlog": 1000,  # Размер очереди соединений
        "log_level": "info"
    }
    
    logger.info(f"Запуск сервера с конфигурацией: {uvicorn_config}")
    uvicorn.run(**uvicorn_config)
