import secrets

# Генерация 32-байтного (256-битного) ключа в формате Base64
secret_key = secrets.token_urlsafe(32)
refresh_secret_key = secrets.token_urlsafe(32)

print("SECRET_KEY:", secret_key)
print("REFRESH_SECRET_KEY:", refresh_secret_key)