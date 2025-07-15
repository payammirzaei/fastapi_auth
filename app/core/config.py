# app/core/config.py

from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    db_url: str | None = None
    jwt_secret: str
    access_token_expire_minutes: int = 30
    postgres_user: str
    postgres_password: str
    postgres_db: str
    postgres_server: str
    postgres_port: int
    email_host: str
    email_port: int
    email_user: str
    email_password: str
    email_from: str
    email_from_name: str
    frontend_url: str
    app_name: str

    model_config = SettingsConfigDict(env_file=".env")

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()
