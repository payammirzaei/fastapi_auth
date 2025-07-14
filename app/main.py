# app/main.py

from fastapi import FastAPI
from app.api import routes_auth, routes_users
from app.db.models import Base
from app.db.session import engine

app = FastAPI(title="Production FastAPI App")

# Include routers
app.include_router(routes_auth.router)
app.include_router(routes_users.router)

# Optional: create tables on startup (for development only)
@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
