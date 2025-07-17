# app/main.py

from fastapi import FastAPI
from app.api import routes_auth, routes_users
from app.db.models import Base
from app.db.session import engine
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(
    title="Production FastAPI App",
    description="""
    **2FA Login Instructions:**  
    - When using the Swagger UI \"Authorize\" button, enter your 2FA code in the `client_secret` field.\n    - For JSON login, use the `/auth/login-json` endpoint and provide `two_fa_code` in the request body.\n - for using Swagger UI \"Authorize\" button put Client credentials location on Request Body
   
    """
)
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Include routers
app.include_router(routes_auth.router)
app.include_router(routes_users.router)

# Optional: create tables on startup (for development only)
@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
