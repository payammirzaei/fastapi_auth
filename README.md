# FastAPI Auth System

## Overview

This project is a robust, production-ready authentication and user management system built with FastAPI, SQLAlchemy, and modern Python security best practices. It is designed to be a solid foundation for any web or API project requiring secure user authentication, email verification, password recovery, and more.

---

## Features

- **User Registration** with email verification
- **JWT Authentication** (access & refresh tokens)
- **Refresh Token Rotation** and revocation
- **Secure Password Hashing** (bcrypt)
- **Password Recovery** (forgot/reset password via email)
- **Change Password**
- **Update User Profile** (name, phone, email)
- **Logout** (refresh token revocation)
- **Phone Number Validation** (E.164 format)
- **Email Configuration** via `.env`
- **Only Verified Users Can Log In**
- **Environment-based Configuration** for all secrets and URLs

---

## Architecture Overview

- **FastAPI** for high-performance, async API endpoints
- **SQLAlchemy** (async) for ORM and database access
- **Alembic** for database migrations
- **Pydantic** for data validation and settings management
- **itsdangerous** for secure, stateless token generation (email verification, password reset)
- **passlib** for password hashing
- **pydantic-extra-types** for phone number validation

---

## Getting Started

### 1. Clone the Repository

```sh
git clone https://github.com/payammirzaei/fastapi_auth.git
cd fastapi_auth
```

### 2. Create and Activate a Virtual Environment

```sh
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```sh
pip install -r requirements.txt
```

### 4. Configure Your Environment

Create a `.env` file in the project root with the following content:

```ini
# Database
DB_URL=postgresql+asyncpg://user:password@localhost:5432/yourdb
POSTGRES_USER=youruser
POSTGRES_PASSWORD=yourpassword
POSTGRES_DB=yourdb
POSTGRES_SERVER=localhost
POSTGRES_PORT=5432

# JWT
JWT_SECRET=your-very-secret-key

# Email (for verification and password reset)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your@email.com
EMAIL_PASSWORD=your_email_password
EMAIL_FROM=your@email.com
EMAIL_FROM_NAME=YourAppName

# Frontend or API base URL (for links in emails)
FRONTEND_URL=http://localhost:8000
```

> **Important:** Never commit your real `.env` file or secrets to version control.

### 5. Run Database Migrations

If you use Alembic, run:

```sh
alembic upgrade head
```

### 6. Start the Application

```sh
uvicorn app.main:app --reload
```

### 7. Open the API Docs

Visit [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive Swagger UI.

---

## Usage Highlights

- **Registration:**

  - Users register with their email and receive a verification link.
  - Accounts are inactive until verified via the emailed link.

- **Login:**

  - Only verified users can log in.
  - Returns both access and refresh tokens.

- **Refresh Token:**

  - Use `/auth/refresh` to obtain a new access token with a valid refresh token.
  - Refresh tokens are rotated and revoked for security.

- **Password Recovery:**

  - Use `/auth/forgot-password` to request a password reset link.
  - Use `/auth/reset-password` to set a new password with the emailed token.

- **Profile Management:**

  - Use `/users/me` to view your profile.
  - Use `PATCH /users/me` to update your name, phone, or email.
  - Use `/users/change-password` to change your password (requires current password).

- **Logout:**
  - Use `/users/logout` to revoke your refresh token.

---

## API Endpoints (Key Examples)

- `POST /auth/register` — Register a new user
- `GET /auth/verify-email` — Verify email with token
- `POST /auth/login` — Log in and receive tokens
- `POST /auth/refresh` — Refresh access token
- `POST /auth/forgot-password` — Request password reset
- `POST /auth/reset-password` — Reset password with token
- `GET /users/me` — Get current user profile
- `PATCH /users/me` — Update profile
- `POST /users/change-password` — Change password
- `POST /users/logout` — Logout (revoke refresh token)

---

## Developer Notes

- All email links (verification, password reset) use the `FRONTEND_URL` from `.env`.
- Phone numbers must be in E.164 format (e.g., `+989171064369`).
- Passwords are securely hashed with bcrypt.
- Refresh tokens are stored and rotated for security.
- All sensitive config is loaded from `.env` using Pydantic Settings.
- Use Alembic for database migrations when changing models.

---

## Security Best Practices

- Use strong, unique secrets for JWT and email.
- Use HTTPS in production.
- Set up proper CORS and rate limiting as needed.
- Regularly update dependencies.
- Never log or expose sensitive data.

---

## License

MIT
