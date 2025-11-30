Backend service for authentication, onboarding and secure profile management used by SIH.

Features:
- Local registration + login
- Google OAuth 2.0
- JWT (RS256) access tokens + rotating refresh tokens (hashed)
- Onboarding (UserDetails)
- HttpOnly cookie-based sessions
- Secure defaults (helmet, bcrypt, rate limiter, CORS)

---

## Table of contents
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Quick setup](#quick-setup)
- [Environment variables](#environment-variables)
- [Generate RSA keys](#generate-rsa-keys)
- [Running](#running)
- [API endpoints](#api-endpoints)
- [Database structure](#database-structure)
- [Testing (Postman)](#testing-postman)
- [Security notes](#security-notes)
- [Contributing](#contributing)

---

## Tech stack
- Node.js + Express
- MongoDB + Mongoose
- JWT (RS256)
- OAuth 2.0 (Google)
- bcrypt for password hashing

---

## Project structure
src/
  - config/
    - env.js
    - db.js
  - controllers/
    - auth.controller.js
    - user.controller.js
  - models/
    - User.js
    - UserDetails.js
  - routes/
    - auth.js
    - api.js
  - utils/
    - jwt.js
    - crypto.js
  - app.js
  - server.js

---

## Quick setup

1. Clone repo and install dependencies:
   - Windows / PowerShell:
     - npm install

2. Create `.env` in project root and set required variables (see below).

---

## Environment variables
Example `.env`:

PORT=4000  
MONGO_URI=mongodb://localhost:27017/sih

APP_URL=http://localhost:3000

JWT_PRIVATE_KEY_PATH=./keys/jwt_private.pem  
JWT_PUBLIC_KEY_PATH=./keys/jwt_public.pem  
JWT_ACCESS_EXP=15m  
REFRESH_TOKEN_EXP_DAYS=30

COOKIE_DOMAIN=localhost  
COOKIE_SECURE=false

GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID  
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET  
GOOGLE_CALLBACK_URL=http://localhost:4000/auth/google/callback

---

## Generate RSA keys
Create keys directory and generate 2048-bit RSA pair:

Windows (Git Bash / PowerShell with OpenSSL):
openssl genpkey -algorithm RSA -out keys/jwt_private.pem -pkeyopt rsa_keygen_bits:2048  
openssl rsa -pubout -in keys/jwt_private.pem -out keys/jwt_public.pem

Make sure the .env paths match these files.

---

## Running the app
Development (hot reload):
npm run dev

Production:
node src/server.js

---

## API endpoints

Auth
- POST /auth/register — Register user
- POST /auth/login — Login (sets HttpOnly cookies)
- GET /auth/google — Redirect to Google OAuth
- GET /auth/google/callback — Google OAuth callback
- POST /auth/refresh — Refresh access token (rotating logic)
- POST /auth/logout — Logout, revoke tokens, clear cookies

User / Onboarding (protected)
- GET /api/me — Get onboarding profile
- POST /api/me — Create/update onboarding profile

---

## Database structure (high level)

User
{
  email: String,
  passwordHash: String,
  providers: [{ name: "google", id: "xyz" }],
  refreshTokens: [{ tokenHash: String, expiresAt: Date, rotated: Boolean }],
  roles: [String],
  lastLoginAt: Date
}

UserDetails
{
  user: ObjectId (ref User),
  ageRange: String,
  preferredLanguage: String,
  state: String,
  district: String,
  education: { highestQualification, stream, status },
  skills: [String],
  interestSectors: [String],
  careerGoal: String
}

---

## Testing (Postman)
1. Login
   - POST http://localhost:4000/auth/login
   - Body: { "email": "test@gmail.com", "password": "password123" }
   - Response sets cookies: access_token, refresh_token (HttpOnly)

2. Get profile
   - GET http://localhost:4000/api/me

3. Update profile
   - POST http://localhost:4000/api/me
   - Body: example payload below

Example UserDetails payload:
{
  "ageRange": "18-24",
  "preferredLanguage": "English",
  "state": "Delhi",
  "district": "South West",
  "education": {
    "highestQualification": "B.Tech",
    "stream": "IT",
    "status": "Final Year"
  },
  "skills": ["JavaScript","Node.js","MongoDB"],
  "interestSectors": ["AI","Web Development"],
  "careerGoal": "Full-stack Developer"
}

---

## Security notes
- Access token: RS256 signed (private key)
- Refresh tokens hashed + rotated (stored hashed in DB)
- HttpOnly cookies to protect against XSS
- Helmet, CORS and rate limiting configured in app

---

## Contributing
- Follow the existing structure for routes/controllers/models
- Add tests where possible and keep secrets out of the repo (.env, keys)

---