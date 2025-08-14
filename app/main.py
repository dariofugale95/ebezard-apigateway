
# === FastAPI and dependencies imports ===
from urllib import response
from fastapi import FastAPI, Request, APIRouter, HTTPException  # FastAPI core imports
from fastapi.middleware.cors import CORSMiddleware  # CORS middleware for cross-origin requests
from fastapi.responses import JSONResponse, RedirectResponse  # Response types
import httpx  # Async HTTP client for service-to-service calls
import os  # For environment variable access

import secrets  # For generating secure random strings (if needed)
import hashlib  # For hashing passwords or sensitive data if needed
import base64  # For encoding/decoding data if needed
import redis  # For caching and session storage
from urllib.parse import urlencode  # For URL encoding parameters

# === Create the FastAPI application instance ===
app = FastAPI(title="eBezard API Gateway")  # Main FastAPI app
router = APIRouter()  # Router for grouping endpoints

# === Enable CORS for frontend and microservices communication ===
# Read allowed origins from environment variable (comma-separated)
ALLOWED_ORIGINS_GATEWAY = os.environ.get("ALLOWED_ORIGINS_GATEWAY", "https://localhost:5180").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS_GATEWAY],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Service URLs and OAuth2 credentials from environment variables ===
# These allow the gateway to communicate with other services and perform OAuth2 flows
BACKEND_BASE_URL = os.environ.get("BACKEND_BASE_URL", "https://localhost:8001")  # Backend service base URL
AUTH_BASE_URL = os.environ.get("AUTH_BASE_URL", "https://localhost:8003")  # Auth service base URL
AUTH_BASE_URL_PUBLIC = os.environ.get("AUTH_BASE_URL_PUBLIC", "https://localhost:8003")  # Public Auth service URL
LANDING_URL = os.environ.get("LANDING_BASE_URL", "https://localhost:8088")  # Landing page URL
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://localhost:5180")  # Frontend redirect URL (business)
MARKETPLACE_URL = os.environ.get("MARKETPLACE_URL", "https://localhost:8200")  # Marketplace redirect URL (customer)
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")  # OAuth2 client ID
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")  # OAuth2 client secret
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "https://localhost:8300/oauth/callback")  # Registered redirect URI

# === Redis configuration for caching and session storage ===
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")  # Redis connection URL
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)  # Create Redis client instance

# OAuth login endpoint
@router.get("/api/oauth/login")
async def oauth_login(request: Request):
    """
    Start the OIDC SSO flow: generate PKCE, save code_verifier and state in Redis, redirect to /o/authorize/.
    """
    next_url = request.query_params.get("next") or FRONTEND_URL
    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()
    # Save in Redis (10 min)
    redis_client.setex(f"sso:state:{state}", 600, f"{code_verifier}|{next_url}")
    # Build authorization URL
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{AUTH_BASE_URL_PUBLIC}/o/authorize/?{urlencode(params)}"
    return RedirectResponse(auth_url)

# OAuth callback endpoint
@router.get("/api/oauth/callback")
async def oauth_callback(request: Request):
    """
    Callback OIDC: receives the code, retrieves code_verifier from Redis, exchanges the code for tokens, redirects to the frontend.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return JSONResponse(status_code=400, content={"detail": "Missing code or state"})

    # Retrieve code_verifier and next_url from Redis
    redis_key = f"sso:state:{state}"
    value = redis_client.get(redis_key)
    if not value:
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired state"})
    code_verifier, next_url = value.split("|", 1)
    redis_client.delete(redis_key)

    # Exchange the code for tokens
    token_url = f"{AUTH_BASE_URL}/o/token/"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "client_id": OAUTH_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    print("[API Gateway] - Token request data:", data)
    async with httpx.AsyncClient(
        cert=("/certs/apigateway-cert.pem", "/certs/apigateway-key.pem"),
        verify="/certs/ca-cert.pem"
    ) as client:
        resp = await client.post(token_url, data=data)
        if resp.status_code != 200:
            return JSONResponse(status_code=400, content={"detail": "Token exchange failed", "error": resp.text})
        tokens = resp.json()

    # ...after obtaining tokens = resp.json()
    response = RedirectResponse(f"{next_url}?sso=ok")
    # Save only the access token (or a session id if you want to manage server-side sessions)
    response.set_cookie(
        key="session_token",
        value=tokens["access_token"],
        httponly=True,
        secure=True,  # only on HTTPS in prod
        samesite="lax",  # or "strict"
        max_age=3600,    # duration in seconds
        path="/"
    )
    return response

# User info endpoint
@router.get("/api/me")
async def get_me(request: Request):
    """ Verify user session through token on HttpOnly cookie and returns user info if authenticated """
    session_token = request.cookies.get("session_token")
    if not session_token:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    
    userinfo_url = f"{AUTH_BASE_URL}/o/userinfo/"
    headers = {"Authorization": f"Bearer {session_token}"}
    async with httpx.AsyncClient(
        cert=("/certs/apigateway-cert.pem", "/certs/apigateway-key.pem"),
        verify="/certs/ca-cert.pem"
    ) as client:
        resp = await client.get(userinfo_url, headers=headers)
        if resp.status_code != 200:
            return JSONResponse(status_code=401, content={"detail": "Invalid or expired session"})
        user_info = resp.json()
    return JSONResponse(status_code=200, content=user_info)

# Logout endpoint
@router.post("/api/users/logout")
async def logout(request: Request):
    """
    OIDC logout: clear local session/cookie and return the landing page URL.
    """
    # Remove the session_token cookie (this is the actual session cookie)
    response = JSONResponse({"detail": "Logged out"})
    response.delete_cookie(
        "session_token",
        path="/",
        secure=True,
        samesite="lax"
    )

    # Return the landing page URL for the frontend to redirect the user
    landing_join_url = f"{LANDING_URL}/join"
    return JSONResponse({"logout_url": landing_join_url})

# === Login endpoint ===
@router.post("/api/users/login/")
async def login_user(request: Request):
    """
    Classic login: forwards username/email and password to the Auth service and returns the result.
    """
    data = await request.json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return JSONResponse(status_code=400, content={"detail": "Username and password are required"})

    # Forward the request to the Auth service (Django)
    async with httpx.AsyncClient(
        cert=("/certs/apigateway-cert.pem", "/certs/apigateway-key.pem"),
        verify="/certs/ca-cert.pem"
    ) as client:
        auth_resp = await client.post(f"{AUTH_BASE_URL}/users/login/", json={"username": username, "password": password})
        if auth_resp.status_code != 200:
            try:
                detail = auth_resp.json()
            except Exception:
                detail = auth_resp.text
            return JSONResponse(status_code=auth_resp.status_code, content={"detail": detail})
        # Return the token/session received from the Auth service
        return JSONResponse(status_code=200, content=auth_resp.json())
    
# === User registration endpoint ===
@router.post("/api/users/register/")
async def register_user(request: Request):
    """
    Handles user registration in two steps:
    1. Registers the user on the Auth Server (for authentication).
    2. If successful, registers the user on the Backend (for business/customer data).
    The frontend only needs to call this endpoint with all required fields.
    """
    data = await request.json()  # Parse the incoming JSON payload
    user_type = data.get("user_type")
    if user_type not in ("business", "customer"):
        # Validate user_type
        raise HTTPException(status_code=400, detail="Invalid user_type. Must be 'business' or 'customer'.")

    # Step 1: Register user on the Auth Server
    async with httpx.AsyncClient(
        cert=("/certs/apigateway-cert.pem", "/certs/apigateway-key.pem"),
        verify="/certs/ca-cert.pem"
    ) as client:
        auth_resp = await client.post(f"{AUTH_BASE_URL}/users/register/", json=data)
        if auth_resp.status_code != 201:
            # Forward error from Auth Server to the frontend
            try:
                detail = auth_resp.json()
            except Exception:
                detail = auth_resp.text
                print(f"[API Gateway] Auth registration error: {detail}")
            raise HTTPException(status_code=auth_resp.status_code, detail=detail)

        # Step 2: Register user on the Backend (flat payload)
        backend_data = {
            "username": data["username"],
            "email": data["email"]
        }
        # Choose the correct backend endpoint based on user_type
        backend_endpoint = "/api/users/register/business/" if user_type == "business" else "/api/users/register/customer/"
        backend_resp = await client.post(f"{BACKEND_BASE_URL}{backend_endpoint}", json=backend_data)
        if backend_resp.status_code != 201:
            # Log backend registration errors for debugging
            try:
                detail = backend_resp.json()
            except Exception:
                detail = backend_resp.text
            print(f"[API Gateway] Backend registration error: {detail}")
            raise HTTPException(status_code=backend_resp.status_code, detail=detail)

    # Registration successful
    return JSONResponse(status_code=201, content={"detail": "Registration successful"})

# === Info endpoint for landing page ===
@router.get("/info")
async def get_info():
    """
    Returns general information about eBezard for the landing page.
    """
    return {
        "name": "eBezard",
        "description": "The platform for businesses and customers: create, manage, or discover online stores!",
        "year": 2025,
        "features": [
            "Online store management",
            "Marketplace for customers",
            "Business and customer registration",
            "Business dashboard",
        ]
    }

# === Register the router with the app ===
app.include_router(router)