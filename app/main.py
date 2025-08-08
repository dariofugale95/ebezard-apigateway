
# === FastAPI and dependencies imports ===
from fastapi import FastAPI, Request, APIRouter, HTTPException  # FastAPI core imports
from fastapi.middleware.cors import CORSMiddleware  # CORS middleware for cross-origin requests
from fastapi.responses import JSONResponse, RedirectResponse  # Response types
import httpx  # Async HTTP client for service-to-service calls
import os  # For environment variable access

# === Create the FastAPI application instance ===
app = FastAPI(title="eBezard API Gateway")  # Main FastAPI app
router = APIRouter()  # Router for grouping endpoints

# === Enable CORS for frontend and microservices communication ===
# Read allowed origins from environment variable (comma-separated)
ALLOWED_ORIGINS_GATEWAY = os.environ.get("ALLOWED_ORIGINS_GATEWAY", "http://localhost:5180").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS_GATEWAY],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Service URLs and OAuth2 credentials from environment variables ===
# These allow the gateway to communicate with other services and perform OAuth2 flows
BACKEND_BASE_URL = os.environ.get("BACKEND_BASE_URL", "http://localhost:8001")  # Backend service base URL
AUTH_BASE_URL = os.environ.get("AUTH_BASE_URL", "http://localhost:8003")  # Auth service base URL
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5180")  # Frontend redirect URL (business)
MARKETPLACE_URL = os.environ.get("MARKETPLACE_URL", "http://localhost:8200")  # Marketplace redirect URL (customer)
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")  # OAuth2 client ID
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")  # OAuth2 client secret
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:8300/oauth/callback")  # Registered redirect URI

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
    async with httpx.AsyncClient() as client:
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
    async with httpx.AsyncClient() as client:
        auth_resp = await client.post(f"{AUTH_BASE_URL}/users/register/", json=data)
        if auth_resp.status_code != 201:
            # Forward error from Auth Server to the frontend
            try:
                detail = auth_resp.json()
            except Exception:
                detail = auth_resp.text
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