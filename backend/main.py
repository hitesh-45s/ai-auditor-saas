"""
Main API Gateway for the AI Auditor SaaS.
Handles incoming scan requests and queues them in Redis.
Includes CORS Middleware, JWT Authentication, and Rate Limiting.
"""
import os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl
from dotenv import load_dotenv
from upstash_redis import Redis
from supabase import create_client, Client
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# pylint: disable=broad-exception-caught

# Load secret keys from the .env file
load_dotenv(dotenv_path="../.env")

# 1. Initialize Upstash (The Conveyor Belt)
REDIS_URL = os.getenv("UPSTASH_REDIS_REST_URL")
REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")

if not REDIS_URL or not REDIS_TOKEN:
    raise RuntimeError("CRITICAL ERROR: Upstash Redis keys are missing!")

redis = Redis(url=REDIS_URL, token=REDIS_TOKEN)

# 2. Initialize Supabase (The Vault)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("CRITICAL ERROR: Supabase keys are missing!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# 3. Rate Limiting setup
limiter = Limiter(key_func=get_remote_address)

# Initialize the API Framework
app = FastAPI(
    title="AI Auditor SaaS API",
    description="The engine powering the AI web modernization platform.",
    version="2.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- THE VIP GUEST LIST (CORS) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # The Next.js Showroom
    allow_credentials=True,
    allow_methods=["*"], # Allow GET, POST, etc.
    allow_headers=["*"],
)

# --- AUTHENTICATION MIDDLEWARE ---
security = HTTPBearer()

def verify_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verifies the user by directly asking the Supabase Auth server."""
    token = credentials.credentials
    try:
        # We use the built-in Supabase client to verify the token for us!
        user_response = supabase.auth.get_user(token)
        
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
            
        # If successful, return the verified user's ID
        return user_response.user.id
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")


# DATA MODELS
class ScanRequest(BaseModel):
    url: HttpUrl
    # user_id is removed from here; we extract it securely from the verified token above

# API ENDPOINTS
@app.get("/")
def health_check():
    return {"status": "online", "message": "AI Auditor Engine is active."}


@app.post("/api/scan")
@limiter.limit("5/minute") # Protects the endpoint from spam
async def request_scan(request: Request, payload: ScanRequest, user_id: str = Depends(verify_user)):
    try:
        domain = str(payload.url)

        website_response = supabase.table("websites").select("id").eq(
            "user_id", user_id
        ).eq("domain_url", domain).execute()

        if len(website_response.data) > 0:
            website_id = website_response.data[0]['id']
        else:
            new_website = supabase.table("websites").insert({
                "user_id": user_id,
                "domain_url": domain
            }).execute()
            website_id = new_website.data[0]['id']

        now_iso = datetime.now(timezone.utc).isoformat()
        new_scan = supabase.table("scans").insert({
            "website_id": website_id,
            "status": "pending",
            "started_at": now_iso
        }).execute()

        scan_id = new_scan.data[0]['id']

        job_ticket = {
            "scan_id": scan_id,
            "target_url": domain,
            "user_id": user_id,
            "status": "pending"
        }
        redis.lpush("scan_queue", job_ticket)

        return {
            "message": "Scan accepted, authenticated, and queued.",
            "scan_id": scan_id,
            "website_id": website_id
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to process scan: {str(e)}"
        ) from e


@app.get("/api/scans")
async def list_user_scans(user_id: str = Depends(verify_user)):
    """Retrieves all past scan records ordered from most recent to oldest."""
    try:
        websites_resp = supabase.table("websites").select("id, domain_url").eq("user_id", user_id).execute()
        if not websites_resp.data:
            return []

        website_map = {w["id"]: w["domain_url"] for w in websites_resp.data}
        website_ids = list(website_map.keys())

        scans_resp = supabase.table("scans")\
            .select("id, website_id, status, started_at, completed_at, audit_results(raw_data, created_at)")\
            .in_("website_id", website_ids)\
            .execute()

        scans_list = []
        for scan in scans_resp.data:
            audit_records = scan.get("audit_results") or []
            first_audit = audit_records[0] if audit_records else {}
            raw_data = first_audit.get("raw_data") if isinstance(first_audit, dict) else {}
            score = raw_data.get("global_score") if isinstance(raw_data, dict) else None
            vulns = raw_data.get("critical_vulnerabilities") if isinstance(raw_data, dict) else []

            # Reliable timestamp prioritization: audit creation -> completed_at -> started_at
            timestamp = (
                first_audit.get("created_at")
                or scan.get("completed_at")
                or scan.get("started_at")
                or ""
            )

            scans_list.append({
                "id": scan["id"],
                "website_id": scan["website_id"],
                "domain_url": website_map.get(scan["website_id"], "Unknown"),
                "status": scan["status"],
                "started_at": scan.get("started_at"),
                "completed_at": scan.get("completed_at"),
                "created_at": timestamp,
                "global_score": score,
                "vulnerability_count": len(vulns) if isinstance(vulns, list) else 0,
                "top_issue": raw_data.get("top_global_issue") if isinstance(raw_data, dict) else None,
            })

        # Sort strictly from newest (most recent) to oldest
        scans_list.sort(key=lambda s: s.get("created_at") or s.get("id") or "", reverse=True)

        return scans_list

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch scan history: {str(e)}") from e


@app.get("/api/scans/{scan_id}")
async def get_scan_results(scan_id: str, user_id: str = Depends(verify_user)):
    try:
        response = supabase.table("scans").select("*, websites(user_id), audit_results(*)").eq("id", scan_id).execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="Scan not found.")
            
        scan_data = response.data[0]
        
        # Security Check: Ensure the scan belongs to the requesting user
        if scan_data.get("websites", {}).get("user_id") != user_id:
             raise HTTPException(status_code=403, detail="Not authorized to view this scan.")
             
        return scan_data
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e)) from e