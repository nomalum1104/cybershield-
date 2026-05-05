from fastapi import APIRouter, Request, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from app.Security import (
    authenticate, validate_token, revoke_token,
    check_rate_limit, sanitize_input,
    get_audit_log, get_blocked_ips, get_active_sessions
)
from app.services.risk_model import analyze_url, analyze_email
import random
from datetime import datetime
from app.static.server import load_data, save_data
from app.static.server import load_data, save_data

router = APIRouter(prefix="/api/admin")

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host

def require_auth(request: Request) -> str:
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        raise HTTPException(429, "Juda ko'p so'rov. Keyinroq urinib ko'ring.")
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        raise HTTPException(401, "Avtorizatsiya talab qilinadi")
    user = validate_token(token, ip)
    if not user:
        raise HTTPException(401, "Token yaroqsiz yoki muddati o'tgan")
    return user

# ── Models ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class ScanBatchRequest(BaseModel):
    items: list
    scan_type: str = "url"

# ── Auth endpoints ────────────────────────────────────────────────────────────
@router.post("/login")
async def admin_login(data: LoginRequest, request: Request):
    ip = get_client_ip(request)
    if not check_rate_limit(ip):
        raise HTTPException(429, "Juda ko'p urinish")
    username = sanitize_input(data.username)
    result = authenticate(username, data.password, ip)
    if result["success"]:
        return result
    status = 423 if result.get("blocked") else 401
    raise HTTPException(status, result["error"])

@router.post("/logout")
async def admin_logout(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    ip = get_client_ip(request)
    revoke_token(token, ip)
    return {"success": True}

# ── Protected endpoints ───────────────────────────────────────────────────────
@router.get("/dashboard")
async def admin_dashboard(request: Request):
    require_auth(request)
    return {
        "stats": {
            "total_users": random.randint(150, 200),
            "active_sessions": len(get_active_sessions()),
            "threats_today": random.randint(20, 60),
            "scans_today": random.randint(100, 300),
            "blocked_ips": len(get_blocked_ips()),
            "audit_events": len(get_audit_log(200))
        },
        "departments": [
            {"name": "Buxgalteriya", "risk": 67, "users": 12, "trained": 5},
            {"name": "IT", "risk": 34, "users": 8, "trained": 8},
            {"name": "HR", "risk": 23, "users": 15, "trained": 14},
            {"name": "Sotuvlar", "risk": 75, "users": 20, "trained": 9},
            {"name": "Marketing", "risk": 45, "users": 10, "trained": 6},
            {"name": "Yuristlar", "risk": 52, "users": 6, "trained": 3},
            {"name": "Logistika", "risk": 38, "users": 14, "trained": 10},
            {"name": "Ombor", "risk": 71, "users": 9, "trained": 4},
            {"name": "Qo'riqchilar", "risk": 82, "users": 7, "trained": 2},
            {"name": "Qo'llab-quvvatlash", "risk": 43, "users": 11, "trained": 8}
        ],
        "recent_threats": [
            {"time": "14:32", "type": "Phishing URL", "user": "employee@company.uz", "risk": "HIGH", "blocked": True},
            {"time": "13:15", "type": "Suspicious Email", "user": "hr@company.uz", "risk": "MEDIUM", "blocked": False},
            {"time": "12:44", "type": "Malicious Domain", "user": "it@company.uz", "risk": "HIGH", "blocked": True},
            {"time": "11:20", "type": "Social Engineering", "user": "sales@company.uz", "risk": "MEDIUM", "blocked": False},
            {"time": "10:05", "type": "Phishing URL", "user": "admin@company.uz", "risk": "LOW", "blocked": True},
        ]
    }

@router.get("/audit")
async def get_audit(request: Request):
    require_auth(request)
    return {"logs": get_audit_log(100)}

@router.get("/security")
async def get_security_status(request: Request):
    require_auth(request)
    return {
        "blocked_ips": get_blocked_ips(),
        "active_sessions": get_active_sessions(),
        "protections": [
            {"name": "Brute Force Himoyasi", "status": "FAOL", "detail": "5 urinishdan keyin 15 daqiqa blok"},
            {"name": "Rate Limiting", "status": "FAOL", "detail": "30 so'rov/daqiqa chegarasi"},
            {"name": "XSS Himoyasi", "status": "FAOL", "detail": "Barcha kirishlar sanitize qilinadi"},
            {"name": "SQL Injection", "status": "FAOL", "detail": "Zararli so'rovlar filtrlangan"},
            {"name": "Token Auth", "status": "FAOL", "detail": "1 soatlik sessiya tokenlar"},
            {"name": "IP Monitoring", "status": "FAOL", "detail": "Barcha urinishlar qayd etiladi"},
        ]
    }

@router.post("/scan/batch")
async def batch_scan(data: ScanBatchRequest, request: Request):
    require_auth(request)
    results = []
    for item in data.items[:20]:
        item = sanitize_input(item)
        if data.scan_type == "url":
            r = analyze_url(item)
        else:
            r = analyze_email(item)
        results.append({"item": item[:60], "score": r["score"], "risk": r["risk_level"]})
    return {"results": results, "total": len(results)}

@router.get("/employees")
async def get_employees(token: str = Header(None), request: Request = None):
    ip = get_client_ip(request)
    user = validate_token(token, ip)
    if not user:
        raise HTTPException(status_code=401, detail="Token noto'g'ri")
    data = load_data()
    return data.get("employees", [])

@router.post("/employees")
async def add_employee(emp: dict, token: str = Header(None), request: Request = None):
    ip = get_client_ip(request)
    user = validate_token(token, ip)
    if not user:
        raise HTTPException(status_code=401, detail="Token noto'g'ri")
    data = load_data()
    if "employees" not in data:
        data["employees"] = []
    emp["id"] = str(len(data["employees"]) + 1)
    data["employees"].append(emp)
    save_data(data)
    return {"success": True, "employee": emp}


@router.post("/simulation/send")
async def send_simulation(body: dict, token: str = Header(None), request: Request = None):
    ip = get_client_ip(request)
    user = validate_token(token, ip)
    if not user:
        raise HTTPException(status_code=401, detail="Token noto'g'ri")
    data = load_data()
    if "simulations" not in data:
        data["simulations"] = []
    data["simulations"].append(body)
    save_data(data)
    return {"success": True}

