import hashlib
import hmac
import time
import secrets
import re
from datetime import datetime
from typing import Dict, Optional
from collections import defaultdict

# ── Token system ──────────────────────────────────────────────────────────────
SECRET_KEY = secrets.token_hex(32)
ADMIN_CREDENTIALS = {
    "admin": hashlib.sha256("CyberShield2024!".encode()).hexdigest()
}

# ── In-memory stores ──────────────────────────────────────────────────────────
active_tokens: Dict[str, dict] = {}
failed_attempts: Dict[str, list] = defaultdict(list)
blocked_ips: Dict[str, float] = {}
audit_log: list = []

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_FAILS = 5
BLOCK_DURATION = 900
TOKEN_TTL = 3600
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30


def _log(event: str, ip: str, detail: str = "", severity: str = "INFO"):
    audit_log.insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "event": event,
        "ip": ip,
        "detail": detail,
        "severity": severity
    })
    if len(audit_log) > 200:
        audit_log.pop()


def is_ip_blocked(ip: str) -> bool:
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]
            failed_attempts.pop(ip, None)
    return False


def record_failed(ip: str):
    now = time.time()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < BLOCK_DURATION]
    failed_attempts[ip].append(now)
    count = len(failed_attempts[ip])
    if count >= MAX_FAILS:
        blocked_ips[ip] = now + BLOCK_DURATION
        _log("IP_BLOCKED", ip, f"{count} marta noto'g'ri urinish", "CRITICAL")
    else:
        _log("FAILED_LOGIN", ip, f"Urinish {count}/{MAX_FAILS}", "WARNING")


def remaining_fails(ip: str) -> int:
    now = time.time()
    recent = [t for t in failed_attempts[ip] if now - t < BLOCK_DURATION]
    return max(0, MAX_FAILS - len(recent))


def create_token(username: str, ip: str) -> str:
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        "user": username,
        "ip": ip,
        "expires": time.time() + TOKEN_TTL,
        "created": datetime.now().isoformat()
    }
    _log("LOGIN_SUCCESS", ip, f"Foydalanuvchi: {username}", "INFO")
    return token


def validate_token(token: str, ip: str) -> Optional[str]:
    if not token or token not in active_tokens:
        return None
    data = active_tokens[token]
    if time.time() > data["expires"]:
        del active_tokens[token]
        return None
    return data["user"]


def revoke_token(token: str, ip: str):
    if token in active_tokens:
        user = active_tokens[token]["user"]
        del active_tokens[token]
        _log("LOGOUT", ip, f"Foydalanuvchi: {user}", "INFO")


def authenticate(username: str, password: str, ip: str) -> dict:
    username = username.strip()[:64]
    password = password[:128]

    if is_ip_blocked(ip):
        unblock_at = datetime.fromtimestamp(blocked_ips[ip]).strftime("%H:%M:%S")
        _log("BLOCKED_ATTEMPT", ip, "Bloklangan IP urinish qildi", "CRITICAL")
        return {"success": False, "error": f"IP bloklangan. {unblock_at} gacha kuting.", "blocked": True}

    if not username or not password:
        return {"success": False, "error": "Login yoki parol bo'sh"}

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if username in ADMIN_CREDENTIALS and hmac.compare_digest(ADMIN_CREDENTIALS[username], pw_hash):
        failed_attempts.pop(ip, None)
        token = create_token(username, ip)
        return {"success": True, "token": token, "user": username}

    record_failed(ip)
    left = remaining_fails(ip)
    msg = f"Login yoki parol noto'g'ri. {left} urinish qoldi." if left > 0 else "Hisob vaqtincha bloklandi!"
    return {"success": False, "error": msg, "blocked": left == 0}


def check_rate_limit(ip: str) -> bool:
    key = f"rate_{ip}"
    now = time.time()
    if key not in failed_attempts:
        failed_attempts[key] = []
    failed_attempts[key] = [t for t in failed_attempts[key] if now - t < RATE_LIMIT_WINDOW]
    if len(failed_attempts[key]) >= RATE_LIMIT_MAX:
        _log("RATE_LIMITED", ip, f"{RATE_LIMIT_MAX}+ so'rov/daqiqa", "WARNING")
        return False
    failed_attempts[key].append(now)
    return True


def sanitize_input(text: str) -> str:
    dangerous = [
        r'<script.*?>.*?</script>', r'javascript:', r'on\w+\s*=',
        r'union\s+select', r'drop\s+table', r'insert\s+into',
        r'--', r';\s*drop', r'exec\s*\(', r'xp_cmdshell'
    ]
    for pattern in dangerous:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)
    return text[:4096]


def get_audit_log(limit: int = 50) -> list:
    return audit_log[:limit]


def get_blocked_ips() -> list:
    now = time.time()
    return [
        {"ip": ip, "until": datetime.fromtimestamp(ts).strftime("%H:%M:%S")}
        for ip, ts in blocked_ips.items() if ts > now
    ]


def get_active_sessions() -> list:
    now = time.time()
    return [
        {
            "user": v["user"], "ip": v["ip"],
            "created": v["created"],
            "expires_in": int(v["expires"] - now)
        }
        for v in active_tokens.values() if v["expires"] > now
    ]