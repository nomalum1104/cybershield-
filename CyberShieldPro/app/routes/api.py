from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import random
from app.services.risk_model import analyze_url, analyze_email, get_training_scenarios

router = APIRouter()

# In-memory stats
scan_stats = {
    "total_scans": 1247,
    "threats_found": 389,
    "emails_scanned": 634,
    "urls_scanned": 613,
    "daily_scans": [45, 67, 89, 120, 95, 145, 178],
    "recent_scans": []
}

class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    text: str

class TrainingSubmit(BaseModel):
    scenario_id: int
    answer: int
    time_taken: int

class UserProgress(BaseModel):
    completed: list
    score: int
    level: str

@router.post("/scan/url")
async def scan_url(request: URLRequest):
    result = analyze_url(request.url)
    scan_stats["total_scans"] += 1
    scan_stats["urls_scanned"] += 1
    if result["score"] > 50:
        scan_stats["threats_found"] += 1

    scan_stats["recent_scans"].insert(0, {
        "type": "URL",
        "value": request.url[:40] + "..." if len(request.url) > 40 else request.url,
        "score": result["score"],
        "risk_level": result["risk_level"],
        "time": datetime.now().strftime("%H:%M:%S")
    })
    scan_stats["recent_scans"] = scan_stats["recent_scans"][:10]

    return result

@router.post("/scan/email")
async def scan_email(request: EmailRequest):
    result = analyze_email(request.text)
    scan_stats["total_scans"] += 1
    scan_stats["emails_scanned"] += 1
    if result["score"] > 50:
        scan_stats["threats_found"] += 1

    scan_stats["recent_scans"].insert(0, {
        "type": "Email",
        "value": request.text[:40] + "...",
        "score": result["score"],
        "risk_level": result["risk_level"],
        "time": datetime.now().strftime("%H:%M:%S")
    })
    scan_stats["recent_scans"] = scan_stats["recent_scans"][:10]

    return result

@router.get("/training/scenarios")
async def get_scenarios():
    return {"scenarios": get_training_scenarios()}

@router.post("/training/submit")
async def submit_answer(data: TrainingSubmit):
    scenarios = get_training_scenarios()
    scenario = next((s for s in scenarios if s["id"] == data.scenario_id), None)
    if not scenario:
        return {"error": "Stsenariy topilmadi"}

    correct = data.answer == scenario["correct"]
    return {
        "correct": correct,
        "explanation": scenario["explanation"],
        "correct_answer": scenario["correct"],
        "points": 20 if correct else 0
    }

@router.get("/stats/dashboard")
async def get_dashboard():
    current_hour = datetime.now().hour
    threat_rate = round((scan_stats["threats_found"] / max(scan_stats["total_scans"], 1)) * 100, 1)

    return {
        "total_scans": scan_stats["total_scans"] + random.randint(0, 5),
        "threats_found": scan_stats["threats_found"],
        "emails_scanned": scan_stats["emails_scanned"],
        "urls_scanned": scan_stats["urls_scanned"],
        "threat_rate": threat_rate,
        "daily_scans": scan_stats["daily_scans"],
        "recent_scans": scan_stats["recent_scans"],
        "status": "Faol himoya",
        "last_updated": datetime.now().isoformat()
    }

@router.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "timestamp": datetime.now().isoformat()}
