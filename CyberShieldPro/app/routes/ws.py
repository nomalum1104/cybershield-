from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import random
from datetime import datetime

router = APIRouter()

connected_clients = []

@router.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await asyncio.sleep(5)
            threat = {
                "type": "live_threat",
                "data": {
                    "threat_type": random.choice(["Phishing URL", "Suspicious Email", "Malicious Domain"]),
                    "risk": random.choice(["LOW", "MEDIUM", "HIGH"]),
                    "location": random.choice(["Toshkent", "Samarqand", "Buxoro", "Namangan"]),
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "blocked": random.choice([True, False])
                }
            }
            try:
                await websocket.send_text(json.dumps(threat))
            except Exception:
                break
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)