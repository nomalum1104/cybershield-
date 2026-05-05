from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.routes import api, ws, admin
from Security import check_rate_limit, sanitize_input
import uvicorn

app = FastAPI(title="CyberShieldPro", version="2.0.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()
    # Block suspicious paths
    path = request.url.path.lower()
    bad_paths = ["/.env", "/wp-admin", "/phpmyadmin", "/.git", "/etc/passwd", "/shell"]
    for bp in bad_paths:
        if path.startswith(bp):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
    response = await call_next(request)
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

app.include_router(api.router, prefix="/api")
app.include_router(admin.router)
app.include_router(ws.router)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse("app/static/index.html")

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)