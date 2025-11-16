from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from server.api.routing import router, limiter
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="Secure Your App Health API", description="AI-powered security assessment tool for CISOs")

# Serve static files (web UI)
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve logo.png from root
@app.get("/logo.png")
async def get_logo():
    logo_path = "logo.png"
    if os.path.exists(logo_path):
        return FileResponse(logo_path, media_type="image/png")
    # Fallback to client/public if exists
    client_logo_path = "client/public/logo.png"
    if os.path.exists(client_logo_path):
        return FileResponse(client_logo_path, media_type="image/png")
    return {"error": "Logo not found"}, 404

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Include router with /api prefix
app.include_router(router, prefix="/api")

@app.get("/")
async def root():
    return {"message": "Secure Your App Health API is running", "docs": "/docs", "web_ui": "/static/index.html" if os.path.exists("static/index.html") else None}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("🚀 Secure Your App Health API Server Starting...")
    print("="*60)
    print(f"📡 Server will be available at: http://localhost:8000")
    print(f"📚 API Documentation: http://localhost:8000/docs")
    print(f"🌐 Web UI: http://localhost:8000/static/index.html")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)

