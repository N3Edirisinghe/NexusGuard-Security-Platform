from fastapi import FastAPI, Depends, Body
from security.waf_middleware import WAFMiddleware
from security.rate_limiter import RateLimitMiddleware
from security.headers import SecurityHeadersMiddleware
from security.auth import AuthHandler, get_current_user
from .schemas import LoginRequest, SecureMessage

from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
from fastapi.openapi.docs import get_swagger_ui_html
from sqlalchemy.orm import Session
from .database import get_db, DBUser
import os

app = FastAPI(
    title="Secure API with NexusGuard WAF",
    description="An enterprise-hardened API with embedded WAF and Redis-backed rate limiting.",
    version="1.0.0",
    docs_url=None, 
    redoc_url=None
)

# Custom Swagger UI with Dark Mode
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Professional SOC",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="/swagger-dark.css", # Point to our custom CSS route
    )

# Custom CSS for Dark Mode
@app.get("/swagger-dark.css", include_in_schema=False)
async def swagger_dark_css():
    dark_css = """
        @import url('https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css');
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Fira+Code:wght@400;500&display=swap');

        :root {
            --bg-dark: #030712;
            --card-bg: rgba(17, 24, 39, 0.6);
            --card-border: rgba(56, 189, 248, 0.15);
            --accent-blue: #0ea5e9;
            --accent-cyan: #22d3ee;
            --accent-purple: #8b5cf6;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }

        body { 
            background-color: var(--bg-dark) !important; 
            margin: 0; 
            font-family: 'Outfit', sans-serif !important;
            background-image: 
                linear-gradient(rgba(14, 165, 233, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(14, 165, 233, 0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            background-position: center center;
        }

        .swagger-ui { font-family: 'Outfit', sans-serif !important; color: var(--text-primary); }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info .title { color: var(--text-primary); font-family: 'Outfit', sans-serif; font-weight: 800; }
        .swagger-ui .info p { color: var(--text-secondary); }

        /* Glassmorphism containers */
        .swagger-ui .scheme-container { background: transparent; box-shadow: none; border-bottom: 1px solid var(--card-border); padding: 20px 0; }

        .swagger-ui .opblock { 
            border-radius: 12px; background: var(--card-bg); 
            backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--card-border) !important; margin-bottom: 15px; 
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1); transition: transform 0.3s, border-color 0.3s;
        }
        .swagger-ui .opblock:hover { transform: translateY(-2px); border-color: rgba(34, 211, 238, 0.4) !important; }
        .swagger-ui .opblock .opblock-summary { border-bottom: 1px solid var(--card-border); padding: 10px; }
        .swagger-ui .opblock-tag { border-bottom: 1px solid var(--card-border); color: var(--accent-cyan); font-size: 1.5rem; margin-top: 20px; font-weight: 600; }

        .swagger-ui section.models { border: 1px solid var(--card-border); background: var(--card-bg); backdrop-filter: blur(12px); border-radius: 12px; margin-top: 30px; }
        .swagger-ui section.models .model-container { background: rgba(0,0,0,0.4); border-radius: 8px; margin: 10px; padding: 10px; border: 1px solid var(--card-border); }

        /* Inputs & Typography */
        .swagger-ui input, .swagger-ui select, .swagger-ui textarea { 
            background: rgba(0,0,0,0.4) !important; color: var(--accent-cyan) !important; 
            border: 1px solid var(--card-border) !important; border-radius: 6px; padding: 8px; font-family: 'Fira Code', monospace !important;
        }
        .swagger-ui input:focus, .swagger-ui textarea:focus { border-color: var(--accent-cyan) !important; box-shadow: 0 0 15px rgba(34, 211, 238, 0.1) !important; }

        .swagger-ui .btn { 
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple)) !important; 
            color: white !important; border: none !important; border-radius: 6px; 
            box-shadow: 0 4px 15px rgba(14, 165, 233, 0.3); font-family: 'Outfit', sans-serif; font-weight: 600;
        }
        .swagger-ui .btn:hover { box-shadow: 0 6px 25px rgba(139, 92, 246, 0.5); transform: translateY(-2px); }

        .swagger-ui .btn.authorize { background: transparent !important; color: var(--accent-cyan) !important; border: 1px solid var(--accent-cyan) !important; box-shadow: none; }
        .swagger-ui .btn.authorize:hover { background: rgba(34, 211, 238, 0.1) !important; box-shadow: 0 0 20px rgba(34, 211, 238, 0.3) !important; }
        .swagger-ui .btn.authorize svg { fill: var(--accent-cyan); }

        .swagger-ui .opblock-description-wrapper p, .swagger-ui .opblock-external-docs-wrapper p, .swagger-ui .opblock-title_wrapper p { color: var(--text-secondary); }
        .swagger-ui .parameter__name, .swagger-ui .parameter__type { color: var(--text-primary); font-family: 'Fira Code', monospace; }
        .swagger-ui table thead tr th { color: var(--text-secondary); border-bottom: 1px solid var(--card-border); font-family: 'Outfit', sans-serif; }
        .swagger-ui table tbody tr td { border-bottom: 1px solid var(--card-border); }
        .swagger-ui .response-col_status { color: var(--text-primary); font-family: 'Fira Code', monospace; }
        .swagger-ui .response-col_description { color: var(--text-secondary); }
        .swagger-ui .markdown p, .swagger-ui .markdown pre { color: var(--text-secondary); }
    """
    return Response(content=dark_css, media_type="text/css")

# Mount frontend for styles
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# Add Middlewares (Order matters: outermost first)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(WAFMiddleware)

@app.get("/", response_class=HTMLResponse)
async def get_landing():
    with open("frontend/landing.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    with open("frontend/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/token")
async def login(request: LoginRequest):
    if request.username == "admin" and request.password == "securepassword123":
        token = AuthHandler.create_access_token(data={"sub": request.username})
        return {"access_token": token, "token_type": "bearer"}
    return {"error": "Invalid credentials"}

@app.post("/submit-data")
async def submit_data(message: SecureMessage):
    return {"status": "Success", "data_received": message.content, "user": "demo-user"}

@app.get("/search")
async def search(q: str):
    return {"query": q, "results": ["Item 1", "Item 2"]}

@app.get("/db-search")
async def db_search(username: str, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == username).first()
    if user:
        return {"username": user.username, "email": user.email}
    return {"message": "User not found"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
