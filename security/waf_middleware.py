from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from .waf_engine import WAFEngine
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NexusGuardWAF")

class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.engine = WAFEngine()

    async def dispatch(self, request: Request, call_next):
        # 1. Inspect Query Parameters
        for key, value in request.query_params.items():
            threat = self.engine.check_value(value)
            if threat:
                return self._block_request(threat, f"Query Param: {key}", request)

        # 2. Inspect Headers
        for key, value in request.headers.items():
            if key.lower() in ["user-agent", "cookie", "authorization"]:
                continue
            threat = self.engine.check_value(value)
            if threat:
                return self._block_request(threat, f"Header: {key}", request)

        # 3. Inspect Body (for JSON)
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    body = await request.body()
                    if body:
                        data = json.loads(body)
                        threat = self.engine.inspect_payload(data)
                        if threat:
                            return self._block_request(threat, "JSON Body", request)
                        
                        async def receive():
                            return {"type": "http.request", "body": body}
                        request._receive = receive
                except json.JSONDecodeError:
                    pass

        response = await call_next(request)
        return response

    def _block_request(self, threat: str, location: str, request: Request):
        from starlette.responses import HTMLResponse, JSONResponse
        
        client_ip = request.client.host
        logger.warning(f"SECURITY BLOCK: IP={client_ip} | Threat={threat} | Location={location}")
        
        accept = request.headers.get("accept", "")
        # Always return the graphical HTML page for GET requests (like opening a URL in a new tab)
        if request.method == "GET" or "text/html" in accept:
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>NexusGuard WAF | Access Denied</title>
                <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
                <style>
                    body {{
                        background-color: #030712;
                        color: #f8fafc;
                        font-family: 'Outfit', sans-serif;
                        margin: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        background-image: radial-gradient(circle at center, #1f0a14 0%, #030712 100%);
                    }}
                    .block-container {{
                        background: rgba(17, 24, 39, 0.8);
                        backdrop-filter: blur(12px);
                        border: 1px solid rgba(244, 63, 94, 0.3);
                        border-radius: 16px;
                        padding: 3rem;
                        max-width: 600px;
                        text-align: center;
                        box-shadow: 0 0 40px rgba(244, 63, 94, 0.1);
                    }}
                    .icon-warning {{
                        width: 80px;
                        height: 80px;
                        margin: 0 auto 1.5rem;
                        color: #f43f5e;
                        filter: drop-shadow(0 0 15px rgba(244,63,94,0.5));
                    }}
                    h1 {{ margin: 0 0 1rem; font-size: 2rem; color: #f43f5e; font-weight: 800; text-transform: uppercase; letter-spacing: 2px; }}
                    p {{ color: #94a3b8; line-height: 1.6; margin-bottom: 2rem; }}
                    .threat-details {{
                        background: rgba(0,0,0,0.5);
                        padding: 1.5rem;
                        border-radius: 8px;
                        font-family: 'Fira Code', monospace;
                        font-size: 0.9rem;
                        color: #fb7185;
                        text-align: left;
                        border-left: 4px solid #f43f5e;
                    }}
                    .detail-row {{ margin-bottom: 0.5rem; }}
                    .detail-label {{ color: #64748b; font-size: 0.8rem; text-transform: uppercase; }}
                </style>
            </head>
            <body>
                <div class="block-container">
                    <svg class="icon-warning" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                    <h1>Request Blocked</h1>
                    <p>The NexusGuard Web Application Firewall has intercepted and blocked your request due to suspicious activity matching a known threat signature.</p>
                    <div class="threat-details">
                        <div class="detail-row"><span class="detail-label">Client IP:</span> {client_ip}</div>
                        <div class="detail-row"><span class="detail-label">Violation:</span> {threat}</div>
                        <div class="detail-row"><span class="detail-label">Location:</span> {location}</div>
                        <div class="detail-row"><span class="detail-label">Action:</span> Terminated</div>
                    </div>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(status_code=403, content=html_content)
            
        return JSONResponse(
            status_code=403,
            content={
                "error": "Security Breach Detected",
                "message": threat,
                "location": location,
                "action": "Request Blocked by NexusGuard WAF"
            }
        )
