from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="Vulnerable API (No WAF)")

# NO SECURITY MIDDLEWARES HERE

@app.get("/")
async def root():
    return {"message": "Warning: This API is VULNERABLE. No WAF active."}

@app.get("/search")
async def search(q: str):
    # Simulated SQL Injection vulnerability (no parameterization)
    # In a real app, this would be a raw query: f"SELECT * FROM users WHERE name = '{q}'"
    return {
        "query": q,
        "vulnerability": "SQL Injection",
        "simulated_query": f"SELECT * FROM items WHERE name LIKE '%{q}%'"
    }

@app.post("/submit-data")
async def submit_data(request: Request):
    # Simulated XSS vulnerability
    data = await request.json()
    content = data.get("content", "")
    return HTMLResponse(content=f"<div>Received: {content}</div>")

@app.get("/view-file")
async def view_file(path: str):
    # Simulated Path Traversal
    return {
        "file_requested": path,
        "vulnerability": "Path Traversal",
        "simulated_path": f"/var/www/app/data/{path}"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
