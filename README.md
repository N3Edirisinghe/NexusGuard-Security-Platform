<div align="center">
  <h1>🛡️ NexusGuard Security Platform</h1>
  <p><strong>Advanced Web Application Firewall (WAF) & Real-time Security Operations Center (SOC)</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python Version" />
    <img src="https://img.shields.io/badge/FastAPI-0.100+-009688.svg?logo=fastapi" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Redis-Rate%20Limiting-DC382D.svg?logo=redis" alt="Redis" />
    <img src="https://img.shields.io/badge/Security-WAF-critical.svg" alt="Security" />
    <img src="https://img.shields.io/badge/License-MIT-success.svg" alt="License" />
  </p>
</div>

## 📖 Overview

**NexusGuard** is an enterprise-grade security middleware and real-time visualization platform built for Python web applications. It acts as a robust defense layer, intercepting malicious payloads, enforcing rate limits, and providing a highly dynamic **Security Operations Center (SOC)** dashboard for live threat monitoring.

This project demonstrates advanced cybersecurity principles, secure API development, and dynamic frontend engineering.

---

## ✨ Key Features

- **🔥 Next-Gen WAF Engine:** Deep packet inspection to block SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal, and Command Injection.
- **📊 Real-time SOC Dashboard:** A beautifully designed, dark-themed command center featuring live attack visualizations, dynamic threat counters, and interactive logs.
- **🛡️ Distributed Rate Limiting:** Redis-backed request throttling to mitigate DDoS attacks and brute-force attempts.
- **🛑 Threat Simulation Engine:** Built-in tools to simulate attacks and verify the WAF's response mechanisms in real-time.
- **🔒 Secure API Architecture:** Hardened FastAPI backend with custom middleware, comprehensive logging, and custom exception handling.

---

## 🛠️ Technology Stack

| Category | Technologies |
| --- | --- |
| **Backend API** | Python, FastAPI, Uvicorn, Pydantic |
| **Security Layer** | Custom WAF Middleware, Cryptography, Regex Threat Signatures |
| **Caching & State** | Redis (for distributed rate limiting) |
| **Frontend SOC** | HTML5, Vanilla CSS (Glassmorphism), Vanilla JavaScript, Chart.js (optional) |
| **Testing & CI/CD** | Pytest, GitHub Actions |

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Redis Server (must be running locally or remotely)

### 1. Clone the Repository
```bash
git clone https://github.com/N3Edirisinghe/NexusGuard-Security-Platform.git
cd NexusGuard-Security-Platform
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start the Platform
```bash
uvicorn app.main:app --reload
```

*The SOC Dashboard will be accessible at: `http://localhost:8000/dashboard`*

---

## 🖥️ Usage

1. **Access the Landing Page:** Navigate to `http://localhost:8000/` to view the public-facing enterprise landing page.
2. **Launch the SOC Console:** Click "Launch Console" to enter the live monitoring dashboard.
3. **Simulate Attacks:** Use the built-in "Simulate Attack" tool on the dashboard to fire mock SQLi or XSS payloads and watch the WAF intercept them in real-time.
4. **View Block Pages:** Attempting to access unauthorized or malicious endpoints will trigger the custom NexusGuard block screen.

---

## 📜 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---
<div align="center">
  <i>Developed with ❤️ by <a href="https://github.com/N3Edirisinghe">N3Edirisinghe</a></i>
</div>
