# Secure Headers Scanner

A tool to analyze **HTTP security headers** in web applications.  
It consists of two main components:

- **secscan-api** → Node.js (Express) API (`:4000`)
- **secscan-web** → React (Vite) UI (`:5173`)

---

## 📂 Project Structure

secure-headers-scanner/
├─ docker-compose.yml
├─ README.md
├─ secscan-api/ # Node.js (Express) API — :4000
│ ├─ Dockerfile
│ ├─ package.json
│ └─ api.js
└─ secscan-web/ # React (Vite) UI — dev: :5173, prod (nginx): :5173
├─ Dockerfile
├─ nginx.conf
├─ package.json
├─ vite.config.js # /api → :4000 proxy in dev
├─ index.html
└─ src/
├─ main.jsx
└─ App.jsx

yaml
Kodu kopyala

---

## 🚀 Getting Started

### 1️⃣ Run with Docker

```bash
docker compose build --no-cache
docker compose up -d
UI: http://<server-ip>/

Health check: http://<server-ip>/api/healthz → {"ok":true}

2️⃣ Run without Docker
🔹 API
bash
Kodu kopyala
cd secscan-api
npm install
npm start
# http://localhost:4000
🔹 Web (Dev)
bash
Kodu kopyala
cd secscan-web
npm install
npm run dev
# http://localhost:5173
⚙️ Notes
In development, the web UI proxies /api requests to the backend (vite.config.js).

In production, the web UI runs on nginx (:5173).

🛠️ Tech Stack
Backend: Node.js, Express

Frontend: React, Vite

Containerization: Docker, Docker Compose

Web Server (Prod): Nginx

📜 License
This project is licensed under the MIT.

yaml
Kodu kopyala

