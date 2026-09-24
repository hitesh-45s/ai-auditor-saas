<div align="center">
# 🛡️ AuditAI — Enterprise AI Web Auditor
### Autonomous AI-Powered Website Intelligence Platform
[![Built with Next.js](https://img.shields.io/badge/Frontend-Next.js%2015-black?logo=next.js)](https://nextjs.org/)
[![Powered by FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![AI Engine](https://img.shields.io/badge/AI-Google%20Gemini-4285F4?logo=google)](https://ai.google.dev/)
[![Database](https://img.shields.io/badge/Database-Supabase-3FCF8E?logo=supabase)](https://supabase.com/)
[![Queue](https://img.shields.io/badge/Queue-Upstash%20Redis-DC382D?logo=redis)](https://upstash.com/)
---
**AuditAI** is a distributed, full-stack SaaS platform that autonomously crawls, analyzes, and audits any website using AI.
It identifies vulnerabilities across **SEO**, **Accessibility**, **Performance**, **Code Quality**, and **Hydration** — then generates framework-aware remediation code in the website's native language.
</div>
---
## 🚀 Key Features
| Feature | Description |
|---|---|
| 🕷️ **Async Deep Crawler** | Concurrent Python spider using asyncio + httpx that crawls up to 40 pages simultaneously with SSRF protection |
| 🧠 **Smart Extraction Engine** | Surgically extracts only audit-critical HTML elements (SEO tags, links, images, forms, headings) to maximize AI accuracy while minimizing token usage |
| 🤖 **Gemini AI Auditor** | Feeds structured website data to Google Gemini with strict scoring rubric and enterprise-grade exponential backoff (5 retries) |
| 🔐 **JWT Authentication** | Secure Supabase server-side token verification on every API request — no spoofable user IDs |
| 🚦 **Rate Limiting** | IP-based rate limiting (5 requests/minute) via slowapi to protect API credits |
| 📸 **Visual Screenshots** | Playwright captures homepage screenshots, uploads to Supabase Storage, and displays them on the dashboard |
| 🔧 **Framework-Aware Fixes** | AI detects the website's tech stack (React, WordPress/PHP, Vue, raw HTML) and generates remediation code in the correct language |
| 📊 **Strict Scoring Rubric** | Mathematical scoring: starts at 100, deducts 15/5/1 points per High/Medium/Low severity defect |
---
## 🏗️ System Architecture
┌─────────────────┐ ┌──────────────────┐ ┌─────────────────────┐ │ │ │ │ │ │ │ Next.js 15 │────▶│ FastAPI + JWT │────▶│ Upstash Redis │ │ React Frontend│◀────│ Rate Limited │ │ Task Queue │ │ │ │ │ │ │ └─────────────────┘ └──────────────────┘ └──────────┬──────────┘ │ ▼ ┌─────────────────┐ ┌──────────────────┐ ┌─────────────────────┐ │ │ │ │ │ │ │ Supabase │◀────│ Python Worker │◀────│ Google Gemini │ │ PostgreSQL + │ │ Async Crawler │────▶│ AI Engine │ │ Storage │ │ + Playwright │ │ │ │ │ │ │ │ │ └─────────────────┘ └──────────────────┘ └─────────────────────┘



---
## 🛠️ Tech Stack
### Frontend
- **Next.js 15** with App Router
- **React 19** with TypeScript
- **Tailwind CSS** for the dark, hacker-themed UI
- **Lucide React** for icons
- **Supabase Auth** for authentication
### Backend
- **FastAPI** (Python) — API Gateway
- **SlowAPI** — Rate limiting middleware
- **Supabase Python SDK** — Server-side JWT verification and database operations
### Worker (Background Processor)
- **AsyncIO + httpx** — Concurrent web crawling
- **BeautifulSoup4** — Smart HTML extraction
- **Playwright** — Headless browser for screenshots
- **Google Gemini AI** — Vulnerability analysis and code generation
### Infrastructure
- **Supabase** — PostgreSQL database + Auth + Storage
- **Upstash Redis** — Serverless task queue
- **Google AI Studio** — Gemini API
---
## ⚡ Quick Start
### Prerequisites
- Python 3.10+
- Node.js 18+
- A [Supabase](https://supabase.com) project
- An [Upstash Redis](https://upstash.com) database
- A [Google AI Studio](https://aistudio.google.com) API key
### 1. Clone the Repository
```bash
git clone https://github.com/hitesh-45s/ai-auditor-saas.git
cd ai-auditor-saas
2. Set Up Environment Variables
Create a .env file in the root directory:

env


# Supabase
SUPABASE_URL=your_supabase_project_url
SUPABASE_SERVICE_KEY=your_service_role_key
# Upstash Redis
UPSTASH_REDIS_REST_URL=your_upstash_redis_url
UPSTASH_REDIS_REST_TOKEN=your_upstash_redis_token
# Google Gemini AI
GEMINI_API_KEY=your_gemini_api_key
Create a .env.local file in the frontend/ directory:

env


NEXT_PUBLIC_SUPABASE_URL=your_supabase_project_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
NEXT_PUBLIC_API_URL=http://localhost:8000
3. Set Up the Database
Run the SQL schema from infrastructure/schema.sql in your Supabase SQL Editor.

Create a public Storage Bucket named screenshots in Supabase Dashboard → Storage.

4. Install and Run the Backend
bash


cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
uvicorn main:app --reload --port 8000
5. Start the Worker (New Terminal)
bash


cd backend
venv\Scripts\activate
python worker.py
6. Install and Run the Frontend (New Terminal)
bash


cd frontend
npm install
npm run dev
7. Open the App
Navigate to http://localhost:3000, create an account, and start auditing!

🔍 How It Works
User submits a URL through the React dashboard
FastAPI validates the JWT token, applies rate limiting, and queues the job in Redis
Python Worker picks up the job from Redis and begins the audit:
📸 Takes a homepage screenshot via Playwright and uploads it to Supabase Storage
🕷️ Launches an async spider that crawls up to 40 pages concurrently
🧠 Smart Extraction Engine pulls only audit-critical HTML elements
🤖 Feeds structured data to Gemini AI with strict scoring rubric
AI returns a structured JSON report with scores, vulnerabilities, and framework-aware remediation code
Results are saved to Supabase and displayed on the React dashboard in real-time
📊 Scoring Rubric
Severity	Points Deducted	Example
🔴 High	-15 points	Missing keyboard navigation, broken forms
🟡 Medium	-5 points	React hydration mismatches, missing alt text
🔵 Low	-1 point	Missing SEO meta tags, suboptimal heading hierarchy
Baseline score: 100 · Minimum score: 10

🔒 Security Features
JWT Authentication — Every API request is verified server-side via Supabase Auth
SSRF Protection — Crawler blocks requests to private/internal IP ranges (127.x, 10.x, 169.254.x, 192.168.x)
Rate Limiting — 5 scans per minute per IP address
No Client-Side Secrets — All sensitive operations happen server-side
📁 Project Structure


ai-auditor-saas/
├── backend/
│   ├── main.py               # FastAPI gateway with JWT auth and rate limiting
│   ├── worker.py              # Async crawler + Smart Extraction + Gemini AI
│   ├── requirements.txt       # Python dependencies
│   └── .gitignore
├── frontend/
│   ├── src/
│   │   └── app/
│   │       ├── page.tsx       # Main React application
│   │       ├── layout.tsx     # Root layout with metadata
│   │       └── globals.css    # Tailwind CSS global styles
│   ├── public/
│   ├── package.json           # Node.js dependencies
│   ├── next.config.ts         # Next.js configuration
│   └── .gitignore
├── infrastructure/
│   └── schema.sql             # Supabase PostgreSQL database schema
├── .env                       # Secret keys (not committed)
├── .gitignore                 # Root-level git ignore rules
└── README.md                  # This file
🤝 Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

Built with 🧠 AI + ☕ Coffee