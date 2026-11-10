# 🚀 Production Deployment Guide: Automated VAPT Framework

This guide walks you through deploying both the **FastAPI Backend** and the **React Frontend** to the cloud for free with public HTTPS URLs.

---

## Architecture Overview

```
┌─────────────────────────────────┐       REST API / CORS       ┌────────────────────────────────┐
│      Vercel / Netlify           │ ──────────────────────────▶ │      Render / Railway          │
│   (React 19 + Vite Frontend)    │                             │    (FastAPI + Python Backend)  │
│  https://your-vapt.vercel.app   │                             │  https://vapt-api.onrender.com │
└─────────────────────────────────┘                             └────────────────────────────────┘
```

---

## Part 1: Push Your Project to GitHub

If you haven't pushed your code to GitHub yet:

1. Open PowerShell in the project root:
   ```powershell
   cd "c:\Users\Mridul\Desktop\VAPT for Web APIs"
   git init
   git add .
   git commit -m "feat: complete VAPT framework with AI assistant & deployment config"
   ```

2. Create a new repository on [GitHub](https://github.com/new) (e.g. `vapt-web-apis`).

3. Link and push:
   ```powershell
   git remote add origin https://github.com/<YOUR-USERNAME>/vapt-web-apis.git
   git branch -M main
   git push -u origin main
   ```

---

## Part 2: Deploy Backend to Render (Free)

[Render](https://render.com) is the easiest platform for FastAPI + SQLite.

1. Go to [dashboard.render.com](https://dashboard.render.com/) and click **New +** ➔ **Web Service**.
2. Connect your GitHub repository.
3. Configure the service:
   - **Name:** `vapt-backend-api`
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type:** `Free`
4. Under **Environment Variables**, click **Add Environment Variable**:
   - `GEMINI_API_KEY` = `your-gemini-api-key-here`
   - `DEBUG` = `false`
5. Click **Create Web Service**.
6. Once deployed, copy your backend URL (e.g. `https://vapt-backend-api.onrender.com`).
   - Check it in your browser: `https://vapt-backend-api.onrender.com/health` ➔ `{"status": "healthy"}`

---

## Part 3: Deploy Frontend to Vercel (Free)

[Vercel](https://vercel.com) provides instant global CDN hosting for Vite/React.

1. Go to [vercel.com](https://vercel.com/) and sign in with GitHub.
2. Click **Add New...** ➔ **Project**.
3. Import your `vapt-web-apis` repository.
4. Configure the project:
   - **Framework Preset:** `Vite`
   - **Root Directory:** Click **Edit** and select `frontend`.
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
5. Under **Environment Variables**:
   - **Name:** `VITE_API_URL`
   - **Value:** `https://vapt-backend-api.onrender.com/api/v1` *(paste your Render backend URL with `/api/v1`)*
6. Click **Deploy**.
7. In ~60 seconds, your frontend will be live at `https://your-app.vercel.app`!

---

## Part 4: Alternate 1-Click Frontend Deployment (Netlify)

If you prefer [Netlify](https://www.netlify.com/):
1. **Import from Git** ➔ select your repo.
2. **Base directory:** `frontend`
3. **Build command:** `npm run build`
4. **Publish directory:** `frontend/dist`
5. **Environment variable:** `VITE_API_URL` = `https://vapt-backend-api.onrender.com/api/v1`
6. Click **Deploy Site**.

---

## Part 5: Production Verification Checklist

Once deployed, test your live cloud instance:
- [ ] Visit `https://your-frontend.vercel.app`
- [ ] Upload `samples/vampi-vulnerable-api.json`
- [ ] Navigate to `/endpoints` to ensure routes render
- [ ] Navigate to `/ai-chat` and verify the security assistant responds
- [ ] Download an executive report

