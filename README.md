# Cipher — Private Messenger

Real-time encrypted messenger. Built with Node.js, WebSockets, SQLite.

## Run locally

```bash
npm install
npm start
```

Open http://localhost:3000

## Deploy to Railway (free)

1. Go to https://railway.app → sign up
2. Click "New Project" → "Deploy from GitHub"
3. Push this folder to a GitHub repo, connect it
4. Railway auto-detects Node.js and deploys
5. Go to Settings → Variables → add: `JWT_SECRET=some-random-long-string`
6. Your app will be live at a `.up.railway.app` URL

## Environment Variables

| Variable | Description | Required |
|---|---|---|
| `JWT_SECRET` | Secret key for tokens | Yes in production |
| `PORT` | Server port | Auto-set by Railway |

## Later: Move to Hetzner (Germany)

When ready for production:
1. Create Hetzner account at https://hetzner.com
2. Create a VPS (CX21, Frankfurt or Nuremberg) — ~€4/month
3. Install Node.js, copy files, run with PM2
4. Add Nginx reverse proxy + SSL (Let's Encrypt, free)
5. Move SQLite → PostgreSQL for better scaling

## Stack

- **Backend**: Node.js + Express + WebSockets (ws)
- **Database**: SQLite (better-sqlite3) — zero config
- **Auth**: JWT + bcrypt
- **Frontend**: Vanilla JS SPA, no framework needed
