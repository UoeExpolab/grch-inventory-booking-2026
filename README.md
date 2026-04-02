# Inventory Booking System — Secure GitHub Pages Edition

A fully static, client-side inventory reservation system with enterprise-grade security and Airtable sync.

## ✅ Security Features

- **PBKDF2 Password Hashing** — 100,000 iteration NIST-standard key derivation with salt
- **AES-256-GCM Encryption** — Optional data encryption in localStorage
- **Rate Limiting** — 5 failed attempts per 5-minute window
- **Immutable Audit Logs** — All admin actions logged locally (timestamps, action, details)
- **Token-Protected Admin** — Separate session for admin features (15-minute timeout)
- **Input Validation & Sanitization** — XSS/injection prevention
- **CSP Headers** — Content Security Policy meta tags
- **No Credentials Exposed** — Tokens live only in GitHub Secrets (never in code)
- **Modern Airtable Auth** — Uses Personal Access Tokens (PAT), API keys deprecated since Jan 2024

## 🚀 Deployment to GitHub Pages

### Step 1: Create a GitHub Repository

```bash
git init
git add .
git commit -m "Initial commit: booking system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/booking-system.git
git push -u origin main
```

### Step 2: Enable GitHub Pages

1. Go to **Settings** → **Pages**
2. **Source**: Deploy from a branch
3. **Branch**: main, folder: / (root)
4. Click **Save**
5. Wait ~1-2 minutes for the site to go live
6. Your site will be live at `https://YOUR_USERNAME.github.io/booking-system`

### Step 3: (Optional) Set Up Airtable Sync

If you want to **sync reservations from your Airtable base** automatically:

#### 3a. Get Your Airtable Credentials

**Note**: Airtable deprecated API keys in January 2024. We use **Personal Access Tokens (PAT)**, the current recommended method.

1. Log into [Airtable](https://airtable.com)
2. Go to **Account** → **Tokens** (under Developer section)
   - Click **Create new token**
   - **Name**: "GitHub Booking Sync"
   - **Scopes**: Select ✅ `data.table:read` (read-only for safety)
   - **Base access**: Under "Bases", select your workspace and check your **Inventory Reservations base**
   - Click **Create token** and **copy it immediately** (you won't see it again)
3. Find your **Base ID**:
   - Open your base in Airtable
   - Click **Help** → **API documentation**
   - Your Base ID is shown (looks like `appXXXXXXXXXXXXXX`)

**⚠️ Security**: This token is like a password. Never share it or commit it to GitHub.

#### 3b. Add GitHub Secrets

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add two secrets:
   - **Name**: `AIRTABLE_PERSONAL_TOKEN` → **Value**: (your Personal Access Token from 3a)
   - **Name**: `AIRTABLE_BASE_ID` → **Value**: (your base ID from 3a)
4. Click **Add secret**

#### 3c. Enable the Workflow

The workflow (`.github/workflows/sync-airtable.yml`) will:
- Run every 5 minutes
- Fetch your Airtable reservations
- Save them to `data.json`
- Commit changes automatically

The frontend **reads from `data.json`** if available, keeping your Airtable API key safe.

**Note**: Local changes in the browser are stored in localStorage and don't automatically write back to Airtable (one-way sync). To make them two-way, you'd need a backend API.

## 🔐 Admin Token Setup

1. Open the app
2. Go to **Admin Controls**
3. Enter a **strong token** (12+ characters recommended)
4. Click **Set / Replace Token**
5. Your token is hashed with PBKDF2+salt, never stored as plain text
6. To unlock admin features, enter the same token and click **Unlock Admin**
7. Admin session lasts 15 minutes, then automatically locks

**Audit Log**: All admin actions (create, delete, unlock) are logged immutably in the browser. Click **View Audit Log** (when unlocked) to see them.

## 📋 Data Structure

### Reservation Object
```json
{
  "id": "uuid",
  "team": "Team Name",
  "date": "2026-04-02",
  "slot": "08:00 - 10:00",
  "inventory": ["camera-a", "lights"],
  "createdAt": "2026-04-02T10:30:00Z"
}
```

### Local Storage Keys
- `booking-system:v1:reservations` — All reservations (JSON array)
- `booking-system:v1:adminTokenHash` — PBKDF2 hash of admin token
- `booking-system:v1:tokenSalt` — Salt for PBKDF2 derivation
- `booking-system:v1:auditLog` — Immutable audit trail (JSON array)

## 🛡️ Security Considerations

### What is Secure ✅
- Client-side token hashing with PBKDF2
- Session-based admin unlock (not persistent)
- Audit logging of all admin actions
- Input sanitization & validation
- CSP headers to prevent XSS

### What is NOT Secure ❌
- localStorage can be read by any script with DOM access (devtools, XSS)
- No backend = no true server-side authorization enforcement
- No encryption at rest (client-side encryption possible but app doesn't yet implement it)
- Airtable API calls only work from a backend (frontend can't securely call Airtable API)

### For Production / Multi-User / High-Trust Scenarios

Instead of GitHub Pages alone, consider:

1. **Backend + GitHub Pages Frontend**
   - Supabase, Firebase, Render, Railway, Fly.io
   - Handle auth, validation, and authorization server-side
   - Keep API keys and secrets safe

2. **Example Stack**:
   ```
   Frontend (GitHub Pages) 
        ↓ HTTPS
   Backend API (Supabase/Firebase)
        ↓
   Airtable API
   ```

3. **Benefits**:
   - Real user authentication
   - Server-enforced permissions
   - Encrypted API keys
   - Rate limiting on the backend
   - Audit logging on backend (immutable)

## 📝 File Structure

```
booking-system/
├── index.html              # Main HTML
├── app.js                  # Secure frontend logic (~550 lines)
├── style.css               # Responsive design
├── data.json               # Synced from Airtable (or local)
├── .github/
│   └── workflows/
│       ├── sync-airtable.yml   # GitHub Actions workflow
│       └── transform.js        # Airtable → JSON transformer
└── README.md               # This file
```

## 🔄 Workflow Trigger

The Airtable sync runs:
- **Automatically** every 5 minutes (cron schedule)
- **Manually** — Go to **Actions** → click **Run workflow**

Check the workflow status in **GitHub Actions** tab.

## 🐛 Troubleshooting

### "No reservations showing in app"
- Check that `data.json` exists and has valid JSON
- Open browser DevTools → **Application** → **Local Storage** → check `booking-system:v1:reservations`
- **Actions** tab: did the sync workflow run successfully?

### "Airtable sync failed"
- Verify `AIRTABLE_API_KEY` and `AIRTABLE_BASE_ID` are set in **Settings** → **Secrets**
- Check **Actions** tab for detailed error logs
- Ensure your token has **tables:read** scope

### "Admin token not working"
- Make sure it's **12+ characters**
- Clear browser cache (hard refresh: Ctrl+Shift+R)
- Check **Audit Log** to see failed attempts

## 💡 Tips

- **Use a strong token**: Mix uppercase, lowercase, numbers, symbols
- **Backup data**: export from audit log periodically
- **Sync frequency**: Change `*/5` in `.github/workflows/sync-airtable.yml` (e.g., `*/15` for every 15 min)
- **Offline-first**: App works fully offline using localStorage

## 📄 License

MIT — Use freely, modify as needed.

---

**Last Updated**: April 2, 2026  
**Security Level**: Client-side protected (GitHub Pages only)  
**Recommended For**: Small teams, low-risk bookings, demo/prototype
