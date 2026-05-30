# 🔐 WebScan X — Web Application Security Testing Tool

> **For educational purposes only. Only scan websites you own or have explicit permission to test.**

A full-stack web application security scanner with a cyberpunk hacker-style interface. Built with React + Vite for the frontend and Python Flask for the backend.

---

## 🖥️ Screenshots

The app features a black + neon green cybersecurity theme with:
- Animated terminal-style scan logs
- Live scan progress bars
- Vulnerability charts and risk scoring
- Detailed finding cards with recommendations

---

## 🛠️ Technologies Used

### Frontend
| Tech | Purpose |
|------|---------|
| React 18 | UI framework |
| Vite | Fast dev server & bundler |
| Tailwind CSS | Utility-first styling |
| Axios | HTTP API requests |
| React Router v6 | Client-side routing |
| React Icons | Icon library |
| Recharts | Vulnerability charts |

### Backend
| Tech | Purpose |
|------|---------|
| Python 3.8+ | Runtime |
| Flask | Web framework |
| Flask-CORS | Cross-origin requests |
| Requests | HTTP scanning |
| BeautifulSoup4 | HTML parsing |
| PyJWT | Authentication tokens |

---

## 📁 Project Structure

```
WebScan-X/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   └── Layout.jsx        # Sidebar + main layout
│   │   ├── context/
│   │   │   └── AuthContext.jsx   # Global auth state
│   │   ├── pages/
│   │   │   ├── LoginPage.jsx     # Login form
│   │   │   ├── SignupPage.jsx    # Registration form
│   │   │   ├── Dashboard.jsx     # Stats overview
│   │   │   ├── ScannerPage.jsx   # URL input form
│   │   │   ├── ScanLivePage.jsx  # Animated terminal scan
│   │   │   ├── ReportPage.jsx    # Full vulnerability report
│   │   │   └── HistoryPage.jsx   # Past scans list
│   │   ├── App.jsx               # Routes setup
│   │   ├── main.jsx              # React entry point
│   │   └── index.css             # Global styles
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── postcss.config.js
│
├── backend/
│   └── app.py                    # Flask API (all-in-one)
│
├── requirements.txt              # Python dependencies
└── README.md
```

---

## 🚀 Installation & Setup

### Prerequisites
- **Node.js** 18+ and npm ([download](https://nodejs.org))
- **Python** 3.8+ ([download](https://python.org))

---

### Step 1: Clone / Extract the project
```bash
cd WebScan-X
```

---

### Step 2: Set up the Backend

```bash
# Navigate to backend folder
cd backend

# Install Python dependencies
pip install -r ../requirements.txt

# Start the Flask server
python app.py
```

✅ Backend will run at: **http://localhost:5000**

You'll see:
```
🔥 WebScan X Backend Starting...
📡 API running at http://localhost:5000
```

---

### Step 3: Set up the Frontend

Open a **new terminal window** and:

```bash
# Navigate to frontend folder
cd frontend

# Install Node dependencies
npm install

# Start the development server
npm run dev
```

✅ Frontend will run at: **http://localhost:3000**

---

## 🔑 Usage

1. Open **http://localhost:3000** in your browser
2. Click **REGISTER NEW OPERATOR** to create an account
3. Log in with your credentials
4. Go to **Scanner** from the sidebar
5. Enter a target URL (e.g. `https://example.com`)
6. Click **SCAN** and watch the live terminal
7. View the full vulnerability report
8. Download the report as a `.txt` file
9. View scan history in the **Scan History** page

---

## 🔍 Scan Modules

| Module | What it checks |
|--------|---------------|
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc. |
| **SSL Certificate** | Validity, expiry date, HTTPS enforcement |
| **XSS Detection** | Form input fields, reflected parameters |
| **SQL Injection** | URL parameters, error messages in responses |
| **Cookie Security** | HttpOnly, Secure, SameSite flags |
| **Port Scan** | Common ports: 80, 443, 22, 3306, 5432, etc. (simulated) |
| **Tech Detection** | React, WordPress, jQuery, Bootstrap, and more |

---

## ⚠️ Important Notes

- **Educational tool**: This is for learning about web security concepts
- **Authorized use only**: Only test websites you own or have permission to test
- **No real exploitation**: The tool performs passive checks and simulations — it does not actually exploit vulnerabilities
- **Port scanning**: Port detection results are simulated for educational purposes
- **Data storage**: Scans are stored in memory — they reset when the server restarts (add a database for persistence)

---

## 🔧 Troubleshooting

**CORS errors**: Make sure the Flask backend is running on port 5000

**Module not found (Python)**: Run `pip install -r requirements.txt` again

**Port already in use**: Change port in `vite.config.js` (frontend) or `app.py` (backend)

**SSL warnings**: The backend uses `verify=False` for scanning — this is intentional for testing

---

## 🧪 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/signup` | Register new user |
| POST | `/api/auth/login` | Login user |
| GET | `/api/auth/me` | Get current user |
| POST | `/api/scan/start` | Initialize a scan |
| GET | `/api/scan/results/:id` | Get scan results |
| GET | `/api/scan/history` | Get user's scan history |
| GET | `/api/dashboard/stats` | Get dashboard statistics |

---

## 📄 License

MIT License — Free for educational and personal use.

---

*Built with ⚡ by WebScan X — Stay ethical, stay secure.*
