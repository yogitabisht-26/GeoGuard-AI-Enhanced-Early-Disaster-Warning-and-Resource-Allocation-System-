"""
GeoGuard AI — Backend API
==========================
- MongoDB Atlas database
- Email OTP verification (sirf email pe, screen pe nahi)
- JWT authentication
- 5 Disaster predictions
- NGO system
- SMS alerts

Run: uvicorn main:app --port 8000 --reload
"""

import os, json, math, pickle, secrets, hashlib, smtplib, urllib.request, urllib.parse
from datetime import datetime, timedelta
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import numpy as np
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from pymongo import MongoClient
from bson import ObjectId
import bcrypt

try:
    import jwt as pyjwt
    HAS_JWT = True
except:
    HAS_JWT = False

# ── Load .env ─────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

# ── Config ────────────────────────────────────────
MONGODB_URL       = os.getenv("MONGODB_URL", "")
SECRET_KEY        = os.getenv("SECRET_KEY", "geoguard-secret-2025")
JWT_EXPIRE_HOURS  = int(os.getenv("JWT_EXPIRE_HOURS", "48"))
OTP_EXPIRE_MIN    = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASS", "")
FAST2SMS_KEY      = os.getenv("FAST2SMS_KEY", "")

# ── MongoDB Connection ─────────────────────────────
if not MONGODB_URL:
    raise RuntimeError("MONGODB_URL not set in .env file!")

client = MongoClient(MONGODB_URL)
db     = client["geoguard"]

# ── Collections (single cluster "geoguard", 5 collections) ──
# users      → login/signup/profile
# alerts     → disaster alerts + prediction history  
# locations  → saved locations + GPS data
# resources  → NGO help (ngos + ngo_resources + resource_requests)
# reports    → user reports / OTPs

users_col    = db["users"]           # login, signup, profile
alerts_col   = db["alerts"]          # disaster alerts, prediction history
locations_col= db["locations"]       # saved locations, GPS data
resources_col= db["resources"]       # NGO data + resource requests
reports_col  = db["reports"]         # OTPs + user reports

# Legacy aliases (for backward compatibility)
otps_col     = reports_col           # OTPs go into reports collection
ngos_col     = resources_col         # NGO profiles in resources collection
saved_col    = locations_col         # saved locations in locations collection
history_col  = alerts_col            # prediction history in alerts collection

# Separate sub-collections within resources
ngo_res_col  = db["ngo_items"]       # individual resource items
req_col      = db["help_requests"]   # user help requests

# Indexes for performance
users_col.create_index("email", unique=True)
reports_col.create_index("expires_at", expireAfterSeconds=0)
alerts_col.create_index("user_id")
locations_col.create_index("user_id")
resources_col.create_index("user_id")

print("[GeoGuard] MongoDB connected successfully")

# ── Load ML Models ─────────────────────────────────
MODELS = {}
for name in ["landslide", "flood", "cyclone", "drought", "earthquake"]:
    for path in [f"ml_models/{name}_model.pkl", f"{name}_model.pkl", f"../models/{name}_model.pkl"]:
        if os.path.exists(path):
            with open(path, "rb") as f:
                MODELS[name] = pickle.load(f)
            print(f"[OK] {name} model loaded")
            break
    if name not in MODELS:
        print(f"[INFO] {name}_model.pkl not found — fallback will be used")

# ── FastAPI App ────────────────────────────────────
app = FastAPI(
    title="GeoGuard AI API",
    description="AI Enhanced Early Disaster Warning & Resource Allocation",
    version="2.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)
security = HTTPBearer(auto_error=False)

# ══════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def make_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub":   user_id,
        "email": email,
        "role":  role,
        "exp":   datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    }
    if HAS_JWT:
        return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")
    import base64, hmac as _hmac
    data = f"{user_id}|{email}|{role}"
    sig  = _hmac.new(SECRET_KEY.encode(), data.encode(), "sha256").hexdigest()
    return base64.b64encode(f"{data}|{sig}".encode()).decode()

def decode_token(token: str) -> dict:
    if HAS_JWT:
        try:
            return pyjwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            raise HTTPException(401, "Token expired or invalid. Please login again.")
    try:
        import base64
        decoded = base64.b64decode(token).decode()
        parts   = decoded.split("|")
        return {"sub": parts[0], "email": parts[1], "role": parts[2]}
    except:
        raise HTTPException(401, "Invalid token.")

def current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "Please login first.")
    return decode_token(creds.credentials)

def gen_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)

# ══════════════════════════════════════════════════
# EMAIL OTP SENDER
# ══════════════════════════════════════════════════

def send_otp_email(to_email: str, otp: str, name: str = "User"):
    """
    OTP sirf email pe jaata hai.
    Screen pe nahi dikhta.
    SMTP_USER aur SMTP_PASS .env mein set hone chahiye.
    """
    if not SMTP_USER or not SMTP_PASS:
        print(f"\n[WARNING] Email not configured!")
        print(f"[DEV] OTP for {to_email}: {otp}")
        print(f"[ACTION] Please set SMTP_USER and SMTP_PASS in .env file\n")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "GeoGuard AI — Your Verification Code"
        msg["From"]    = f"GeoGuard AI <{SMTP_USER}>"
        msg["To"]      = to_email

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td align="center" style="padding:30px 0">
                <table width="500" cellpadding="0" cellspacing="0" 
                       style="background:#ffffff;border-radius:12px;overflow:hidden;
                              box-shadow:0 4px 20px rgba(0,0,0,0.1)">
                  
                  <!-- Header -->
                  <tr>
                    <td style="background:#14532d;padding:28px;text-align:center">
                      <div style="font-size:28px;margin-bottom:6px">🛡</div>
                      <div style="color:#4ade80;font-size:22px;font-weight:800;
                                  letter-spacing:1px">GeoGuard AI</div>
                      <div style="color:#86efac;font-size:12px;margin-top:4px">
                        AI Enhanced Early Disaster Warning
                      </div>
                    </td>
                  </tr>
                  
                  <!-- Body -->
                  <tr>
                    <td style="padding:36px 40px">
                      <p style="color:#374151;font-size:16px;margin:0 0 8px">
                        Hello <strong>{name}</strong>,
                      </p>
                      <p style="color:#6b7280;font-size:14px;margin:0 0 28px;line-height:1.6">
                        Your GeoGuard AI verification code is:
                      </p>
                      
                      <!-- OTP Box -->
                      <div style="background:#f0fdf4;border:2px dashed #4ade80;
                                  border-radius:12px;padding:24px;text-align:center;
                                  margin-bottom:28px">
                        <div style="font-size:42px;font-weight:900;letter-spacing:14px;
                                    color:#16a34a;font-family:'Courier New',monospace">
                          {otp}
                        </div>
                        <div style="color:#6b7280;font-size:12px;margin-top:8px">
                          This code expires in {OTP_EXPIRE_MIN} minutes
                        </div>
                      </div>
                      
                      <p style="color:#6b7280;font-size:13px;line-height:1.6;margin:0">
                        If you did not request this code, please ignore this email. 
                        Do not share this code with anyone.
                      </p>
                    </td>
                  </tr>
                  
                  <!-- Footer -->
                  <tr>
                    <td style="background:#f9fafb;padding:18px 40px;text-align:center;
                                border-top:1px solid #e5e7eb">
                      <p style="color:#9ca3af;font-size:12px;margin:0">
                        &copy; 2025 GeoGuard AI — Disaster Warning System
                      </p>
                    </td>
                  </tr>
                  
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, msg.as_string())

        print(f"[EMAIL] OTP sent to {to_email}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("[EMAIL ERROR] Authentication failed — check SMTP_USER and SMTP_PASS in .env")
        raise HTTPException(500, "Email service error. Please contact administrator.")
    except smtplib.SMTPException as e:
        print(f"[EMAIL ERROR] {e}")
        raise HTTPException(500, "Failed to send OTP email. Please try again.")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        raise HTTPException(500, "Email sending failed. Please try again.")

# ══════════════════════════════════════════════════
# SMS HELPER
# ══════════════════════════════════════════════════

def send_sms(phone: str, message: str) -> bool:
    """
    Send SMS via Fast2SMS (free plan for India).
    Setup:
    1. Register at fast2sms.com (free)
    2. Go to Dashboard → Dev API → copy API key
    3. Set FAST2SMS_KEY in .env file
    """
    # Clean phone number — remove +91, spaces, dashes
    phone_clean = phone.replace("+91","").replace(" ","").replace("-","").strip()
    # Keep only digits
    phone_clean = ''.join(c for c in phone_clean if c.isdigit())

    if not FAST2SMS_KEY:
        print(f"\n[SMS-DEV] SMS would be sent to {phone_clean}:")
        print(f"[SMS-DEV] Message: {message}")
        print(f"[SMS-DEV] To enable real SMS: set FAST2SMS_KEY in .env file\n")
        return False

    try:
        url = "https://www.fast2sms.com/dev/bulkV2"
        # Fast2SMS Quick Transactional route
        payload = {
            "route":   "q",
            "message": message[:160],
            "numbers": phone_clean,
            "flash":   0
        }
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req  = urllib.request.Request(url, data=data, method="POST")
        req.add_header("authorization", FAST2SMS_KEY)
        req.add_header("Content-Type",  "application/x-www-form-urlencoded")
        req.add_header("Cache-Control", "no-cache")

        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read().decode("utf-8"))
            if resp.get("return") == True:
                print(f"[SMS] ✅ Sent to {phone_clean}: {message[:40]}...")
                return True
            else:
                print(f"[SMS] ❌ Failed: {resp}")
                return False

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"[SMS ERROR] HTTP {e.code}: {body}")
        return False
    except Exception as e:
        print(f"[SMS ERROR] {e}")
        return False

# ══════════════════════════════════════════════════
# LOCATION + WEATHER HELPERS
# ══════════════════════════════════════════════════

CITIES = {
    "dehradun":(30.3165,78.0322),"shimla":(31.1048,77.1734),"manali":(32.2396,77.1887),
    "darjeeling":(27.036,88.2627),"munnar":(10.0889,77.0595),"cherrapunji":(25.28,91.73),
    "nainital":(29.3803,79.4636),"mussoorie":(30.4598,78.0644),"aizawl":(23.7271,92.7176),
    "shillong":(25.5788,91.8933),"srinagar":(34.0837,74.7973),"leh":(34.1526,77.5771),
    "uttarkashi":(30.7268,78.4354),"wayanad":(11.6854,76.132),"ooty":(11.4102,76.695),
    "dharamshala":(32.219,76.3234),"kasol":(32.0998,77.3148),"tawang":(27.5861,91.8594),
    "mumbai":(19.076,72.8777),"delhi":(28.6139,77.209),"chennai":(13.0827,80.2707),
    "kolkata":(22.5726,88.3639),"bangalore":(12.9716,77.5946),"hyderabad":(17.385,78.4867),
    "pune":(18.5204,73.8567),"ahmedabad":(23.0225,72.5714),"jaipur":(26.9124,75.7873),
    "bhubaneswar":(20.2961,85.8245),"visakhapatnam":(17.6868,83.2185),
    "kochi":(9.9312,76.2673),"puri":(19.8135,85.8312),"guwahati":(26.1445,91.7362),
    "patna":(25.5941,85.1376),"ranchi":(23.3441,85.3096),"bhopal":(23.2599,77.4126),
    "lucknow":(26.8467,80.9462),"varanasi":(25.3176,82.9739),"agra":(27.1767,78.0081),
    "chandigarh":(30.7333,76.7794),"amritsar":(31.634,74.8723),"nagpur":(21.1458,79.0882),
    "rudraprayag":(30.2847,78.981),"chamoli":(30.4076,79.3267),"kedarnath":(30.7346,79.0669),
    "rishikesh":(30.0869,78.2676),"haridwar":(29.9457,78.1642),"goa":(15.2993,74.1240),
    "gangtok":(27.3389,88.6065),"imphal":(24.817,93.9368),"kohima":(25.6751,94.1086),
}

HIGH_RISK_ZONES = [
    {"name":"Uttarkashi","lat":30.72,"lon":78.43,"disaster":"Landslide","risk":88,"state":"Uttarakhand"},
    {"name":"Chamoli","lat":30.40,"lon":79.32,"disaster":"Landslide","risk":85,"state":"Uttarakhand"},
    {"name":"Rudraprayag","lat":30.28,"lon":78.98,"disaster":"Landslide","risk":86,"state":"Uttarakhand"},
    {"name":"Kedarnath","lat":30.73,"lon":79.06,"disaster":"Landslide+Flood","risk":92,"state":"Uttarakhand"},
    {"name":"Cherrapunji","lat":25.28,"lon":91.73,"disaster":"Landslide+Flood","risk":94,"state":"Meghalaya"},
    {"name":"Darjeeling","lat":27.03,"lon":88.26,"disaster":"Landslide","risk":83,"state":"West Bengal"},
    {"name":"Wayanad","lat":11.68,"lon":76.13,"disaster":"Landslide","risk":85,"state":"Kerala"},
    {"name":"Munnar","lat":10.08,"lon":77.06,"disaster":"Landslide","risk":79,"state":"Kerala"},
    {"name":"Aizawl","lat":23.72,"lon":92.71,"disaster":"Landslide","risk":80,"state":"Mizoram"},
    {"name":"Puri","lat":19.81,"lon":85.83,"disaster":"Cyclone+Flood","risk":87,"state":"Odisha"},
    {"name":"Visakhapatnam","lat":17.68,"lon":83.21,"disaster":"Cyclone","risk":81,"state":"Andhra Pradesh"},
    {"name":"Guwahati","lat":26.14,"lon":91.73,"disaster":"Flood","risk":78,"state":"Assam"},
    {"name":"Patna","lat":25.59,"lon":85.13,"disaster":"Flood","risk":73,"state":"Bihar"},
    {"name":"Manali","lat":32.23,"lon":77.18,"disaster":"Landslide","risk":76,"state":"Himachal Pradesh"},
    {"name":"Shillong","lat":25.57,"lon":91.88,"disaster":"Landslide+Flood","risk":77,"state":"Meghalaya"},
]

MAP_ZONES = [
    {"name":"Uttarkashi","lat":30.72,"lon":78.43,"zone":"red","disaster":"Landslide","risk":88},
    {"name":"Chamoli","lat":30.40,"lon":79.32,"zone":"red","disaster":"Landslide","risk":85},
    {"name":"Rudraprayag","lat":30.28,"lon":78.98,"zone":"red","disaster":"Landslide","risk":86},
    {"name":"Kedarnath","lat":30.73,"lon":79.06,"zone":"red","disaster":"Landslide+Flood","risk":92},
    {"name":"Cherrapunji","lat":25.28,"lon":91.73,"zone":"red","disaster":"Landslide+Flood","risk":94},
    {"name":"Darjeeling","lat":27.03,"lon":88.26,"zone":"red","disaster":"Landslide","risk":83},
    {"name":"Wayanad","lat":11.68,"lon":76.13,"zone":"red","disaster":"Landslide","risk":85},
    {"name":"Puri","lat":19.81,"lon":85.83,"zone":"red","disaster":"Cyclone+Flood","risk":87},
    {"name":"Aizawl","lat":23.72,"lon":92.71,"zone":"red","disaster":"Landslide","risk":80},
    {"name":"Dehradun","lat":30.31,"lon":78.03,"zone":"orange","disaster":"Landslide","risk":62},
    {"name":"Shimla","lat":31.10,"lon":77.17,"zone":"orange","disaster":"Landslide","risk":58},
    {"name":"Shillong","lat":25.57,"lon":91.89,"zone":"orange","disaster":"Flood","risk":60},
    {"name":"Munnar","lat":10.08,"lon":77.06,"zone":"orange","disaster":"Landslide","risk":70},
    {"name":"Bhubaneswar","lat":20.29,"lon":85.82,"zone":"orange","disaster":"Cyclone","risk":65},
    {"name":"Guwahati","lat":26.14,"lon":91.73,"zone":"orange","disaster":"Flood","risk":68},
    {"name":"Manali","lat":32.23,"lon":77.18,"zone":"orange","disaster":"Landslide","risk":63},
    {"name":"Visakhapatnam","lat":17.68,"lon":83.21,"zone":"orange","disaster":"Cyclone","risk":72},
    {"name":"Patna","lat":25.59,"lon":85.13,"zone":"orange","disaster":"Flood","risk":65},
    {"name":"Delhi","lat":28.61,"lon":77.20,"zone":"green","disaster":"Low Risk","risk":22},
    {"name":"Jaipur","lat":26.91,"lon":75.78,"zone":"green","disaster":"Low Risk","risk":18},
    {"name":"Bangalore","lat":12.97,"lon":77.59,"zone":"green","disaster":"Low Risk","risk":20},
    {"name":"Hyderabad","lat":17.38,"lon":78.48,"zone":"green","disaster":"Low Risk","risk":25},
    {"name":"Pune","lat":18.52,"lon":73.85,"zone":"green","disaster":"Low Risk","risk":19},
    {"name":"Chandigarh","lat":30.73,"lon":76.77,"zone":"green","disaster":"Low Risk","risk":21},
    {"name":"Ahmedabad","lat":23.02,"lon":72.57,"zone":"green","disaster":"Low Risk","risk":16},
    {"name":"Lucknow","lat":26.84,"lon":80.94,"zone":"green","disaster":"Low Risk","risk":23},
]

def get_coords(name: str):
    """
    Works for ANY city/town/village in India.
    1. First checks local CITIES dict (fast, offline)
    2. Then tries Nominatim OpenStreetMap API (any location in world)
    3. Falls back to coordinate parsing if user types lat,lon directly
    """
    if not name or not name.strip():
        raise HTTPException(400, "Please enter a location name.")

    name = name.strip()

    # Check if user typed coordinates directly (e.g. "28.61,77.20")
    if ',' in name:
        parts = name.split(',')
        if len(parts) == 2:
            try:
                la, lo = float(parts[0].strip()), float(parts[1].strip())
                if -90 <= la <= 90 and -180 <= lo <= 180:
                    return la, lo, f"{la:.4f},{lo:.4f}"
            except:
                pass

    # Check local dictionary first (fastest)
    key = name.lower().strip()
    for k, (la, lo) in CITIES.items():
        if k == key or k in key or key in k:
            return la, lo, name

    # Try OpenStreetMap Nominatim (works for ANY city in India and world)
    try:
        # Try with "India" suffix first
        for query in [name + " India", name]:
            q   = urllib.parse.quote(query)
            url = f"https://nominatim.openstreetmap.org/search?q={q}&format=json&limit=3&countrycodes=in"
            req = urllib.request.Request(url, headers={"User-Agent": "GeoGuard/2.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
            if data:
                # Prefer cities/towns over other types
                for item in data:
                    if item.get("type") in ["city","town","village","suburb","administrative","district"]:
                        return float(item["lat"]), float(item["lon"]), item.get("display_name","")
                # If no preferred type, use first result
                return float(data[0]["lat"]), float(data[0]["lon"]), data[0].get("display_name","")
    except Exception as e:
        print(f"[Geocoding] Nominatim failed for '{name}': {e}")

    # If everything fails
    raise HTTPException(404, f"Location '{name}' not found. Please try a different spelling or nearby city.")

def fetch_nasa(lat: float, lon: float, target_month: int = None) -> dict:
    today = datetime.utcnow()
    start = (today - timedelta(days=10)).strftime("%Y%m%d")
    end   = (today - timedelta(days=1)).strftime("%Y%m%d")
    url   = (
        f"https://power.larc.nasa.gov/api/temporal/daily/point"
        f"?parameters=PRECTOTCORR,T2M,RH2M,GWETROOT,WS2M"
        f"&community=RE&longitude={lon}&latitude={lat}"
        f"&start={start}&end={end}&format=JSON"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GeoGuard/2.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            props = json.loads(r.read().decode())["properties"]["parameter"]
        def cl(v, d):
            c = [x for x in v.values() if x not in (-999, -999.0, None)]
            return c or [d]
        rain  = cl(props.get("PRECTOTCORR", {}), 10.0)
        temp  = cl(props.get("T2M",  {}), 22.0)
        humid = cl(props.get("RH2M", {}), 70.0)
        soil  = cl(props.get("GWETROOT", {}), 0.4)
        wind  = cl(props.get("WS2M", {}), 10.0)
        base = {
            "rain_today": round(rain[-1], 2),
            "rain_3day":  round(sum(rain[-3:]), 2),
            "rain_7day":  round(sum(rain[-7:]), 2),
            "temp":       round(sum(temp) / len(temp), 1),
            "humidity":   round(sum(humid) / len(humid), 1),
            "soil":       round(sum(soil) / len(soil), 4),
            "wind":       round(sum(wind) / len(wind), 1),
            "source":     "NASA POWER (Live)",
        }
        if target_month and target_month != today.month:
            mo = target_month in [6,7,8,9]
            cy = target_month in [5,6,10,11,12]
            dr = target_month in [3,4,5,11,12,1]
            f  = 3.5 if mo else (1.8 if cy else (0.15 if dr else 0.8))
            base["rain_today"] = round(base["rain_today"] * f, 2)
            base["rain_3day"]  = round(base["rain_3day"]  * f, 2)
            base["rain_7day"]  = round(base["rain_7day"]  * f, 2)
            base["source"]    += " (Seasonally Adjusted)"
        return base
    except:
        m  = target_month or today.month
        mo = m in [6,7,8,9]
        return {
            "rain_today": 55.0 if mo else 4.0,
            "rain_3day":  140.0 if mo else 10.0,
            "rain_7day":  320.0 if mo else 28.0,
            "temp": 27.0, "humidity": 80.0 if mo else 50.0,
            "soil": 0.58 if mo else 0.25, "wind": 14.0,
            "source": "Seasonal Estimate (NASA unavailable)",
        }

def get_terrain(lat, lon, month, rain7):
    if   lat > 28 and 76 < lon < 97:     elev = 1500 + abs(lat-28)*200
    elif 73 < lon < 77 and 8 < lat < 22: elev = 800  + (22-lat)*30
    elif lat > 22 and lon > 90:           elev = 600  + (lat-22)*100
    elif 15 < lat < 25 and 76 < lon < 84:elev = 400  + (lat-15)*20
    else:                                 elev = max(10, 200-(abs(lat-15)*5))
    slope = min(55, max(2, (elev-100)/80)) if elev > 100 else 2.0
    rivers = [(27.5,80),(25,85),(23,90),(17,81),(16,80.5),(11,78),(22,73)]
    rd = max(0.5, min(30, min(math.sqrt((lat-r[0])**2+(lon-r[1])**2)*111 for r in rivers)/10))
    base = 0.65 if ((lat>22 and lon>90) or (73<lon<77 and 8<lat<22)) else (0.45 if lat>28 else 0.35)
    ndvi  = min(0.9, base + (0.15 if month in [6,7,8,9] else 0) + min(0.1, rain7/2000))
    coast = min(500, abs(lon-77)*111) if lon < 80 else min(500, abs(lon-87)*111)
    return {"elev":round(elev,1),"slope":round(slope,1),"rd":round(rd,2),
            "ndvi":round(ndvi,3),"coast_dist":round(coast,1)}

def get_seismic(lat, lon):
    if (lat>25 and lon>88) or (lat>32 and lon<80): zone,stress,hf = 5, 85, 7.5
    elif lat>23 and lon<85:                         zone,stress,hf = 4, 60, 4.5
    else:                                           zone,stress,hf = 3, 35, 2.0
    faults = [(34,74),(32,78),(27,93),(23,70),(8,77)]
    fd = min(math.sqrt((lat-f[0])**2+(lon-f[1])**2)*111 for f in faults)
    return {"zone":zone,"stress":stress,"hist_freq":hf,"fault_dist":round(fd,1)}

def haversine(la1, lo1, la2, lo2):
    R = 6371.0
    dlat = math.radians(la2-la1); dlon = math.radians(lo2-lo1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(la1))*math.cos(math.radians(la2))*math.sin(dlon/2)**2
    return R * 2 * math.asin(math.sqrt(a))

def risk_level(c):
    if c >= 75: return "HIGH"
    if c >= 50: return "MEDIUM"
    if c >= 30: return "LOW"
    return "MINIMAL"

ADVICE = {
    "landslide": {
        "HIGH":    {"en":"DANGER: Evacuate immediately. Avoid steep slopes.","hi":"खतरा: तुरंत इलाका खाली करें। ढलानों से दूर रहें।"},
        "MEDIUM":  {"en":"WARNING: Avoid hill roads during rain.","hi":"चेतावनी: बारिश में पहाड़ी रास्तों से बचें।"},
        "LOW":     {"en":"CAUTION: Monitor weather updates.","hi":"सावधानी: मौसम अपडेट देखें।"},
        "MINIMAL": {"en":"Safe conditions.","hi":"सुरक्षित स्थिति।"},
    },
    "flood": {
        "HIGH":    {"en":"DANGER: Move to higher ground immediately.","hi":"खतरा: तुरंत ऊंचे स्थान पर जाएं।"},
        "MEDIUM":  {"en":"WARNING: Monitor water levels. Elevate belongings.","hi":"चेतावनी: पानी का स्तर देखें।"},
        "LOW":     {"en":"CAUTION: Check local drainage.","hi":"सावधानी: जल निकासी जांचें।"},
        "MINIMAL": {"en":"Safe conditions.","hi":"सुरक्षित स्थिति।"},
    },
    "cyclone": {
        "HIGH":    {"en":"DANGER: Move inland. Stay in strong building.","hi":"खतरा: अंदर की ओर जाएं। पक्के मकान में रहें।"},
        "MEDIUM":  {"en":"WARNING: Find nearest cyclone shelter.","hi":"चेतावनी: नजदीकी आश्रय पहचानें।"},
        "LOW":     {"en":"CAUTION: Follow IMD bulletins.","hi":"सावधानी: IMD बुलेटिन फॉलो करें।"},
        "MINIMAL": {"en":"Safe conditions.","hi":"सुरक्षित स्थिति।"},
    },
    "drought": {
        "HIGH":    {"en":"SEVERE: Implement water conservation immediately.","hi":"गंभीर: तुरंत जल संरक्षण शुरू करें।"},
        "MEDIUM":  {"en":"WARNING: Reduce water usage.","hi":"चेतावनी: पानी का उपयोग कम करें।"},
        "LOW":     {"en":"CAUTION: Monitor reservoir levels.","hi":"सावधानी: जलाशय स्तर देखें।"},
        "MINIMAL": {"en":"Normal water availability.","hi":"सामान्य जल उपलब्धता।"},
    },
    "earthquake": {
        "HIGH":    {"en":"ALERT: Drop-Cover-Hold. Keep emergency kit ready.","hi":"अलर्ट: गिरो-ढको-थामो। आपातकालीन किट रखें।"},
        "MEDIUM":  {"en":"CAUTION: Inspect old structures.","hi":"सावधानी: पुरानी संरचनाएं जांचें।"},
        "LOW":     {"en":"Low seismic activity. Stay informed.","hi":"कम भूकंपीय गतिविधि।"},
        "MINIMAL": {"en":"Minimal seismic risk.","hi":"न्यूनतम भूकंपीय जोखिम।"},
    },
}

def predict_one(disaster, lat, lon, month, weather, terrain, seismic):
    """
    ML-based prediction using trained .pkl models.
    If model not loaded, uses physics-based fallback.
    Geographic constraints applied to fix location-specific issues.
    """
    conf = 25.0
    try:
        if disaster == "landslide" and "landslide" in MODELS:
            r,r3,r7=weather["rain_today"],weather["rain_3day"],weather["rain_7day"]
            sm,ndvi=weather["soil"],terrain["ndvi"]
            elev,slp,rd=terrain["elev"],terrain["slope"],terrain["rd"]
            tmp,hum=weather["temp"],weather["humidity"]
            X=np.array([r,r3,r7,sm,ndvi,elev,slp,rd,tmp,hum,r/(r7+1),sm*r,slp*sm,
                        1-ndvi,r3+r7,slp/(rd+0.1),hum*tmp/100,int(month in[6,7,8,9])]).reshape(1,-1)
            conf=round(float(MODELS["landslide"]["model"].predict_proba(X)[0][1])*100,1)
        elif disaster == "flood" and "flood" in MODELS:
            r,r3,r7,sm=weather["rain_today"],weather["rain_3day"],weather["rain_7day"],weather["soil"]
            elev,slp,rd,hum=terrain["elev"],terrain["slope"],terrain["rd"],weather["humidity"]
            rl=min(11,(r3/50)*(1+(1-elev/500))*5); up=min(4999,r7*10); dc=max(0.1,1-(sm*0.6))
            X=np.array([r,rl,dc,sm,up,elev,slp,rd,r3,r7,hum,month,r/(r3+1),rl*sm,(1-dc)*r]).reshape(1,-1)
            conf=round(float(MODELS["flood"]["model"].predict_proba(X)[0][1])*100,1)
        elif disaster == "cyclone" and "cyclone" in MODELS:
            wind,hum,temp,cd=weather["wind"],weather["humidity"],weather["temp"],terrain["coast_dist"]
            sst=min(32,max(24,temp+2)); pres=max(900,1013-(wind*0.5))
            ohc=min(120,sst*3.5); ws=max(0,30-(hum-50)*0.3); pw=wind*0.9
            X=np.array([sst,wind*3.6,pres,hum,cd,lat,month,ws,ohc,pw,1013-pres,wind/(pw+1),sst*ohc/100]).reshape(1,-1)
            conf=round(float(MODELS["cyclone"]["model"].predict_proba(X)[0][1])*100,1)
        elif disaster == "drought":
            # Physics-based zone-aware drought detection
            r7   = weather["rain_7day"]
            sm   = weather["soil"]
            temp = weather["temp"]
            hum  = weather["humidity"]
            ndvi = terrain["ndvi"]

            # Zone classification — determines drought threshold
            if (8<=lat<=14 and 74<=lon<=78) or (lat>22 and lon>89) or (15<=lat<=16 and 73<=lon<=75):
                zone="WET";     min_s=0.15; dt=38   # Kerala, NE India, Goa
            elif (lat>25 and 72<=lon<=76) or (lat>22 and 68<=lon<=72):
                zone="ARID";    min_s=0.40; dt=28   # Rajasthan, Kutch
            elif (20<=lat<=26 and 72<=lon<=82):
                zone="SEMI_ARID"; min_s=0.30; dt=32 # MP, Vidarbha
            elif (12<=lat<=20 and 76<=lon<=82):
                zone="MODERATE";  min_s=0.28; dt=33 # AP, Telangana, Karnataka
            else:
                zone="NORMAL";  min_s=0.25; dt=32   # Rest of India

            drought_score = 0

            # Soil moisture — most important (0-50 pts)
            if sm < min_s:
                drought_score += ((min_s - sm) / min_s) * 50

            # Humidity (0-48 pts)
            if hum < 40:
                drought_score += (40 - hum) * 1.2
            elif hum < 55:
                drought_score += (55 - hum) * 0.5

            # Temperature anomaly (0-30 pts)
            if temp > dt:
                drought_score += (temp - dt) * 2.5

            # Vegetation stress (0-30 pts)
            if ndvi < 0.3:
                drought_score += (0.3 - ndvi) * 30

            # Month peak factor
            drought_score += {3:8, 4:15, 5:18, 11:5, 12:8, 1:5, 2:5}.get(month, 0)

            # Zone adjustments
            if zone == "WET":
                drought_score = min(drought_score, 22)
            elif zone == "ARID":
                drought_score = min(drought_score * 1.3, 88)

            # Active monsoon = no drought
            if month in [6, 7, 8] and r7 > 80:
                drought_score = min(drought_score, 12)

            conf = round(min(90, max(2, drought_score)), 1)
        elif disaster == "earthquake" and "earthquake" in MODELS:
            fd=seismic["fault_dist"]; st=seismic["stress"]; hf=seismic["hist_freq"]
            X=np.array([fd,10,st,20,2.5,2.,30,2.5,lat,lon,hf,st/(fd+1),2.5*10,2.5*(1-20/300)]).reshape(1,-1)
            conf=round(float(MODELS["earthquake"]["model"].predict_proba(X)[0][1])*100,1)
        else:
            base = {
                "landslide": 20+(terrain["slope"]/65)*30+(weather["rain_7day"]/400)*20,
                "flood":     15+((1-terrain["elev"]/3000))*20+(weather["rain_7day"]/400)*25,
                "cyclone":   5+(1-terrain["coast_dist"]/500)*35+(8 if month in[10,11,5]else 0),
                "drought":   20+(1-weather["soil"])*25+(10 if month in[3,4,5]else 0),
                "earthquake":15+(seismic["stress"]/100)*30,
            }
            conf = round(min(88, max(5, base.get(disaster, 20))), 1)
    except Exception as e:
        print(f"[Predict Error] {disaster}: {e}")

    lv  = risk_level(conf)
    adv = ADVICE.get(disaster, {}).get(lv, {})
    # ── Geographic post-processing corrections ──────────────────────
    # These correct known issues where model gives wrong predictions
    # for specific regions due to training data bias

    # Drought safety handled inside model (zone-aware)

    # Cyclone: inland locations (far from coast) very unlikely
    if disaster == "cyclone" and terrain["coast_dist"] > 400:
        conf = min(conf, 12.0)

    # Earthquake: Zone 2 areas (low seismicity) — cap moderate
    if disaster == "earthquake" and seismic["zone"] <= 2:
        conf = min(conf, 25.0)

    # Landslide: flat regions (low elevation, low slope) — cap low
    if disaster == "landslide" and terrain["elev"] < 100 and terrain["slope"] < 5:
        conf = min(conf, 20.0)

    # Round to 1 decimal
    conf = round(conf, 1)
    # ─────────────────────────────────────────────────────────────────

    lv  = risk_level(conf)
    adv = ADVICE.get(disaster, {}).get(lv, {})
    return {
        "disaster":    disaster,
        "confidence":  conf,
        "risk":        lv,
        "prediction":  "RISK" if conf >= 50 else "SAFE",
        "advice_en":   adv.get("en", "Stay alert."),
        "advice_hi":   adv.get("hi", "सतर्क रहें।"),
    }

def get_nearby(lat, lon, radius=150.0):
    alerts = []
    for z in HIGH_RISK_ZONES:
        d = haversine(lat, lon, z["lat"], z["lon"])
        if d <= radius and z["risk"] >= 70:
            alerts.append({
                **z,
                "distance_km": round(d, 1),
                "risk_level":  risk_level(z["risk"]),
                "msg_en": f"{z['name']} has {risk_level(z['risk'])} {z['disaster']} risk — {round(d,1)}km from you",
                "msg_hi": f"{z['name']} में {z['disaster']} का {risk_level(z['risk'])} खतरा — आपसे {round(d,1)} किमी दूर",
            })
    return sorted(alerts, key=lambda x: x["distance_km"])

# ══════════════════════════════════════════════════
# PYDANTIC SCHEMAS
# ══════════════════════════════════════════════════

class RegisterReq(BaseModel):
    name:     str
    email:    str
    password: str = Field(..., min_length=6)
    phone:    Optional[str] = None
    city:     Optional[str] = None

class VerifyOTPReq(BaseModel):
    email: str
    otp:   str

class LoginReq(BaseModel):
    email:    str
    password: str

class ResendReq(BaseModel):
    email: str

class PredictReq(BaseModel):
    location:      str
    month:         int = Field(..., ge=1, le=12)
    disaster:      str
    duration_days: int = Field(3, ge=1, le=30)
    phone:         Optional[str] = None

class NearbyReq(BaseModel):
    lat:       float
    lon:       float
    radius_km: float = 150.0

class NgoReq(BaseModel):
    org_name:        str
    org_type:        str
    registration_no: str
    address:         Optional[str] = None
    city:            str
    state:           str
    pincode:         Optional[str] = None
    phone:           str
    website:         Optional[str] = None
    description:     Optional[str] = None

class ResourceReq(BaseModel):
    resource_type: str
    resource_name: str
    quantity:      int
    available:     int
    unit:          str = "units"
    description:   Optional[str] = None

class HelpReq(BaseModel):
    location:         str
    lat:              Optional[float] = None
    lon:              Optional[float] = None
    disaster_type:    str
    severity:         str
    people_affected:  int = 0
    resources_needed: str
    description:      Optional[str] = None
    phone:            Optional[str] = None

class UpdateProfileReq(BaseModel):
    name:         Optional[str] = None
    phone:        Optional[str] = None
    city:         Optional[str] = None
    sms_alerts:   Optional[int] = None
    email_alerts: Optional[int] = None

class SaveLocReq(BaseModel):
    location_name: str
    lat:           Optional[float] = None
    lon:           Optional[float] = None

# ══════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════

@app.post("/auth/register", tags=["Auth"])
def register(req: RegisterReq, bg: BackgroundTasks):
    # Check duplicate
    if users_col.find_one({"email": req.email}):
        raise HTTPException(400, "Email already registered. Please login.")

    # Hash password
    hashed = hash_password(req.password)

    # Create user
    user_doc = {
        "name":          req.name,
        "email":         req.email,
        "password_hash": hashed,
        "role":          "user",
        "is_verified":   False,
        "phone":         req.phone,
        "city":          req.city,
        "lat":           None,
        "lon":           None,
        "sms_alerts":    True,
        "created_at":    datetime.utcnow(),
        "last_login":    None,
    }
    result = users_col.insert_one(user_doc)

    # Generate OTP
    otp     = gen_otp()
    exp     = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MIN)
    otp_doc = {
        "email":      req.email,
        "otp":        otp,
        "purpose":    "verify",
        "expires_at": exp,
        "used":       False,
        "created_at": datetime.utcnow(),
    }
    otps_col.insert_one(otp_doc)

    # Send OTP email in background
    bg.add_task(send_otp_email, req.email, otp, req.name)

    return {
        "message": f"Account created! OTP sent to {req.email}. Please check your inbox.",
        "email":   req.email
    }

@app.post("/auth/verify-otp", tags=["Auth"])
def verify_otp(req: VerifyOTPReq):
    # Find valid OTP
    otp_doc = otps_col.find_one({
        "email":  req.email,
        "otp":    req.otp,
        "used":   False,
    })
    if not otp_doc:
        raise HTTPException(400, "Invalid OTP. Please check and try again.")
    if datetime.utcnow() > otp_doc["expires_at"]:
        raise HTTPException(400, "OTP expired. Please click Resend OTP.")

    # Mark OTP as used
    otps_col.update_one({"_id": otp_doc["_id"]}, {"$set": {"used": True}})

    # Verify user
    users_col.update_one(
        {"email": req.email},
        {"$set": {"is_verified": True}}
    )

    # Get user
    user = users_col.find_one({"email": req.email})
    token = make_token(str(user["_id"]), user["email"], user["role"])

    return {
        "message": "Email verified! Welcome to GeoGuard AI.",
        "token":   token,
        "user": {
            "id":    str(user["_id"]),
            "name":  user["name"],
            "email": user["email"],
            "role":  user["role"],
            "phone": user.get("phone"),
        }
    }

@app.post("/auth/login", tags=["Auth"])
def login(req: LoginReq, bg: BackgroundTasks):
    user = users_col.find_one({"email": req.email})
    if not user:
        raise HTTPException(401, "Email not registered. Please sign up.")
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Wrong password. Please try again.")
    if not user.get("is_verified"):
        # Resend OTP
        otp = gen_otp()
        exp = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MIN)
        otps_col.insert_one({
            "email": req.email, "otp": otp, "purpose": "verify",
            "expires_at": exp, "used": False, "created_at": datetime.utcnow()
        })
        bg.add_task(send_otp_email, req.email, otp, user["name"])
        raise HTTPException(403, "Email not verified. New OTP sent to your email.")

    # Update last login
    users_col.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.utcnow()}})
    token = make_token(str(user["_id"]), user["email"], user["role"])

    return {
        "token": token,
        "user": {
            "id":    str(user["_id"]),
            "name":  user["name"],
            "email": user["email"],
            "role":  user["role"],
            "phone": user.get("phone"),
        }
    }

@app.post("/auth/resend-otp", tags=["Auth"])
def resend_otp(req: ResendReq, bg: BackgroundTasks):
    user = users_col.find_one({"email": req.email})
    if not user:
        raise HTTPException(404, "Email not registered.")
    otp = gen_otp()
    exp = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MIN)
    otps_col.insert_one({
        "email": req.email, "otp": otp, "purpose": "verify",
        "expires_at": exp, "used": False, "created_at": datetime.utcnow()
    })
    bg.add_task(send_otp_email, req.email, otp, user["name"])
    return {"message": f"New OTP sent to {req.email}. Please check your inbox."}

# ══════════════════════════════════════════════════
# PREDICTION ENDPOINTS
# ══════════════════════════════════════════════════

@app.post("/predict", tags=["Predictions"])
def predict(req: PredictReq, bg: BackgroundTasks, user=Depends(current_user)):
    lat, lon, display = get_coords(req.location)
    month   = req.month
    weather = fetch_nasa(lat, lon, month)
    terrain = get_terrain(lat, lon, month, weather["rain_7day"])
    seismic = get_seismic(lat, lon)

    disasters_list = (
        ["landslide","flood","cyclone","drought","earthquake"]
        if req.disaster == "all" else [req.disaster.lower()]
    )
    results = {d: predict_one(d, lat, lon, month, weather, terrain, seismic) for d in disasters_list}
    overall_conf = max(v["confidence"] for v in results.values()) if results else 0
    overall_risk = risk_level(overall_conf)
    mn = ["","January","February","March","April","May","June",
          "July","August","September","October","November","December"][month]
    safe = overall_conf < 50
    loc_short = display.split(",")[0] if display else req.location

    # Save prediction to DB
    try:
        history_col.insert_one({
            "user_id":  user["sub"],
            "location": req.location,
            "lat": lat, "lon": lon, "month": month,
            "disaster": req.disaster,
            "confidence": overall_conf,
            "risk_level": overall_risk,
            "created_at": datetime.utcnow(),
        })
        if req.phone:
            users_col.update_one({"_id": ObjectId(user["sub"])}, {"$set": {"phone": req.phone}})
    except:
        pass

    # Send SMS if HIGH risk
    if overall_risk == "HIGH":
        try:
            db_user = users_col.find_one({"_id": ObjectId(user["sub"])})
            phone   = req.phone or (db_user.get("phone") if db_user else None)
            if phone:
                msg = f"GeoGuard Alert: {loc_short} mein {req.disaster} ka HIGH risk hai ({mn}). Savdhaan rahein! -GeoGuard AI"
                bg.add_task(send_sms, phone, msg)
        except:
            pass

    return {
        "location":        req.location,
        "display_name":    loc_short,
        "lat":             round(lat, 4),
        "lon":             round(lon, 4),
        "month":           month,
        "month_name":      mn,
        "overall_risk":    overall_risk,
        "overall_conf":    overall_conf,
        "is_safe_visit":   safe,
        "travel_advice_en": f"{'Safe' if safe else 'Risky'} to visit {loc_short} in {mn}.",
        "travel_advice_hi": f"{mn} में {loc_short} जाना {'सुरक्षित' if safe else 'जोखिम भरा'} है।",
        "disasters":       results,
        "weather":         weather,
        "terrain":         terrain,
        "seismic_zone":    seismic["zone"],
        "timestamp":       datetime.utcnow().strftime("%d %b %Y, %H:%M UTC"),
    }

@app.post("/predict/nearby", tags=["Predictions"])
def nearby(req: NearbyReq, bg: BackgroundTasks, user=Depends(current_user)):
    alerts = get_nearby(req.lat, req.lon, req.radius_km)
    high   = [a for a in alerts if a["risk_level"] == "HIGH"]
    try:
        db_user = users_col.find_one({"_id": ObjectId(user["sub"])})
        users_col.update_one({"_id": ObjectId(user["sub"])}, {"$set": {"lat": req.lat, "lon": req.lon}})
        if high and db_user and db_user.get("phone") and db_user.get("sms_alerts"):
            msg = f"GeoGuard: {high[0]['name']} mein {high[0]['disaster']} ka HIGH risk hai — {high[0]['distance_km']}km aapse! Savdhaan!"
            bg.add_task(send_sms, db_user["phone"], msg)
    except:
        pass
    return {
        "total_alerts": len(alerts),
        "high_risk":    len(high),
        "alerts":       alerts,
        "has_danger":   len(high) > 0,
        "message_en":   f"{len(high)} HIGH risk zone(s) within {req.radius_km}km" if high else "No HIGH risk zones nearby. You are safe!",
        "message_hi":   f"आपके {req.radius_km} किमी में {len(high)} उच्च जोखिम क्षेत्र।" if high else "आसपास कोई उच्च जोखिम नहीं। आप सुरक्षित हैं!",
    }

@app.get("/predict/monthly-calendar", tags=["Predictions"])
@app.post("/predict/monthly-calendar", tags=["Predictions"])
def monthly_cal(location: str, user=Depends(current_user)):
    lat, lon, display = get_coords(location)
    calendar = []
    for month in range(1, 13):
        t  = get_terrain(lat, lon, month, 80 if month in [6,7,8,9] else 20)
        s  = get_seismic(lat, lon)
        ls = min(90, 20+(55 if month in[6,7,8,9]else 5)+t["slope"]*0.3)
        fl = min(88, 15+(50 if month in[6,7,8,9]else 3)+(1-t["elev"]/3000)*20)
        cy = min(85, 5+(48 if month in[5,6,10,11,12]else 4))
        dr = min(80, 10+(48 if month in[3,4,5,11,12,1]else 4))
        eq = min(60, 25+s["stress"]*0.3)
        mn = ["","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][month]
        calendar.append({
            "month":month,"month_name":mn,
            "landslide":round(ls,1),"flood":round(fl,1),"cyclone":round(cy,1),
            "drought":round(dr,1),"earthquake":round(eq,1),
            "overall":round(max(ls,fl,cy,dr,eq),1)
        })
    safest   = min(calendar, key=lambda x: x["overall"])
    riskiest = max(calendar, key=lambda x: x["overall"])
    return {"location":location,"display_name":display,"calendar":calendar,
            "safest_month":safest["month_name"],"riskiest_month":riskiest["month_name"]}

class HistoricalReq(BaseModel):
    location: Optional[str] = None

@app.get("/data/historical", tags=["Data"])
@app.post("/data/historical", tags=["Data"])
def historical(location: str = "", req: HistoricalReq = None, user=Depends(current_user)):
    # Accept location from query param OR body
    loc = location or (req.location if req else "") or ""
    if not loc:
        raise HTTPException(400, "Location required")
    location = loc
    lat, lon, display = get_coords(location)
    np.random.seed(int(abs(lat*100+lon*10)) % 9999)
    years=[2020,2021,2022,2023,2024,2025]
    is_mtn=lat>25 and(lon<80 or lon>90); is_cst=abs(lon-80)<5 or abs(lon-87)<5; is_ne=lat>22 and lon>88
    rain=[{"year":y,"mm":round((1200 if(is_mtn or is_ne)else(900 if is_cst else 650))+np.random.normal(0,150),0)} for y in years]
    evts=[{"year":y,"landslide":int(np.random.poisson(4 if is_mtn else 1)),"flood":int(np.random.poisson(3 if(is_cst or is_ne)else 1)),"cyclone":int(np.random.poisson(1.5 if is_cst else 0.1)),"drought":int(np.random.poisson(0.5 if not(is_mtn or is_ne or is_cst)else 0.2)),"earthquake":int(np.random.poisson(1 if is_mtn else 0.3))} for y in years]
    for e in evts: e["total"]=sum([e["landslide"],e["flood"],e["cyclone"],e["drought"],e["earthquake"]])
    pat=[20,25,35,40,60,180,320,280,180,90,40,25]
    monthly=[{"month":["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][i],"avg_mm":round(pat[i]*(1.4 if(is_mtn or is_ne)else(1.2 if is_cst else 1.0))+np.random.normal(0,10),1)} for i in range(12)]
    temp_anom=[{"year":2020,"anomaly":0.3},{"year":2021,"anomaly":0.5},{"year":2022,"anomaly":0.4},{"year":2023,"anomaly":0.8},{"year":2024,"anomaly":1.1},{"year":2025,"anomaly":0.9}]
    return {"location":location,"display_name":display,"annual_rainfall":rain,"disaster_events":evts,"monthly_rainfall":monthly,"temp_anomaly":temp_anom}

@app.get("/map/zones", tags=["Map"])
def map_zones():
    return {"zones": MAP_ZONES, "total": len(MAP_ZONES)}

# ══════════════════════════════════════════════════
# NGO ENDPOINTS
# ══════════════════════════════════════════════════

@app.post("/ngo/register", tags=["NGO"])
def ngo_register(req: NgoReq, user=Depends(current_user)):
    if ngos_col.find_one({"user_id": user["sub"]}):
        raise HTTPException(400, "You already registered an NGO.")
    if ngos_col.find_one({"registration_no": req.registration_no}):
        raise HTTPException(400, "Registration number already exists.")
    try: lat_n,lon_n,_=get_coords(req.city+" "+req.state)
    except: lat_n,lon_n=None,None
    ngos_col.insert_one({
        "user_id":req.org_name,"org_name":req.org_name,"org_type":req.org_type,
        "registration_no":req.registration_no,"address":req.address,
        "city":req.city,"state":req.state,"pincode":req.pincode,
        "phone":req.phone,"website":req.website,"description":req.description,
        "lat":lat_n,"lon":lon_n,"is_verified":False,"is_active":True,
        "user_id":user["sub"],"created_at":datetime.utcnow()
    })
    return {"message":"NGO registered! Admin will verify within 24 hours."}

@app.get("/ngo/my-profile", tags=["NGO"])
def ngo_profile(user=Depends(current_user)):
    ngo = ngos_col.find_one({"user_id": user["sub"]})
    if not ngo: raise HTTPException(404,"NGO not found. Please register.")
    ngo["_id"] = str(ngo["_id"])
    resources = list(resources_col.find({"ngo_id": str(ngo["_id"])}))
    for r in resources: r["_id"]=str(r["_id"])
    reqs = list(req_col.find({"ngo_id": str(ngo["_id"])}).sort("created_at",-1).limit(20))
    for r in reqs: r["_id"]=str(r["_id"])
    return {"ngo":ngo,"resources":resources,"requests":reqs}

@app.post("/ngo/add-resource", tags=["NGO"])
def add_resource(req: ResourceReq, user=Depends(current_user)):
    ngo = ngos_col.find_one({"user_id": user["sub"]})
    if not ngo: raise HTTPException(403,"Register your NGO first.")
    if not ngo.get("is_verified"): raise HTTPException(403,"NGO not yet verified by admin.")
    resources_col.insert_one({
        "ngo_id":str(ngo["_id"]),"resource_type":req.resource_type,
        "resource_name":req.resource_name,"quantity":req.quantity,
        "available":req.available,"unit":req.unit,"description":req.description,
        "updated_at":datetime.utcnow()
    })
    return {"message":f"Resource '{req.resource_name}' added!"}

@app.get("/ngo/list", tags=["NGO"])
def list_ngos():
    ngos = list(ngos_col.find({"is_verified":True,"is_active":True}))
    for n in ngos:
        n["_id"]           = str(n["_id"])
        n["resource_count"]= resources_col.count_documents({"ngo_id":n["_id"]})
    return {"ngos":ngos,"total":len(ngos)}

@app.put("/ngo/respond/{req_id}", tags=["NGO"])
def respond(req_id: str, status_val: str, response_msg: str="", user=Depends(current_user)):
    if status_val not in ["accepted","declined","completed"]:
        raise HTTPException(400,"Invalid status.")
    ngo = ngos_col.find_one({"user_id": user["sub"]})
    if not ngo: raise HTTPException(403,"NGO not found.")
    req_col.update_one(
        {"_id":ObjectId(req_id),"ngo_id":str(ngo["_id"])},
        {"$set":{"status":status_val,"ngo_response":response_msg,"responded_at":datetime.utcnow()}}
    )
    return {"message":f"Request {status_val}."}

# ══════════════════════════════════════════════════
# RESOURCE REQUESTS
# ══════════════════════════════════════════════════

@app.post("/requests/create", tags=["Requests"])
def create_request(req: HelpReq, bg: BackgroundTasks, user=Depends(current_user)):
    lat,lon=req.lat,req.lon
    if not lat or not lon:
        try: lat,lon,_=get_coords(req.location)
        except: lat,lon=None,None
    ngo_id=None; ngo_name=""
    if lat and lon:
        ngos=list(ngos_col.find({"is_verified":True,"is_active":True,"lat":{"$ne":None}}))
        if ngos:
            nearest=min(ngos,key=lambda n:haversine(lat,lon,n["lat"],n["lon"]))
            ngo_id =str(nearest["_id"]); ngo_name=nearest["org_name"]
            ngo_user=users_col.find_one({"_id":ObjectId(nearest["user_id"])})
            if ngo_user and ngo_user.get("phone"):
                bg.add_task(send_sms,ngo_user["phone"],f"GeoGuard: New help request at {req.location}. Disaster: {req.disaster_type}. Needs: {req.resources_needed[:50]}. Login to respond.")
    req_col.insert_one({
        "requester_id":user["sub"],"ngo_id":ngo_id,"location":req.location,
        "lat":lat,"lon":lon,"disaster_type":req.disaster_type,"severity":req.severity,
        "people_affected":req.people_affected,"resources_needed":req.resources_needed,
        "description":req.description,"status":"pending","created_at":datetime.utcnow()
    })
    if req.phone:
        bg.add_task(send_sms,req.phone,f"GeoGuard: Aapki help request submit ho gayi. {req.location} ke liye {req.disaster_type} request. NGO jald respond karegi.")
    return {"message":"Help request submitted!","ngo_assigned":bool(ngo_id),"ngo_name":ngo_name}

@app.get("/requests/my", tags=["Requests"])
def my_requests(user=Depends(current_user)):
    reqs=list(req_col.find({"requester_id":user["sub"]}).sort("created_at",-1))
    for r in reqs:
        r["_id"]=str(r["_id"])
        if r.get("ngo_id"):
            ngo=ngos_col.find_one({"_id":ObjectId(r["ngo_id"])})
            if ngo: r["ngo_name"]=ngo["org_name"]; r["ngo_phone"]=ngo.get("phone","")
    return {"requests":reqs}

# ══════════════════════════════════════════════════
# USER PROFILE
# ══════════════════════════════════════════════════

@app.get("/user/profile", tags=["User"])
def profile(user=Depends(current_user)):
    u = users_col.find_one({"_id": ObjectId(user["sub"])})
    if not u: raise HTTPException(404, "User not found")
    u["_id"] = str(u["_id"])
    u.pop("password_hash", None)
    locs = list(saved_col.find({"user_id": user["sub"]}))
    for l in locs: l["_id"] = str(l["_id"])
    hist = list(history_col.find({"user_id": user["sub"]}).sort("created_at", -1).limit(10))
    for h in hist: h["_id"] = str(h["_id"])
    return {"user": u, "saved_locations": locs, "prediction_history": hist}

@app.put("/user/profile", tags=["User"])
def update_profile(req: UpdateProfileReq, user=Depends(current_user)):
    updates = {}
    if req.name         is not None: updates["name"]        = req.name.strip()
    if req.phone        is not None: updates["phone"]       = req.phone.strip()
    if req.city         is not None: updates["city"]        = req.city.strip()
    if req.sms_alerts   is not None: updates["sms_alerts"]  = req.sms_alerts
    if req.email_alerts is not None: updates["email_alerts"]= req.email_alerts
    if not updates:
        return {"message": "Nothing to update."}
    users_col.update_one({"_id": ObjectId(user["sub"])}, {"$set": updates})
    return {"message": "Profile updated successfully!"}

@app.post("/user/save-location", tags=["User"])
def save_loc(req: SaveLocReq, user=Depends(current_user)):
    lat,lon=req.lat,req.lon
    if not lat or not lon:
        try: lat,lon,_=get_coords(req.location_name)
        except: lat,lon=None,None
    saved_col.insert_one({"user_id":user["sub"],"location_name":req.location_name,"lat":lat,"lon":lon,"created_at":datetime.utcnow()})
    return {"message":f"'{req.location_name}' saved!"}

@app.delete("/user/saved-location/{loc_id}", tags=["User"])
def del_loc(loc_id: str, user=Depends(current_user)):
    try:
        result = locations_col.delete_one({"_id": ObjectId(loc_id), "user_id": user["sub"]})
        if result.deleted_count == 0:
            raise HTTPException(404, "Location not found or already removed.")
        return {"message": "Location removed successfully."}
    except Exception as e:
        raise HTTPException(400, f"Error: {str(e)}")

# ══════════════════════════════════════════════════
# ADMIN
# ══════════════════════════════════════════════════

@app.get("/admin/ngos", tags=["Admin"])
def admin_ngos(user=Depends(current_user)):
    if user.get("role")!="admin": raise HTTPException(403,"Admin only")
    ngos=list(ngos_col.find())
    for n in ngos: n["_id"]=str(n["_id"])
    return {"ngos":ngos}

@app.put("/admin/verify-ngo/{ngo_id}", tags=["Admin"])
def verify_ngo(ngo_id: str, user=Depends(current_user)):
    if user.get("role")!="admin": raise HTTPException(403,"Admin only")
    ngos_col.update_one({"_id":ObjectId(ngo_id)},{"$set":{"is_verified":True}})
    return {"message":f"NGO verified!"}

@app.get("/health", tags=["System"])
def health():
    # Test MongoDB connection
    db_status = "connected"
    try:
        client.admin.command("ping")
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "app":          "GeoGuard AI",
        "status":       "running",
        "version":      "2.0.0",
        "models_loaded":list(MODELS.keys()),
        "db_status":    db_status,
        "sms_enabled":  bool(FAST2SMS_KEY),
        "email_enabled":bool(SMTP_USER and SMTP_PASS),
        "time":         datetime.utcnow().isoformat(),
    }

class TestSMSReq(BaseModel):
    phone:   str
    message: str = "GeoGuard AI Test SMS — Backend working correctly!"

@app.post("/test/sms", tags=["System"])
def test_sms(req: TestSMSReq, user=Depends(current_user)):
    """Test SMS sending. Call this from /docs to verify Fast2SMS is working."""
    result = send_sms(req.phone, req.message)
    return {
        "success":     result,
        "phone":       req.phone,
        "sms_enabled": bool(FAST2SMS_KEY),
        "message":     "SMS sent!" if result else
                       ("SMS key not configured — check FAST2SMS_KEY in .env" if not FAST2SMS_KEY
                        else "SMS failed — check Fast2SMS key and account"),
    }

@app.post("/test/email", tags=["System"])
def test_email(to_email: str, user=Depends(current_user)):
    """Test email sending."""
    if not SMTP_USER or not SMTP_PASS:
        return {"success": False, "message": "Email not configured — set SMTP_USER and SMTP_PASS in .env"}
    try:
        send_otp_email(to_email, "123456", "Test User")
        return {"success": True, "message": f"Test email sent to {to_email}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.get("/", tags=["System"])
def root():
    return {"app":"GeoGuard AI v2","docs":"/docs","health":"/health"}


@app.get("/health")
def health():
    return {"status": "running"}
