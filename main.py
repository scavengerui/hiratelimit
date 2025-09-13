from fastapi import FastAPI, Form, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from bs4 import BeautifulSoup
import requests
from io import BytesIO
import logging
import os
import secrets
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

# ------------------ LOGGING ------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="TimeTable & Attendance Backend", version="3.0.0")

@app.on_event("startup")
async def startup_event():
    logger.info("✅ FastAPI app starting...")
    logger.info(f"Environment: PORT={os.getenv('PORT', '8080')}")

# ------------------ CORS ------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Session-ID"],  # Expose the custom header
)

# ------------------ ALLOWED CLOUDFLARE IP RANGES ------------------
ALLOWED_IPV4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]
ALLOWED_IPV6 = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

allowed_networks = [ip_network(cidr) for cidr in ALLOWED_IPV4 + ALLOWED_IPV6]

def verify_cloudflare_ip(request: Request):
    client_ip = request.client.host
    ip_obj = ip_address(client_ip)

    if not any(ip_obj in net for net in allowed_networks):
        logger.warning(f"❌ Blocked request from IP: {client_ip}")
        raise HTTPException(status_code=403, detail="Access forbidden: IP not allowed")
    logger.info(f"✅ Allowed request from Cloudflare IP: {client_ip}")

# ------------------ HEALTH ------------------
@app.get("/", dependencies=[Depends(verify_cloudflare_ip)])
def health():
    return {"message": "Backend running ✅", "status": "healthy"}

# ------------------ CAPTCHA STORE ------------------
captcha_sessions = {}

def cleanup_expired_sessions():
    try:
        current_time = datetime.now()
        expired_sessions = []
        for session_id, data in captcha_sessions.items():
            if current_time - data["created_at"] > timedelta(minutes=10):
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del captcha_sessions[session_id]

        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    except Exception as e:
        logger.error(f"Error cleaning up sessions: {e}")

# ------------------ CAPTCHA ROUTE ------------------
@app.get("/get-captcha", dependencies=[Depends(verify_cloudflare_ip)])
def get_captcha():
    cleanup_expired_sessions()
    try:
        session = requests.Session()
        base_url = "https://newerp.kluniversity.in"
        login_url = f"{base_url}/index.php?r=site%2Flogin"
        headers = {"User-Agent": "Mozilla/5.0"}

        logger.info("Fetching login page and CSRF token...")
        res = session.get(login_url, headers=headers, timeout=30)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        csrf_meta = soup.find("meta", {"name": "csrf-token"})
        if not csrf_meta:
            raise HTTPException(status_code=500, detail="Failed to get CSRF token")
        csrf = csrf_meta["content"]

        logger.info("Triggering CAPTCHA with a dummy request...")
        dummy_data = {"_csrf": csrf, "LoginForm[username]": "", "LoginForm[password]": ""}
        res_post = session.post(login_url, data=dummy_data, headers=headers, timeout=30)
        res_post.raise_for_status()
        soup_post = BeautifulSoup(res_post.text, "html.parser")

        captcha_img_tag = soup_post.find("img", src=lambda x: x and "r=site%2Fcaptcha" in x)
        if not captcha_img_tag:
            raise HTTPException(status_code=500, detail="CAPTCHA image not found after trigger.")

        captcha_url = base_url + captcha_img_tag["src"].replace("&amp;", "&")
        logger.info(f"Fetching CAPTCHA from: {captcha_url}")
        captcha_response = session.get(captcha_url, timeout=30)
        captcha_response.raise_for_status()

        session_id = secrets.token_urlsafe(16)
        captcha_sessions[session_id] = {
            "session": session,
            "csrf": csrf,
            "created_at": datetime.now()
        }
        logger.info(f"Session created with ID: {session_id[:8]}...")

        response = StreamingResponse(BytesIO(captcha_response.content), media_type="image/jpeg")
        response.headers["X-Session-ID"] = session_id
        return response

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error in get_captcha: {e}")
        raise HTTPException(status_code=500, detail="Network error while fetching CAPTCHA")
    except Exception as e:
        logger.error(f"Unexpected error in get_captcha: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

# ------------------ FETCH TIMETABLE ------------------
@app.post("/fetch-timetable", dependencies=[Depends(verify_cloudflare_ip)])
def fetch_timetable(
    username: str = Form(...),
    password: str = Form(...),
    captcha: str = Form(...),
    session_id: str = Form(...),
    academic_year_code: str = Form(default="19"),
    semester_id: str = Form(default="1")
):
    if session_id not in captcha_sessions:
        raise HTTPException(status_code=400, detail="Invalid or expired session.")
    session_data = captcha_sessions[session_id]
    session = session_data["session"]
    csrf = session_data["csrf"]
    base_url = "https://newerp.kluniversity.in"
    login_url = f"{base_url}/index.php?r=site%2Flogin"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        login_payload = {
            "_csrf": csrf,
            "LoginForm[username]": username,
            "LoginForm[password]": password,
            "LoginForm[captcha]": captcha,
        }
        login_response = session.post(login_url, data=login_payload, headers=headers, timeout=30)
        login_response.raise_for_status()
        if "Logout" not in login_response.text:
            raise HTTPException(status_code=400, detail="Invalid credentials or captcha")
        logger.info(f"Fetching timetable for user: {username}")
        tt_url = f"{base_url}/index.php?r=timetables%2Funiversitymasteracademictimetableview%2Findividualstudenttimetableget&UniversityMasterAcademicTimetableView%5Bacademicyear%5D={academic_year_code}&UniversityMasterAcademicTimetableView%5Bsemesterid%5D={semester_id}"
        tt_response = session.get(tt_url, headers=headers, timeout=30)
        tt_response.raise_for_status()
        soup_tt = BeautifulSoup(tt_response.text, "html.parser")
        table = soup_tt.find("table")
        if not table:
            raise HTTPException(status_code=404, detail="Timetable not found")
        thead = table.find("thead")
        headers = [th.text.strip() for th in thead.find_all("th")][1:]
        tbody = table.find("tbody")
        timetable = {}
        for row in tbody.find_all("tr"):
            cols = row.find_all("td")
            day = cols[0].text.strip()
            slots = [td.text.strip() for td in cols[1:]]
            timetable[day] = dict(zip(headers, slots))
        return {"success": True, "timetable": timetable}
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error in fetch_timetable: {e}")
        raise HTTPException(status_code=500, detail="Network error while fetching timetable")
    except Exception as e:
        logger.error(f"Unexpected error in fetch_timetable: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if session_id in captcha_sessions:
            del captcha_sessions[session_id]

# ------------------ FETCH ATTENDANCE ------------------
@app.post("/fetch-attendance", dependencies=[Depends(verify_cloudflare_ip)])
def fetch_attendance(
    username: str = Form(...),
    password: str = Form(...),
    captcha: str = Form(...),
    session_id: str = Form(...),
    academic_year_code: str = Form(...),
    semester_id: str = Form(...)
):
    if session_id not in captcha_sessions:
        raise HTTPException(status_code=400, detail="Invalid or expired session. Please refresh and try again.")
    session_data = captcha_sessions[session_id]
    session = session_data["session"]
    csrf = session_data["csrf"]
    base_url = "https://newerp.kluniversity.in"
    login_url = f"{base_url}/index.php?r=site%2Flogin"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        login_payload = {
            "_csrf": csrf,
            "LoginForm[username]": username,
            "LoginForm[password]": password,
            "LoginForm[captcha]": captcha,
        }
        login_response = session.post(login_url, data=login_payload, headers=headers, timeout=30)
        login_response.raise_for_status()
        if "Logout" not in login_response.text:
            raise HTTPException(status_code=400, detail="Invalid credentials or captcha")
        logger.info(f"Login successful for user: {username}")
        attendance_url = f"{base_url}/index.php?r=studentattendance%2Fstudentdailyattendance%2Fcourselist"
        post_login_soup = BeautifulSoup(login_response.text, "html.parser")
        post_login_csrf_meta = post_login_soup.find("meta", {"name": "csrf-token"})
        if not post_login_csrf_meta:
            raise HTTPException(status_code=500, detail="Could not find CSRF token on post-login page.")
        post_login_csrf = post_login_csrf_meta["content"]
        attendance_payload = {
            "_csrf": post_login_csrf,
            "DynamicModel[academicyear]": academic_year_code,
            "DynamicModel[semesterid]": semester_id,
        }
        attendance_response = session.post(attendance_url, data=attendance_payload, headers=headers, timeout=30)
        attendance_response.raise_for_status()
        attendance_soup = BeautifulSoup(attendance_response.text, "html.parser")
        container = attendance_soup.find("div", class_="grid-view")
        if not container:
            raise HTTPException(status_code=404, detail="Could not find the attendance data container on the page.")
        table = container.find("table")
        if not table:
            raise HTTPException(status_code=404, detail="Could not find the attendance table within the container.")
        table_headers = [th.text.strip() for th in table.find("thead").find_all("th")]
        attendance_data = []
        for row in table.find("tbody").find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue
            row_data = {table_headers[i]: cells[i].text.strip() for i in range(len(cells))}
            attendance_data.append(row_data)
        if not attendance_data:
            return {"success": True, "message": "No attendance data found for the selected period.", "attendance": []}
        return {"success": True, "attendance": attendance_data}
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during attendance fetch: {e}")
        raise HTTPException(status_code=500, detail="A network error occurred.")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal server error occurred.")
    finally:
        if session_id in captcha_sessions:
            del captcha_sessions[session_id]
            logger.info(f"Session {session_id[:8]}... cleaned up.")
