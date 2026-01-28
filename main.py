from __future__ import annotations

import os
import sqlite3
import math
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "btech_buddy.sqlite3")

# ---------- Database helpers ----------

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT,
            name TEXT NOT NULL,
            credits INTEGER DEFAULT 0,
            target_attendance REAL DEFAULT 75.0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS timetable_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            day_of_week INTEGER NOT NULL, -- 0=Mon .. 6=Sun
            start_time TEXT NOT NULL, -- HH:MM
            end_time TEXT NOT NULL,   -- HH:MM
            location TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            class_date TEXT NOT NULL, -- YYYY-MM-DD
            status TEXT NOT NULL CHECK(status IN ('present','absent')),
            note TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, subject_id, class_date),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject_id INTEGER,
            title TEXT NOT NULL,
            due_at TEXT, -- ISO datetime or YYYY-MM-DD
            priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('low','medium','high')),
            status TEXT NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','done')),
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject_id INTEGER,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            tags TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS coding_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            log_date TEXT NOT NULL, -- YYYY-MM-DD
            platform TEXT NOT NULL,
            problem TEXT NOT NULL,
            difficulty TEXT,
            topic TEXT,
            link TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    conn.commit()
    conn.close()

def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False

# ---------- Auth helpers ----------

def require_user(request: Request) -> Dict[str, Any]:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"id": int(user_id), "name": request.session.get("user_name"), "email": request.session.get("user_email")}

def redirect_if_not_logged_in(request: Request) -> Optional[RedirectResponse]:
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=303)
    return None

# ---------- App ----------

app = FastAPI(title="BTech Buddy (CSE)")

SECRET_KEY = os.getenv("BTB_SECRET_KEY", "dev-secret-change-me")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax")

app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))

@app.on_event("startup")
def _startup() -> None:
    init_db()

# ---------- Common UI routes ----------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    email = email.strip().lower()
    if len(password) < 6:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Password must be at least 6 characters."},
            status_code=400,
        )

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name.strip(), email, hash_password(password), now_iso()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Email already registered. Try logging in."},
            status_code=400,
        )
    finally:
        conn.close()

    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    email = email.strip().lower()
    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password."},
            status_code=400,
        )

    request.session["user_id"] = int(user["id"])
    request.session["user_name"] = user["name"]
    request.session["user_email"] = user["email"]
    return RedirectResponse(url="/dashboard", status_code=303)

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

# ---------- Dashboard ----------

def _weekday_idx(d: date) -> int:
    # Monday=0..Sunday=6
    return (d.weekday())

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir

    user = require_user(request)
    today = date.today()
    dow = _weekday_idx(today)

    conn = get_conn()

    # Today's classes
    classes = conn.execute(
        """
        SELECT t.*, s.name AS subject_name, s.code AS subject_code
        FROM timetable_entries t
        JOIN subjects s ON s.id = t.subject_id
        WHERE t.user_id = ? AND t.day_of_week = ?
        ORDER BY t.start_time
        """,
        (user["id"], dow),
    ).fetchall()

    # Upcoming tasks in next 7 days
    horizon = (datetime.now() + timedelta(days=7)).replace(microsecond=0).isoformat()
    tasks = conn.execute(
        """
        SELECT tasks.*, subjects.name AS subject_name
        FROM tasks
        LEFT JOIN subjects ON subjects.id = tasks.subject_id
        WHERE tasks.user_id = ?
          AND tasks.status = 'todo'
          AND (tasks.due_at IS NULL OR tasks.due_at <= ?)
        ORDER BY
          CASE tasks.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
          tasks.due_at IS NULL,
          tasks.due_at
        LIMIT 10
        """,
        (user["id"], horizon),
    ).fetchall()

    # Attendance summary per subject
    attendance = conn.execute(
        """
        SELECT
            s.id AS subject_id,
            COALESCE(s.code, '') AS subject_code,
            s.name AS subject_name,
            COUNT(a.id) AS total_classes,
            SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END) AS present_classes,
            s.target_attendance AS target_attendance
        FROM subjects s
        LEFT JOIN attendance_records a
            ON a.subject_id = s.id AND a.user_id = s.user_id
        WHERE s.user_id = ?
        GROUP BY s.id
        ORDER BY s.name
        """,
        (user["id"],),
    ).fetchall()

    conn.close()

    def pct(present: int, total: int) -> float:
        return round((present / total) * 100.0, 1) if total else 0.0

    attendance_rows = []
    for row in attendance:
        total = int(row["total_classes"])
        present = int(row["present_classes"] or 0)
        target_pct = float(row["target_attendance"] or 75.0)
        target = (target_pct / 100.0) if target_pct else 0.0

        percentage = pct(present, total)

        safe_absences = 0
        need_attend = 0
        if total > 0 and 0.0 < target < 1.0:
            # How many more classes you can miss and still stay >= target
            safe_absences = max(0, int((present / target) - total))
            # If below target, how many consecutive "present" you need to reach it
            if percentage < target_pct:
                need_attend = int(math.ceil((target * total - present) / (1.0 - target)))

        attendance_rows.append({
            "subject_id": row["subject_id"],
            "subject_code": row["subject_code"],
            "subject_name": row["subject_name"],
            "total_classes": total,
            "present_classes": present,
            "percentage": percentage,
            "target_attendance": target_pct,
            "safe_absences": safe_absences,
            "need_attend": need_attend,
        })

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "today": today.isoformat(),
            "weekday": today.strftime("%A"),
            "classes": classes,
            "tasks": tasks,
            "attendance": attendance_rows,
        },
    )

# ---------- Subjects ----------

@app.get("/subjects", response_class=HTMLResponse)
def subjects_page(request: Request):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir
    user = require_user(request)
    conn = get_conn()
    subjects = conn.execute(
        "SELECT * FROM subjects WHERE user_id = ? ORDER BY name",
        (user["id"],),
    ).fetchall()
    conn.close()
    return templates.TemplateResponse("subjects.html", {"request": request, "user": user, "subjects": subjects})

@app.post("/subjects/add")
def subjects_add(
    request: Request,
    name: str = Form(...),
    code: str = Form(""),
    credits: int = Form(0),
    target_attendance: float = Form(75.0),
):
    user = require_user(request)
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO subjects (user_id, code, name, credits, target_attendance, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user["id"], code.strip(), name.strip(), int(credits), float(target_attendance), now_iso()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/subjects", status_code=303)

@app.post("/subjects/delete")
def subjects_delete(request: Request, subject_id: int = Form(...)):
    user = require_user(request)
    conn = get_conn()
    conn.execute("DELETE FROM subjects WHERE id = ? AND user_id = ?", (int(subject_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/subjects", status_code=303)

# ---------- Timetable ----------

@app.get("/timetable", response_class=HTMLResponse)
def timetable_page(request: Request, day: Optional[int] = None):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir
    user = require_user(request)
    day = _weekday_idx(date.today()) if day is None else int(day)

    conn = get_conn()
    subjects = conn.execute("SELECT id, name, code FROM subjects WHERE user_id = ? ORDER BY name", (user["id"],)).fetchall()
    entries = conn.execute(
        """
        SELECT t.*, s.name AS subject_name, s.code AS subject_code
        FROM timetable_entries t
        JOIN subjects s ON s.id = t.subject_id
        WHERE t.user_id = ? AND t.day_of_week = ?
        ORDER BY t.start_time
        """,
        (user["id"], day),
    ).fetchall()
    conn.close()

    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return templates.TemplateResponse(
        "timetable.html",
        {
            "request": request,
            "user": user,
            "day": day,
            "day_label": days[day],
            "days": list(enumerate(days)),
            "subjects": subjects,
            "entries": entries,
        },
    )

@app.post("/timetable/add")
def timetable_add(
    request: Request,
    subject_id: int = Form(...),
    day_of_week: int = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...),
    location: str = Form(""),
):
    user = require_user(request)
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO timetable_entries
        (user_id, subject_id, day_of_week, start_time, end_time, location, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user["id"], int(subject_id), int(day_of_week), start_time.strip(), end_time.strip(), location.strip(), now_iso()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/timetable?day={int(day_of_week)}", status_code=303)

@app.post("/timetable/delete")
def timetable_delete(request: Request, entry_id: int = Form(...), day: int = Form(...)):
    user = require_user(request)
    conn = get_conn()
    conn.execute("DELETE FROM timetable_entries WHERE id = ? AND user_id = ?", (int(entry_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/timetable?day={int(day)}", status_code=303)

# ---------- Attendance ----------

@app.get("/attendance", response_class=HTMLResponse)
def attendance_page(request: Request):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir
    user = require_user(request)
    conn = get_conn()
    subjects = conn.execute("SELECT id, name, code, target_attendance FROM subjects WHERE user_id = ? ORDER BY name", (user["id"],)).fetchall()
    # Recent records
    recent = conn.execute(
        """
        SELECT a.*, s.name AS subject_name, s.code AS subject_code
        FROM attendance_records a
        JOIN subjects s ON s.id = a.subject_id
        WHERE a.user_id = ?
        ORDER BY a.class_date DESC
        LIMIT 50
        """,
        (user["id"],),
    ).fetchall()

    summary = conn.execute(
        """
        SELECT
            s.id AS subject_id,
            COALESCE(s.code, '') AS subject_code,
            s.name AS subject_name,
            COUNT(a.id) AS total_classes,
            SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END) AS present_classes,
            s.target_attendance AS target_attendance
        FROM subjects s
        LEFT JOIN attendance_records a
            ON a.subject_id = s.id AND a.user_id = s.user_id
        WHERE s.user_id = ?
        GROUP BY s.id
        ORDER BY s.name
        """,
        (user["id"],),
    ).fetchall()

    conn.close()

    def pct(present: int, total: int) -> float:
        return round((present / total) * 100.0, 1) if total else 0.0

    summary_rows = []
    for row in summary:
        total = int(row["total_classes"])
        pres = int(row["present_classes"] or 0)
        target_pct = float(row["target_attendance"] or 75.0)
        target = (target_pct / 100.0) if target_pct else 0.0

        percentage = pct(pres, total)

        safe_absences = 0
        need_attend = 0
        if total > 0 and 0.0 < target < 1.0:
            safe_absences = max(0, int((pres / target) - total))
            if percentage < target_pct:
                need_attend = int(math.ceil((target * total - pres) / (1.0 - target)))

        summary_rows.append({
            "subject_id": row["subject_id"],
            "subject_code": row["subject_code"],
            "subject_name": row["subject_name"],
            "present": pres,
            "total": total,
            "percentage": percentage,
            "target": target_pct,
            "safe_absences": safe_absences,
            "need_attend": need_attend,
        })

    return templates.TemplateResponse(
        "attendance.html",
        {"request": request, "user": user, "subjects": subjects, "recent": recent, "summary": summary_rows, "today": date.today().isoformat()},
    )

@app.post("/attendance/mark")
def attendance_mark(
    request: Request,
    subject_id: int = Form(...),
    class_date: str = Form(...),
    status: str = Form(...),
    note: str = Form(""),
):
    user = require_user(request)
    status = status.strip().lower()
    if status not in {"present", "absent"}:
        raise HTTPException(status_code=400, detail="Invalid status")

    conn = get_conn()
    # Upsert: if same date+subject exists, replace
    conn.execute(
        """
        INSERT INTO attendance_records (user_id, subject_id, class_date, status, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, subject_id, class_date)
        DO UPDATE SET status=excluded.status, note=excluded.note
        """,
        (user["id"], int(subject_id), class_date.strip(), status, note.strip(), now_iso()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/attendance", status_code=303)

@app.post("/attendance/delete")
def attendance_delete(request: Request, record_id: int = Form(...)):
    user = require_user(request)
    conn = get_conn()
    conn.execute("DELETE FROM attendance_records WHERE id = ? AND user_id = ?", (int(record_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/attendance", status_code=303)

# ---------- Tasks ----------

@app.get("/tasks", response_class=HTMLResponse)
def tasks_page(request: Request, show: str = "todo"):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir
    user = require_user(request)
    show = show if show in {"todo", "done", "all"} else "todo"

    conn = get_conn()
    subjects = conn.execute("SELECT id, name, code FROM subjects WHERE user_id = ? ORDER BY name", (user["id"],)).fetchall()

    where = ""
    params: List[Any] = [user["id"]]
    if show == "todo":
        where = "AND status='todo'"
    elif show == "done":
        where = "AND status='done'"

    tasks = conn.execute(
        f"""
        SELECT tasks.*, subjects.name AS subject_name, subjects.code AS subject_code
        FROM tasks
        LEFT JOIN subjects ON subjects.id = tasks.subject_id
        WHERE tasks.user_id = ?
        {where}
        ORDER BY
          CASE tasks.status WHEN 'todo' THEN 0 ELSE 1 END,
          CASE tasks.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
          tasks.due_at IS NULL,
          tasks.due_at DESC
        """,
        params,
    ).fetchall()

    conn.close()
    return templates.TemplateResponse("tasks.html", {"request": request, "user": user, "tasks": tasks, "subjects": subjects, "show": show, "today": date.today().isoformat()})

@app.post("/tasks/add")
def tasks_add(
    request: Request,
    title: str = Form(...),
    subject_id: Optional[int] = Form(None),
    due_at: str = Form(""),
    priority: str = Form("medium"),
):
    user = require_user(request)
    priority = priority.strip().lower()
    if priority not in {"low", "medium", "high"}:
        priority = "medium"

    due_at_val = due_at.strip() or None

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO tasks (user_id, subject_id, title, due_at, priority, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'todo', ?)
        """,
        (user["id"], int(subject_id) if subject_id else None, title.strip(), due_at_val, priority, now_iso()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/tasks", status_code=303)

@app.post("/tasks/toggle")
def tasks_toggle(request: Request, task_id: int = Form(...), next_status: str = Form(...), show: str = Form("todo")):
    user = require_user(request)
    next_status = next_status.strip().lower()
    if next_status not in {"todo", "done"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    conn = get_conn()
    conn.execute("UPDATE tasks SET status=? WHERE id=? AND user_id=?", (next_status, int(task_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/tasks?show={show}", status_code=303)

@app.post("/tasks/delete")
def tasks_delete(request: Request, task_id: int = Form(...), show: str = Form("todo")):
    user = require_user(request)
    conn = get_conn()
    conn.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (int(task_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/tasks?show={show}", status_code=303)

# ---------- Resources ----------

@app.get("/resources", response_class=HTMLResponse)
def resources_page(request: Request):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir
    user = require_user(request)
    conn = get_conn()
    subjects = conn.execute("SELECT id, name, code FROM subjects WHERE user_id = ? ORDER BY name", (user["id"],)).fetchall()
    resources = conn.execute(
        """
        SELECT r.*, s.name AS subject_name, s.code AS subject_code
        FROM resources r
        LEFT JOIN subjects s ON s.id = r.subject_id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
        LIMIT 200
        """,
        (user["id"],),
    ).fetchall()
    conn.close()
    return templates.TemplateResponse("resources.html", {"request": request, "user": user, "subjects": subjects, "resources": resources})

@app.post("/resources/add")
def resources_add(
    request: Request,
    title: str = Form(...),
    url: str = Form(...),
    subject_id: Optional[int] = Form(None),
    tags: str = Form(""),
):
    user = require_user(request)
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO resources (user_id, subject_id, title, url, tags, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user["id"], int(subject_id) if subject_id else None, title.strip(), url.strip(), tags.strip(), now_iso()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/resources", status_code=303)

@app.post("/resources/delete")
def resources_delete(request: Request, resource_id: int = Form(...)):
    user = require_user(request)
    conn = get_conn()
    conn.execute("DELETE FROM resources WHERE id=? AND user_id=?", (int(resource_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/resources", status_code=303)

# ---------- Coding logs ----------

@app.get("/coding", response_class=HTMLResponse)
def coding_page(request: Request):
    redir = redirect_if_not_logged_in(request)
    if redir:
        return redir
    user = require_user(request)
    conn = get_conn()
    logs = conn.execute(
        "SELECT * FROM coding_logs WHERE user_id=? ORDER BY log_date DESC, created_at DESC LIMIT 200",
        (user["id"],),
    ).fetchall()
    conn.close()
    return templates.TemplateResponse("coding.html", {"request": request, "user": user, "logs": logs, "today": date.today().isoformat()})

@app.post("/coding/add")
def coding_add(
    request: Request,
    log_date: str = Form(...),
    platform: str = Form(...),
    problem: str = Form(...),
    difficulty: str = Form(""),
    topic: str = Form(""),
    link: str = Form(""),
):
    user = require_user(request)
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO coding_logs (user_id, log_date, platform, problem, difficulty, topic, link, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user["id"], log_date.strip(), platform.strip(), problem.strip(), difficulty.strip(), topic.strip(), link.strip(), now_iso()),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/coding", status_code=303)

@app.post("/coding/delete")
def coding_delete(request: Request, log_id: int = Form(...)):
    user = require_user(request)
    conn = get_conn()
    conn.execute("DELETE FROM coding_logs WHERE id=? AND user_id=?", (int(log_id), user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/coding", status_code=303)

# ---------- JSON API (optional) ----------

@app.get("/api/me")
def api_me(request: Request):
    user = require_user(request)
    return {"id": user["id"], "name": user["name"], "email": user["email"]}

@app.get("/api/subjects")
def api_subjects(request: Request):
    user = require_user(request)
    conn = get_conn()
    rows = conn.execute("SELECT * FROM subjects WHERE user_id=? ORDER BY name", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/tasks")
def api_tasks(request: Request, status: str = "todo"):
    user = require_user(request)
    status = status if status in {"todo", "done", "all"} else "todo"
    conn = get_conn()
    if status == "all":
        rows = conn.execute("SELECT * FROM tasks WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM tasks WHERE user_id=? AND status=? ORDER BY created_at DESC", (user["id"], status)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
