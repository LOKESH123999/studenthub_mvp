# BTech Buddy (CSE) — Student Necessaries Automation (MVP)

A lightweight web app to organize **timetable, attendance, tasks/assignments, resources, and coding practice logs** for BTech CSE students.

## Features (MVP)
- ✅ Register/Login (cookie session)
- ✅ Subjects CRUD
- ✅ Timetable (day-wise)
- ✅ Attendance (mark present/absent + % per subject)
- ✅ Tasks / Assignments (due date + priority + done)
- ✅ Resources (links + tags)
- ✅ Coding practice log (DSA/profiles)

## Tech
- FastAPI + Jinja2 templates
- SQLite (single file DB)
- bcrypt password hashing

## Run locally
```bash
cd btech_buddy
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -r requirements.txt

# (Optional) set a secret for session signing
export BTB_SECRET_KEY="change-me-please"

uvicorn app.main:app --reload
```

Open: http://127.0.0.1:8000

## Data storage
A local SQLite DB file is created at:
- `btech_buddy/app/btech_buddy.sqlite3`

## Roadmap ideas (next)
- Notifications (email/WhatsApp/Push)
- Import timetable from CSV
- LMS integrations (Google Classroom/Moodle) via APIs
- Placement tracker (companies, applications, interview notes)
- Contest calendar (Codeforces API) + LeetCode daily plan
- Mobile app (Flutter) consuming `/api/*`

## Security notes
This is a student-friendly MVP (not production hardened). If you deploy publicly, add:
- CSRF protection
- rate limiting
- stronger password policies
- HTTPS + secure cookies
