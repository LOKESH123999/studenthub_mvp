@echo off
cd C:\btech_buddy
call .venv\Scripts\activate
cd app
uvicorn main:app --reload

