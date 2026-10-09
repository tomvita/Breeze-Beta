@echo off
rem Double-clicking pcconnect_app.py runs whatever Python owns the .py association;
rem this starts it with Python 3 through the launcher, without a console window.
start "" pyw -3 "%~dp0pcconnect_app.py" %*
