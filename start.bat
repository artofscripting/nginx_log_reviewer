@echo off
echo Starting NGINX Access Log Analyzer...
echo.
echo Make sure you have the following log files in this directory:
echo - access.log (current log file)
echo - access.log-YYYYMMDD (archived log files)
echo - access.log-YYYYMMDD.gz (compressed archived log files)
echo.
echo Starting the web application...
C:\Users\ArtOf\PycharmProjects\NGINX\.venv\Scripts\python.exe app.py
pause