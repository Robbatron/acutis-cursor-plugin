: << 'CMDBLOCK'
@echo off
REM Acutis hook launcher that is both a Windows batch file and a POSIX sh
REM script, for clients that start hook commands through a shell: Cursor
REM (PowerShell on Windows, which cannot run the extensionless scripts/hook)
REM and VS Code. Usage: hook.cmd <claude|codex|cursor> <event>
REM Windows: cmd skips the first line as a label and runs hook.exe here.
REM macOS and Linux: ":" swallows this block and the sh part runs below.
"%~dp0hook.exe" %*
exit /b %ERRORLEVEL%
CMDBLOCK
exec "$(dirname -- "$0")/hook" "$@"
