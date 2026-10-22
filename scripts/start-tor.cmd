@echo off
REM Starts the Tor daemon that arms T3MP3ST's outbound dark-web lanes.
REM Exposes SOCKS on 127.0.0.1:9050 only (SocksPolicy rejects everything else).
REM
REM IMPORTANT: tor.exe is launched through WMI (Win32_Process.Create), NOT via
REM `start` or Start-Process with output redirection. Both of those were measured
REM dying with their parent shell -- the task runner kills the process tree when
REM the launching command exits. WMI creates the process outside that tree, and
REM it was verified still alive from a fresh shell afterwards.
REM
REM Idempotent: does nothing if SOCKS is already answering.

set TOR_BIN=C:\Temp\TorBrowser\Browser\TorBrowser\Tor\tor.exe
set TORRC=C:\Temp\TorBrowser\t3mp3st-data\torrc

if not exist "%TOR_BIN%" (
  echo tor.exe not found at %TOR_BIN%
  echo Re-extract with: tb-portable.exe /S /D=C:\Temp\TorBrowser
  exit /b 1
)

powershell -NoProfile -Command "if ((Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue).TcpTestSucceeded) { Write-Output 'Tor SOCKS already live on 9050 - nothing to do'; exit 0 } else { exit 1 }"
if %errorlevel%==0 exit /b 0

powershell -NoProfile -Command "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='\"%TOR_BIN%\" -f %TORRC%'}; Write-Output ('tor.exe started, pid=' + $r.ProcessId)"
if %errorlevel% neq 0 (
  echo Failed to start tor.exe
  exit /b 1
)

echo Bootstrapping takes 30-90s. Verify with:
echo   curl http://127.0.0.1:3333/api/osint/tor-status
echo Log: C:\Temp\TorBrowser\t3mp3st-data\tor.log