@echo off
REM reach.bat - lean reachability probe (no netsh: it hangs on this guest)
REM every line appends immediately so a force-kill still leaves evidence
set OUT=C:\Users\Public\reach.txt
echo start %TIME% > "%OUT%"
ipconfig | findstr /C:"IPv4" >> "%OUT%" 2>&1
curl.exe -s -m 4 -o NUL -w "http_code=%%{http_code}\n" http://192.168.253.1:8080/ >> "%OUT%" 2>&1
powershell -nop -c "$c=New-Object Net.Sockets.TcpClient;$t=$c.ConnectAsync('192.168.253.1',8080);if($t.Wait(3000) -and $c.Connected){'tcp-ok'}else{'tcp-fail'}" >> "%OUT%" 2>&1
echo done %TIME% >> "%OUT%"
