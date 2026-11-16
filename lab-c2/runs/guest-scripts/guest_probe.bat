@echo off
REM lcs_probe.bat - guest-side probe: identity, network, firewall, Defender, host reachability
REM pushed to C:\Users\Public\lcs_probe.bat and run via runProgramInGuest
set OUT=C:\Users\Public\lcs_probe.txt
(
  echo == identity
  echo COMPUTERNAME=%COMPUTERNAME% USERNAME=%USERNAME% DATE=%DATE% %TIME%
  echo == ipv4
  ipconfig | findstr /C:"IPv4"
  echo == firewall state
  netsh advfirewall show allprofiles state
  echo == defender realtime
  powershell -nop -c "(Get-MpComputerStatus).RealTimeProtectionEnabled"
  echo == defender exclusion count
  powershell -nop -c "((Get-MpPreference).ExclusionPath -join ';')"
  echo == reach host C2 8080
  curl.exe -s -m 5 -o NUL -w "http_code=%%{http_code}" http://192.168.253.1:8080/
  echo.
  echo == tcp raw
  powershell -nop -c "$c=New-Object Net.Sockets.TcpClient;$t=$c.ConnectAsync('192.168.253.1',8080);if($t.Wait(3000) -and $c.Connected){'tcp-ok'}else{'tcp-fail'}"
) > "%OUT%" 2>&1
