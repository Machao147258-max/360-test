@echo off
REM hrgo.bat - ASCII only, designed to be launched by an interactive (/it) task so that
REM everything below happens inside the logged-on session.
REM Step 1: start the x64 installer as a child of this session.
REM Step 2: click its primary button deterministically via UI Automation, picking the
REM         button with the largest bounding rectangle (the big install button), instead
REM         of guessing Tab order -- earlier Tab+Enter landed on the title-bar X and
REM         raised the "confirm exit" dialog.
set LOG=C:\Users\Public\hrgo.txt
del "%LOG%" 2>nul
echo == start installer >> "%LOG%"
start "" "C:\Users\Public\huorong64.exe"
ping -n 11 127.0.0.1 >nul
echo == UIA invoke largest button >> "%LOG%"
powershell -nop -c "Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes; $ae=[System.Windows.Automation.AutomationElement]; $p=Get-Process huorong64 -EA SilentlyContinue | Select-Object -First 1; if(-not $p){ 'NO-PROC' | Out-File -Encoding ascii C:\Users\Public\uia.txt; exit }; $cond=New-Object System.Windows.Automation.PropertyCondition($ae::ProcessIdProperty,$p.Id); $win=$ae::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children,$cond); if(-not $win){ 'NO-WIN' | Out-File -Encoding ascii C:\Users\Public\uia.txt; exit }; $bc=New-Object System.Windows.Automation.PropertyCondition($ae::ControlTypeProperty,[System.Windows.Automation.ControlType]::Button); $btns=$win.FindAll([System.Windows.Automation.TreeScope]::Descendants,$bc); $best=$null; $area=0; foreach($b in $btns){ $r=$b.Current.BoundingRectangle; $a=$r.Width*$r.Height; if($a -gt $area){ $area=$a; $best=$b } }; if($best){ $best.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); ('INVOKED area=' + [int]$area + ' buttons=' + $btns.Count) | Out-File -Encoding ascii C:\Users\Public\uia.txt } else { 'NO-BUTTON' | Out-File -Encoding ascii C:\Users\Public\uia.txt }" >> "%LOG%" 2>&1
ping -n 40 127.0.0.1 >nul
echo == install state after 40s >> "%LOG%"
sc query Sysdiag >> "%LOG%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%LOG%" 2>&1
tasklist | findstr /I "huorong Hips sysdiag usysdiag" >> "%LOG%" 2>&1
echo == end %TIME% >> "%LOG%"
