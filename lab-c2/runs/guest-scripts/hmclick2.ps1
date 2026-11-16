# hmclick2.ps1 - ASCII only, runs inside the interactive session.
# Decisive experiment: does synthetic mouse input reach this window at all?
#   1) click the licence checkbox (approx 226,540) and capture
#   2) click the big install button (approx 513,406) and capture
# If the checkbox visibly toggles, mouse input works and the earlier button click was
# merely off-target; if nothing changes, synthetic input is not reaching the desktop.
Add-Type -AssemblyName System.Drawing
Add-Type -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
[DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, int e);
'@ -Name U -Namespace W

function Click([int]$x, [int]$y) {
    [W.U]::SetCursorPos($x, $y) | Out-Null
    Start-Sleep -Milliseconds 400
    [W.U]::mouse_event(2, 0, 0, 0, 0)
    Start-Sleep -Milliseconds 100
    [W.U]::mouse_event(4, 0, 0, 0, 0)
    Start-Sleep -Milliseconds 700
}

function Shot([string]$path) {
    $b = New-Object System.Drawing.Bitmap 1024, 768
    $g = [System.Drawing.Graphics]::FromImage($b)
    $g.CopyFromScreen(0, 0, 0, 0, $b.Size)
    $b.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $b.Dispose()
}

Shot 'C:\Users\Public\hm_before.png'
Click 226 540      # licence checkbox
Shot 'C:\Users\Public\hm_after_checkbox.png'
Click 513 406      # big install button
Shot 'C:\Users\Public\hm_after_button.png'
"EXPERIMENT DONE" | Out-File -Encoding ascii C:\Users\Public\hm_result.txt
