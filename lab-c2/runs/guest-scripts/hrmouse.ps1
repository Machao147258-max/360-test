# hrmouse.ps1 - ASCII only. Real mouse click inside the interactive session.
# Coordinates read straight off the 1024x768 capture: the Huorong wizard's primary
# button (the big orange one) is centred near 513,406.
#
# Why this instead of alternatives already tried and measured:
#   vmrun typeKeystrokesInGuest -> "Insufficient permissions in the host operating system"
#   UI Automation               -> NO-BUTTON (the wizard is custom drawn)
#   bare {ENTER}                -> does not activate the button
#   {TAB}{ENTER}                -> focus went to the title-bar X (raised "confirm exit?")
Add-Type -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
[DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, int e);
'@ -Name U -Namespace W

[W.U]::SetCursorPos(513, 406) | Out-Null
Start-Sleep -Milliseconds 500
[W.U]::mouse_event(2, 0, 0, 0, 0)   # LEFTDOWN
Start-Sleep -Milliseconds 100
[W.U]::mouse_event(4, 0, 0, 0, 0)   # LEFTUP
"CLICKED 513,406" | Out-File -Encoding ascii C:\Users\Public\hrmouse_b.txt
