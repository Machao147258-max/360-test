# lcs_probe.ps1 - 靶机侧连通性探针: 克隆机(192.168.253.140) -> 宿主机 C2
# 用法(宿主): vmctl.ps1 ... -push <本文件> C:\Users\Public\lcs_probe.ps1
#             vmctl.ps1 ... -script "powershell -nop -ExecutionPolicy Bypass -File C:\Users\Public\lcs_probe.ps1"
#             vmctl.ps1 ... -pull C:\Users\Public\lcs_probe.txt <本机路径>
$out = 'C:\Users\Public\lcs_probe.txt'
$res = @()
$res += "host=$(hostname) user=$env:USERNAME wallet=$([Environment]::UserInteractive)"
foreach ($ip in @('192.168.253.1', '192.168.253.2')) {
    try {
        $c = New-Object Net.Sockets.TcpClient
        $c.Connect($ip, 8080)
        $res += "TCP $ip:8080 OK"
        $c.Close()
    } catch {
        $res += "TCP $ip:8080 FAIL: $($_.Exception.Message)"
    }
}
try {
    $r = Invoke-WebRequest 'http://192.168.253.1:8080/' -UseBasicParsing -TimeoutSec 5
    $res += "HTTP 192.168.253.1:8080 -> $($r.StatusCode)"
} catch {
    $res += "HTTP FAIL: $($_.Exception.Message)"
}
$res | Out-File -Encoding ascii $out
