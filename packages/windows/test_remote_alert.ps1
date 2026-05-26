$body = @{
    severity = "CRITICAL"
    description = "Intrusion detectada en nodo remoto Windows 192.168.125.148"
    src_ip = "192.168.125.148"
    agent_name = "clean-remote-pc"
    mitre_tactics = @("Execution")
    mitre_techniques = @("User Execution")
    rule_level = 14
} | ConvertTo-Json -Compress

Write-Host "Sending mock alert to remote gateway at http://192.168.125.148:8080/api/alerts/webhook..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "http://192.168.125.148:8080/api/alerts/webhook" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10
    $response | Format-Table -AutoSize
    Write-Host "Alert successfully injected!" -ForegroundColor Green
} catch {
    Write-Host "Error sending alert: $_" -ForegroundColor Red
    Write-Host "`nPlease verify that:" -ForegroundColor Yellow
    Write-Host "1. The CybersecGateway service is running on the remote PC (192.168.125.148)." -ForegroundColor Yellow
    Write-Host "2. You have executed the firewall rule to open port 8080 on the remote PC:" -ForegroundColor Yellow
    Write-Host "   New-NetFirewallRule -DisplayName 'Cybersec Gateway Port 8080' -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow" -ForegroundColor Yellow
}
