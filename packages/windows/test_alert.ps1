$body = @{
    severity = "CRITICAL"
    description = "Intrusion detectada en terminal Windows (MSI Testing)"
    src_ip = "192.168.1.120"
    agent_name = "cybersec-windows-agent"
    mitre_tactics = @("Execution")
    mitre_techniques = @("User Execution")
    rule_level = 12
} | ConvertTo-Json -Compress

Invoke-RestMethod -Uri "http://localhost:8080/api/alerts/webhook" -Method Post -ContentType "application/json" -Body $body
