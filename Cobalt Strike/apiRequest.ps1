# Here is a PowerShell script I used to get the SHA256 hash values from MalwareBazaar
(Invoke-Webrequest -Method POST -Body "query=get_siginfo&signature=CobaltStrike&limit=1000" -Uri https://mb-api.abuse.ch/api/v1/).Content | Out-File -FilePath "C:\path\to\file.json"

$json = (Get-Content "C:\path\to\file.json" -Raw) | ConvertFrom-Json
$json | foreach {
    $_.data | foreach {
        $sha256 = $_.sha256_hash 
        Write-Output $sha256 | Add-Content -Path "C:\path\to\newfile.json"
    }
}
