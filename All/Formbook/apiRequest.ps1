# PowerShell script for getting FormBook hash values from MalwareBazaar
(Invoke-Webrequest -Method POST -Body "query=get_siginfo&signature=FormBook&limit=1000" -Uri https://mb-api.abuse.ch/api/v1/).Content | Out-File -FilePath "C:\path\to\file.json"

$json = (Get-Content "C:\path\to\file.json" -Raw) | ConvertFrom-Json
$json | foreach {
    $_.data | foreach {
        $md5 = $_.md5_hash 
        Write-Output $md5 | Add-Content -Path "C:\path\to\md5.json"
        $sha1 = $_.sha1_hash 
        Write-Output $sha1 | Add-Content -Path "C:\path\to\sha1.json"
        $sha256 = $_.sha256_hash 
        Write-Output $sha256 | Add-Content -Path "C:\path\to\sha256.json"
        $sha384 = $_.sha3_384_hash 
        Write-Output $sha384 | Add-Content -Path "C:\path\to\sha384.json"
    }
}
