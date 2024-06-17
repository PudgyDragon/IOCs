# PowerShell script to get hash values from MalwareBazaar for AgentTesla

(Invoke-Webrequest -Method POST -Body "query=get_siginfo&signature=AgentTesla&limit=1000" -Uri https://mb-api.abuse.ch/api/v1/).Content | Out-File -FilePath "C:\path\to\file.json"

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

# Powershell script for getting Agent Tesla IOCs from ThreatFox
(Invoke-Webrequest -Method POST -Body '{ "query": "malwareinfo", "malware": "AgentTesla", "limit": 1000 }' -Uri https://threatfox-api.abuse.ch/api/v1/).Content | Out-File -FilePath "C:\path\to\file.json"

$json = (Get-Content "C:\path\to\file.json" -Raw) | ConvertFrom-Json
$json | foreach {
    $_.data | foreach {
        $ioc = $_.ioc
        $type = $_.ioc_type
        if ($type -eq "domain")
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc_domain.json"
        }    
        elseif ($type -eq "ip:port")
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc_ip.json"
        }
        elseif ($type -eq "url")
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc_url.json"
        }
        elseif ($type -eq "md5")
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc_md5.json"
        }
        elseif ($type -eq "sha1")
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc_sha1.json"
        }
        elseif ($type -eq "sha256")
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc_sha256.json"
        }
        else
        {
            Write-Output $ioc | Add-Content -Path "C:\path\to\ioc.json"
        }
    }
}
