rule NetMonitor 
{
  meta:
    author = "FBI"
    source = "FBI"
    sharing = "TLP:CLEAR"
    status = "RELEASED"
    description = "Yara rule to detect NetMonitor.exe"
    category = "MALWARE"
    creation_date = "2023-05-05"
  strings:
    $rc4key = {11 4b 8c dd 65 74 22 c3}
    $op0 = {c6 [3] 00 00 05 c6 [3] 00 00 07 83 [3] 00 00 05 0f 85 [4] 83 [3] 00 00 01 75 ?? 8b [2] 4c 8d [2] 4c 8d [3] 00 00 48 8d [3] 00 00 48 8d [3] 00 00 48 89 [3] 48 89 ?? e8}
  condition:
    uint16(0) == 0x5A4D
    and filesize < 50000
    and any of them
}
