rule Linux_Trojan_Gafgyt_28a2fe0c {
    meta:
        author = "Elastic Security"
        id = "28a2fe0c-eed5-4c79-81e6-3b11b73a4ebd"
        fingerprint = "a2c6beaec18ca876e8487c11bcc7a29279669588aacb7d3027d8d8df8f5bcead"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Gafgyt"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }
    condition:
        all of them
}

rule Gafgyt_Botnet_hoho : MALW
{
meta:
description = "Gafgyt Trojan"
author = "Joan Soriano / @joanbtl"
date = "2017-05-25"
version = "1.0"
MD5 = "369c7c66224b343f624803d595aa1e09"
SHA1 = "54519d2c124cb536ed0ddad5683440293d90934f"

    strings:
            $s1 = "PING"
            $s2 = "PRIVMSG"
            $s3 = "Remote IRC Bot"
            $s4 = "23.95.43.182"
    condition:
            $s1 and $s2 and $s3 and $s4
}
