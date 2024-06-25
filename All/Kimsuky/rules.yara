import "pe"
rule NikiCert
{
meta:
	description = "Identifies Nexaweb digital certificate used in (likely) Kimsuky campaign."
	author = "@bartblaze, @nsquar3"
	date = "2024-06"
	tlp = "White"
	hash_a = "cca1705d7a85fe45dce9faec5790d498427b3fa8e546d7d7b57f18a925fdfa5d"
	hash_b = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"
	reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"

condition:
	uint16(0) == 0x5A4D and
    for any i in (0 .. pe.number_of_signatures) : (
		pe.signatures[i].serial == "03:15:e1:37:a6:e2:d6:58:f0:7a:f4:54:c6:3a:0a:f2"
    )
}

rule NikiHTTP
{
meta:
	description = "Identifies NikiHTTP, a versatile backdoor by (likely) Kimsuky."
	author = "@bartblaze, @nsquar3"
	date = "2024-06"
	tlp = "White"
	hash_a = "3314b6ea393e180c20db52448ab6980343bc3ed623f7af91df60189fec637744"
	hash_b = "c94a5817fcd6a4ea93d47d70b9f2b175923a8b325234a77f127c945ae8649874"
	reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"

strings:
	$cmd = {4? 8d 0d be 2f 03 00 4? 85 c0 4? 8d 15 8c 2f 03 00}
	$str_1 = "%s%sc %s >%s 2>&1" ascii wide
	$str_2 = "%s%sc %s 2>%s" ascii wide
	$str_3 = "%s:info" ascii wide
	
	//D:\02.data\03.atk-tools\engine\niki\httpSpy\..\bin\httpSpy.pdb
	$pdb_full = "\\02.data\\03.atk-tools\\" ascii wide
	$pdb_httpspy = "\\bin\\httpSpy.pdb" ascii wide
		
	$code = { 0f 57 c0 4? 89 7? ?? 33 c0 c7 4? ?? 68 00 00 00 0f 11 4? ?? c7 4? ?? 01 00 00 00 66 4? 89 7? 00 0f 11 4? ?? 4? 89 4? ?? 0f 11 4? ?? c7 44 ?? ?? 53 71 80 60 0f 11 4? ?? c7 44 ?? ?? 71 79 7c 5c 0f 11 4? ?? c7 44 ?? ?? 6d 80 74 63 0f 11 4? ?? 88 44 ?? ?? 0f 11 4? ?? 0f 1f 44 00 00 }

condition:
	uint16(0) == 0x5A4D and (
	$cmd or (2 of ($str_*)) or
	any of ($pdb_*) or $code
	)
}

rule NikiGo
{
meta:
	description = "Identifies NikiGo, a Go dropper by (likely) Kimsuky."
	author = "@bartblaze, @nsquar3"
	date = "2024-06"
	tlp = "White"
	hash = "000e2926f6e094d01c64ff972e958cd38590299e9128a766868088aa273599c7"
	reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"

strings:
	$go = "Go build ID:"

	$func1 = "main.ParseCommandLine" ascii wide fullword
	$func2 = "main.RunCmd" ascii wide fullword
	$func3 = "main.HttpGet" ascii wide fullword
	$func4 = "main.SelfDel" ascii wide fullword
	$func5 = "main.RandomBytes" ascii wide fullword

	$pdb_src = "%USERPROFILE%\go/src/niki/auxiliary/engine-binder/main.go" ascii wide
	$pdb_path = "/Users/niki/go/src/niki/auxiliary/engine-binder/" ascii wide
	
condition:
	uint16(0) == 0x5A4D and $go and (
	all of ($func*) or
	any of ($pdb*)
	)
}

