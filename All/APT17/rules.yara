import "hash"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_RDP {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination manipulating RDP / Terminal Services"
    strings:
        // Beginning with Windows Server 2008 and Windows Vista, this policy no longer has any effect
        // https://docs.microsoft.com/en-us/windows/win32/msi/enableadmintsremote
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii wide nocase
        $k1 = "EnableAdminTSRemote" fullword ascii wide nocase
        // Whether basic Terminal Services functions are enabled
        $r2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k2 = "TSEnabled" fullword ascii wide nocase
        // Terminal Device Driver Attributes
        // Terminal Services hosts and configurations
        $r3 = "SYSTEM\\CurrentControlSet\\Services\\TermDD" ascii wide nocase
        $r4 = "SYSTEM\\CurrentControlSet\\Services\\TermService" ascii wide nocase
        $k3 = "Start" fullword ascii wide nocase
        // Allows or denies connecting to Terminal Services
        $r5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k4 = "fDenyTSConnections" fullword ascii wide nocase
        // RDP Port Number
        $r6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii wide nocase
        $r7 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii wide nocase
        $r8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide nocase
        $k5 = "PortNumber" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 5 of ($r*) and 3 of ($k*)
}
rule Windows_API_Function
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects the presence of a number of Windows API functionality often seen within embedded executables. When this signature alerts on an executable, it is not an indication of malicious behavior. However, if seen firing in other file types, deeper investigation may be warranted."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "http://en.wikipedia.org/wiki/Windows_API"
        labs_reference = "https://labs.inquest.net/dfi/hash/f9b62b2aee5937e4d7f33f04f52ad5b05c4a1ccde6553e18909d2dc0cb595209"
        labs_pivot     = "N/A"
        samples        = "f9b62b2aee5937e4d7f33f04f52ad5b05c4a1ccde6553e18909d2dc0cb595209"

	strings:
			$magic  = "INQUEST-PII="
	$api_00 = "LoadLibraryA" nocase ascii wide
    $api_01 = "ShellExecuteA" nocase ascii wide
    $api_03 = "GetProcAddress" nocase ascii wide
    $api_04 = "GetVersionExA" nocase ascii wide
    $api_05 = "GetModuleHandleA" nocase ascii wide
    $api_06 = "OpenProcess" nocase ascii wide
    $api_07 = "GetWindowsDirectoryA" nocase ascii wide
    $api_08 = "lstrcatA" nocase ascii wide
    $api_09 = "GetSystemDirectoryA" nocase ascii wide
    $api_10 = "WriteFile" nocase ascii wide
    $api_11 = "ReadFile" nocase ascii wide
    $api_12 = "GetFileSize" nocase ascii wide
    $api_13 = "CreateFileA" nocase ascii wide
    $api_14 = "DeleteFileA" nocase ascii wide
    $api_15 = "CreateProcessA" nocase ascii wide
    $api_16 = "GetCurrentProcessId" nocase ascii wide
    $api_17 = "RegOpenKeyExA" nocase ascii wide
    $api_18 = "GetStartupInfoA" nocase ascii wide
    $api_19 = "CreateServiceA" nocase ascii wide
    $api_20 = "CopyFileA" nocase ascii wide
    $api_21 = "GetModuleFileNameA" nocase ascii wide
    $api_22 = "IsBadReadPtr" nocase ascii wide
    $api_23 = "CreateFileW" nocase ascii wide
    $api_24 = "SetFilePointer" nocase ascii wide
    $api_25 = "VirtualAlloc" nocase ascii wide
    $api_26 = "AdjustTokenPrivileges" nocase ascii wide
    $api_27 = "CloseHandle" nocase ascii wide
    $api_28 = "CreateFile" nocase ascii wide
    $api_29 = "GetProcAddr" nocase ascii wide
    $api_30 = "GetSystemDirectory" nocase ascii wide
    $api_31 = "GetTempPath" nocase ascii wide
    $api_32 = "GetWindowsDirectory" nocase ascii wide
    $api_33 = "IsBadReadPtr" nocase ascii wide
    $api_34 = "IsBadWritePtr" nocase ascii wide
    $api_35 = "LoadLibrary" nocase ascii wide
    $api_36 = "ReadFile" nocase ascii wide
    $api_37 = "SetFilePointer" nocase ascii wide
    $api_38 = "ShellExecute" nocase ascii wide
    $api_39 = "UrlDownloadToFile" nocase ascii wide
    $api_40 = "WinExec" nocase ascii wide
    $api_41 = "WriteFile" nocase ascii wide
    $api_42 = "StartServiceA" nocase ascii wide
    $api_43 = "VirtualProtect" nocase ascii wide
	condition:
			any of ($api*)
    and not $magic in (filesize-30..filesize)
    and not 
    (
        /* trigger = 'MZ' */
        (uint16be(0x0) == 0x4d5a)
        or
        /* trigger = 'ZM' */
        (uint16be(0x0) == 0x5a4d)
        or
        /* trigger = 'PE' */
        (uint16be(uint32(0x3c)) == 0x5045)
    )
}
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_RDP {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination manipulating RDP / Terminal Services"
    strings:
        // Beginning with Windows Server 2008 and Windows Vista, this policy no longer has any effect
        // https://docs.microsoft.com/en-us/windows/win32/msi/enableadmintsremote
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii wide nocase
        $k1 = "EnableAdminTSRemote" fullword ascii wide nocase
        // Whether basic Terminal Services functions are enabled
        $r2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k2 = "TSEnabled" fullword ascii wide nocase
        // Terminal Device Driver Attributes
        // Terminal Services hosts and configurations
        $r3 = "SYSTEM\\CurrentControlSet\\Services\\TermDD" ascii wide nocase
        $r4 = "SYSTEM\\CurrentControlSet\\Services\\TermService" ascii wide nocase
        $k3 = "Start" fullword ascii wide nocase
        // Allows or denies connecting to Terminal Services
        $r5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k4 = "fDenyTSConnections" fullword ascii wide nocase
        // RDP Port Number
        $r6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii wide nocase
        $r7 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii wide nocase
        $r8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide nocase
        $k5 = "PortNumber" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 5 of ($r*) and 3 of ($k*)
}
rule Sig_RemoteAdmin_1 {
   meta:
      description = "Detects strings from well-known APT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-12-03"
      score = 45
      id = "da55084c-ec1f-5800-a614-189dce7b5820"
   strings:
      $ = "Radmin, Remote Administrator" wide
      $ = "Radmin 3.0" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}
rule INDICATOR_TOOL_LTM_CompiledImpacket {
    meta:
        author = "ditekSHen"
        description = "Detects executables of compiled Impacket's python scripts"
    strings:
        $s1 = "impacket(" fullword ascii
        $s2 = "impacket.dcerpc(" fullword ascii
        $s3 = "impacket.krb5(" fullword ascii
        $s4 = "impacket.smb(" fullword ascii
        $s5 = "impacket.smb3(" fullword ascii
        $s6 = "impacket.winregistry(" fullword ascii
        $s7 = "impacket.ntlm(" fullword ascii
        $m1 = "inspect(" fullword ascii
        $m2 = "pickle(" fullword ascii
        $m3 = "spsexec" fullword ascii
        $m4 = "schecker" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (3 of ($m*) and 1 of ($s*)))
}
rule PyInstaller
{
    meta:
        id = "6Pyq57uDDAEHbltmbp7xRT"
        fingerprint = "ae849936b19be3eb491d658026b252c2f72dcb3c07c6bddecb7f72ad74903eee"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2023-12-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies executable converted using PyInstaller. This rule by itself does NOT necessarily mean the detected file is malicious."
        category = "INFO"

    strings:
        $ = "pyi-windows-manifest-filename" ascii wide
        $ = "pyi-runtime-tmpdir" ascii wide
        $ = "PyInstaller: " ascii wide

    condition:
        uint16(0)==0x5a4d and any of them or ( for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type==pe.RESOURCE_TYPE_ICON and hash.md5(pe.resources[i].offset,pe.resources[i].length)=="20d36c0a435caad0ae75d3e5f474650c"))
}
rule win_typehash_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.typehash."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.typehash"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 83e11f 8b0485e03d4100 8d04c8 eb05 b8???????? f6400420 740d }
            // n = 7, score = 100
            //   83e11f               | and                 ecx, 0x1f
            //   8b0485e03d4100       | mov                 eax, dword ptr [eax*4 + 0x413de0]
            //   8d04c8               | lea                 eax, [eax + ecx*8]
            //   eb05                 | jmp                 7
            //   b8????????           |                     
            //   f6400420             | test                byte ptr [eax + 4], 0x20
            //   740d                 | je                  0xf

        $sequence_1 = { c3 8bc8 83e01f c1f905 8b0c8de03d4100 8a44c104 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8de03d4100       | mov                 ecx, dword ptr [ecx*4 + 0x413de0]
            //   8a44c104             | mov                 al, byte ptr [ecx + eax*8 + 4]

        $sequence_2 = { e8???????? 6a01 8d4c2450 c68424cc00000001 e8???????? bf???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d4c2450             | lea                 ecx, [esp + 0x50]
            //   c68424cc00000001     | mov                 byte ptr [esp + 0xcc], 1
            //   e8????????           |                     
            //   bf????????           |                     

        $sequence_3 = { 8944240c c744241004000000 7460 8b2d???????? 8b3d???????? }
            // n = 5, score = 100
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   c744241004000000     | mov                 dword ptr [esp + 0x10], 4
            //   7460                 | je                  0x62
            //   8b2d????????         |                     
            //   8b3d????????         |                     

        $sequence_4 = { c1f805 c1e603 8d1c85e03d4100 8b0485e03d4100 03c6 8a5004 }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   c1e603               | shl                 esi, 3
            //   8d1c85e03d4100       | lea                 ebx, [eax*4 + 0x413de0]
            //   8b0485e03d4100       | mov                 eax, dword ptr [eax*4 + 0x413de0]
            //   03c6                 | add                 eax, esi
            //   8a5004               | mov                 dl, byte ptr [eax + 4]

        $sequence_5 = { 50 51 6813000020 56 c744242000000000 c744242404000000 ffd7 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   6813000020           | push                0x20000013
            //   56                   | push                esi
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   c744242404000000     | mov                 dword ptr [esp + 0x24], 4
            //   ffd7                 | call                edi

        $sequence_6 = { 03c8 3bc1 7d1e 8d1440 2bc8 8d1495e8294100 832200 }
            // n = 7, score = 100
            //   03c8                 | add                 ecx, eax
            //   3bc1                 | cmp                 eax, ecx
            //   7d1e                 | jge                 0x20
            //   8d1440               | lea                 edx, [eax + eax*2]
            //   2bc8                 | sub                 ecx, eax
            //   8d1495e8294100       | lea                 edx, [edx*4 + 0x4129e8]
            //   832200               | and                 dword ptr [edx], 0

        $sequence_7 = { 3bf3 7505 be???????? 8b54242c 8b442430 8bcf 55 }
            // n = 7, score = 100
            //   3bf3                 | cmp                 esi, ebx
            //   7505                 | jne                 7
            //   be????????           |                     
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
            //   8bcf                 | mov                 ecx, edi
            //   55                   | push                ebp

        $sequence_8 = { 837d1805 7538 837d1000 7508 8bb6b42b4100 }
            // n = 5, score = 100
            //   837d1805             | cmp                 dword ptr [ebp + 0x18], 5
            //   7538                 | jne                 0x3a
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   7508                 | jne                 0xa
            //   8bb6b42b4100         | mov                 esi, dword ptr [esi + 0x412bb4]

        $sequence_9 = { e8???????? 68???????? 8d45c8 c745c8e4e74000 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   c745c8e4e74000       | mov                 dword ptr [ebp - 0x38], 0x40e7e4
            //   50                   | push                eax

    condition:
        7 of them and filesize < 180224
}
rule MAL_Winnti_BR_Report_MockingJay {
   meta:
      description = "Detects Winnti samples"
      author = "@br_data repo"
      reference = "https://github.com/br-data/2019-winnti-analyse"
      date = "2019-07-24"
      id = "9aff9d65-3827-59de-9dc3-38f227155d3d"
  strings:
    $load_magic = { C7 44 ?? ?? FF D8 FF E0 }
    $iter = { E9 EA EB EC ED EE EF F0 }
    $jpeg = { FF D8 FF E0 00 00 00 00 00 00 }
  condition:
    uint16(0) == 0x5a4d and
      $jpeg and
      ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and
      for any i in (1..#jpeg): ( uint8(@jpeg[i] + 11) != 0 )
}
rule Linux_Trojan_Winnti_61215d98 {
    meta:
        author = "Elastic Security"
        id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
        fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}
rule HKTL_mimikatz_icon {
    meta:
        description = "Detects mimikatz icon in PE file"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        reference = "https://blog.gentilkiwi.com/mimikatz"
        date = "2023-02-18"
        score = 60
        hash1 = "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1"
        hash2 = "1c3f584164ef595a37837701739a11e17e46f9982fdcee020cf5e23bad1a0925"
        hash3 = "c6bb98b24206228a54493274ff9757ce7e0cbb4ab2968af978811cc4a98fde85"
        hash4 = "721d3476cdc655305902d682651fffbe72e54a97cd7e91f44d1a47606bae47ab"
        hash5 = "c0f3523151fa307248b2c64bdaac5f167b19be6fccff9eba92ac363f6d5d2595"
        id = "2a5ea476-a30d-5eac-b57a-3fb49386c046"
    strings:
        $ico = {79 e1 d7 ff 7e e5 db ff 7f e8 dc ff 85 eb dd ff ba ff f1 ff 66 a0 b6 ff 01 38 61 ff 22 50 75 c3}
    condition:
        uint16(0) == 0x5A4D and
        $ico and
        filesize < 10MB
}
rule APT_CN_Group_Loader_Jan20_1 {
   meta:
      description = "Detects loaders used by Chinese groups"
      author = "Vitali Kremez"
      reference = "https://twitter.com/VK_Intel/status/1223411369367785472?s=20"
      date = "2020-02-01"
      score = 80
      id = "c85ae499-4f76-56ff-877d-887e1a7fc077"
   strings:
      $xc1 = { 8B C3 C1 E3 10 C1 E8 10 03 D8 6B DB 77 83 C3 13 }
   condition:
      1 of them
}
rule Winnti_NlaifSvc {
   meta:
      description = "Winnti sample - file NlaifSvc.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/VbvJtL"
      date = "2017-01-25"
      hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"
      id = "d2bfcad4-9762-5f2a-88cc-e8cdc648e710"
   strings:
      $x1 = "cracked by ximo" ascii

      $s1 = "Yqrfpk" fullword ascii
      $s2 = "IVVTOC" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}
rule HeavensGate
{
    meta:
        author = "kevoreilly"
        description = "Heaven's Gate: Switch from 32-bit to 64-mode"
        cape_type = "Heaven's Gate"

    strings:
        $gate_v1 = {6A 33 E8 00 00 00 00 83 04 24 05 CB}
        $gate_v2 = {9A 00 00 00 00 33 00 89 EC 5D C3 48 83 EC 20 E8 00 00 00 00 48 83 C4 20 CB}
        $gate_v3 = {5A 66 BB 33 00 66 53 50 89 E0 83 C4 06 FF 28}

    condition:
        ($gate_v1 or $gate_v2 or $gate_v3)
}
rule win_hyperbro_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hyperbro."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hyperbro"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 33c0 6a40 66890479 e8???????? 6a40 }
            // n = 5, score = 400
            //   33c0                 | xor                 eax, eax
            //   6a40                 | push                0x40
            //   66890479             | mov                 word ptr [ecx + edi*2], ax
            //   e8????????           |                     
            //   6a40                 | push                0x40

        $sequence_1 = { 8b4604 83c004 50 6a00 57 }
            // n = 5, score = 400
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   83c004               | add                 eax, 4
            //   50                   | push                eax
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_2 = { 46 47 83e801 75f5 }
            // n = 4, score = 400
            //   46                   | inc                 esi
            //   47                   | inc                 edi
            //   83e801               | sub                 eax, 1
            //   75f5                 | jne                 0xfffffff7

        $sequence_3 = { 8d542428 68???????? c74424200c000000 c744242801000000 89542424 ff15???????? }
            // n = 6, score = 400
            //   8d542428             | lea                 edx, [esp + 0x28]
            //   68????????           |                     
            //   c74424200c000000     | mov                 dword ptr [esp + 0x20], 0xc
            //   c744242801000000     | mov                 dword ptr [esp + 0x28], 1
            //   89542424             | mov                 dword ptr [esp + 0x24], edx
            //   ff15????????         |                     

        $sequence_4 = { 05ff000000 41 3d01feffff 0f871c010000 8bd5 2bd1 83fa01 }
            // n = 7, score = 400
            //   05ff000000           | add                 eax, 0xff
            //   41                   | inc                 ecx
            //   3d01feffff           | cmp                 eax, 0xfffffe01
            //   0f871c010000         | ja                  0x122
            //   8bd5                 | mov                 edx, ebp
            //   2bd1                 | sub                 edx, ecx
            //   83fa01               | cmp                 edx, 1

        $sequence_5 = { 50 8d4c2472 51 6689442474 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   8d4c2472             | lea                 ecx, [esp + 0x72]
            //   51                   | push                ecx
            //   6689442474           | mov                 word ptr [esp + 0x74], ax

        $sequence_6 = { 6882000000 c706???????? e8???????? 6882000000 6a00 50 }
            // n = 6, score = 400
            //   6882000000           | push                0x82
            //   c706????????         |                     
            //   e8????????           |                     
            //   6882000000           | push                0x82
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_7 = { e8???????? 83c404 83eb01 79ec 8b4f2c 51 e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83eb01               | sub                 ebx, 1
            //   79ec                 | jns                 0xffffffee
            //   8b4f2c               | mov                 ecx, dword ptr [edi + 0x2c]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_8 = { 83c410 85ed 750e 8b7c2410 }
            // n = 4, score = 400
            //   83c410               | add                 esp, 0x10
            //   85ed                 | test                ebp, ebp
            //   750e                 | jne                 0x10
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]

        $sequence_9 = { 8b44242c 3bc3 7415 50 e8???????? 83c404 }
            // n = 6, score = 400
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   3bc3                 | cmp                 eax, ebx
            //   7415                 | je                  0x17
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 352256
}
rule SUSP_PE_Signed_by_Suspicious_Entitiy_Mar23
{
    meta:
        author = "Arnim Rupp (https://github.com/ruppde)"
        date_created = "2023-03-06"
        description = "Find driver signed by suspicious company (see references)"
        score = 60
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        reference = "https://www.mandiant.com/resources/blog/hunting-attestation-signed-malware"
        reference = "https://news.sophos.com/en-us/2022/12/13/signed-driver-malware-moves-up-the-software-trust-chain/"
        reference = "https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/"
        hash = "2fb7a38e69a88e3da8fece4c6a1a81842c1be6ae9d6ac299afa4aef4eb55fd4b"
        hash = "9a24befcc0c0926abb49d43174fe25c2469cca06d6ab3b5000d7c9d434c42fe9"
        hash = "9ad716f0173489e74fefe086000dfbea9dc093b1c3460bed9cdb82f923073806"
        hash = "a007c8c6c1aecfff1065429fef691e7ae1c0ce20012a113f01ac57c61564a627"
        hash = "fbe82a21939d04735aa3bbf23fbabd45ac491a143396e8e62ee20509c1257918"
        hash = "d12c6ea0a86c58ea2d80d1dc9b793ba28a0db92c72bb5b6f4ee2b800fe42091b"
        hash = "4cf31d000f1542690cbc0ace41e4166651a71747978dc408e3cce32e82713917"
        hash = "e1adaea335b20d4d2e351f7bea496cd40cb379376900434866db342f851d9ddf"
        hash = "031408cf2f2c282bcc05066356fcc2bb862b7e3c504ab7ffb0220bea341404a5"
        hash = "2f13d4e1bd35f6c0ad0978af19006c17193cf3d42b71cba763cca68f7e9d7fca"
        hash = "cb40a5dc4f6a27b1dc50176770026b827f8baa05fa95a98a4e880652f6729d96"
        hash = "a7591b7384bd10eb934f0dac8dcbfdff8c352eba2309f4d75553567fa2376efa"
        hash = "d517ce5f132b3274f0b9783a5b0c37d1d648e6079874960af24ca764b011c042"
        hash = "aeec903013d5b66f0ae1c6fa50bb892759149c1cec86db8089a4e60482e02250"
        hash = "0d22828724cb7fbc6cef7f98665d020867d2eb801cff2c21f2e97e481040499b"
        hash = "4b2e874d51d332fd840dadd463a393f9f019de46e49de73be910b9b1365e4e4e"
        hash = "3839c0925acf836238ba9a0c5798b84b1c089a8353cc27ae7e6b75d273b539e3"
        hash = "c470f519fb0d4a2862035e0d9e105a0a6918adc51842b12ad14b5b5f34879963"
        hash = "cc6d174bc86f84f5a4c516e9c04947e2fecc0509a84748ea80576aeee5950aed"
        hash = "6fe8df70254f9b5f53452815f0163cb2ffb2d7f0f5aefbb9b149ad1be9284e31"
        hash = "4cde473fb68fa9b2709ea8a23349cd2fce8b8b3991b9fea12f95d12292b8aa7a"
        hash = "e2c40c8dd60bb395807c39c76bfdf5cd158ebefd2a47ad3306a96662c50057c0"
        hash = "9c12b09b529fa517eaeb49df22527d7563b5432d62776166048d97f83b2dce5c"
        hash = "5a4e17287f3dceb5bf1ed411e5fdd7e8692aebf2a19b334327733fc1c158b0ba"
        hash = "c42964aa7fa354b1a285bdbcbd9e84b6bdd8813ff9361955e0e455d032803cce"
        hash = "ffd6955bf40957a35901d82fd5b96d0cb191b651d3eca7afa779eebfed0d9f7e"
        hash = "f6874335eb0d611d47b2ec99a6b70f7b373a50d8d1f62d290b06174f42279f36"
        hash = "4e6d7fd70a143f19429fead2c14779aea9d9140e270bb9e91e47fa601643e40e"
        hash = "7b0e4aae37660b1099de69f4c14f5d976f260c64a4af8495ff1415512a6268ba"
        hash = "db45cbfb094f3e1ebf1cb3880087a24d4e771cc43ba48ad373e6283cbe7391da"
        hash = "813edc804f59a97ec9391ea0db4b779443bd8daf1e64c622b5e3c9a22ee9c2e0"
        hash = "8d66a4b7c2ae468390d32e5e70b3f9b7cb796b54b7c404cde038de9786be8d1d"
        hash = "85936141f0f32cf8f3173655e7200236d1fce6ef9c2616fd2b19ae7951c644c5"
        hash = "b5fc0cc9980fc594a18682d2b0d5b0d0f19ba7a35d35106693a78f4aaba346ac"
        hash = "7aae36c5ffa8baaab19724dae051673ddafd36107cb61c505926bfceaadcd516"
        hash = "5d0228a0d321e2ddac5502da04ca7a2b2744f3dc1382daa5f02faa9da5aface1"
        hash = "2af1ac8bc8ae8d7cad703d2695f2f6c6d79b82eebba01253a8ec527e11e83fcd"
        hash = "c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497"
        hash = "0e339c9c8a6702b32ee9f2915512cbeb3391ced74b16c7e0aed9b1a80c9e58c8"
        hash = "80bdeaa4f162c65722b700e4ffba31701d0d634f5533e59bf3885dc67ee92f3f"
        hash = "4570f64f2000bdaf53aec0fc2214c8bd54e0f5cb75987cdf1f8bda6ea5fc4c43"
        hash = "a9c906bde6c8a693d5d46c9922dafa2dfd2dec0fff554f3f6a953c2e36d3f7b7"
        hash = "520df3ddd7c9ecdeecac8e443d75ac258c26b45d37ecec22501afdda797f6a0a"
        hash = "4d3e0f27a7bcfd4b442b489c63641af22285ca41c6d56ac1db734196ab10b315"
        hash = "5000b3b1d593ba40cc10098644af1551259590ac67d3726fab2be87aad460877"
        hash = "7c27bd6104fc67dd16e655f3bf67c2abd8b5bf2a693ba714ac86904c5765b316"
        hash = "34b1234eab7ff10edde9e09ecf73c5e4bfe9ee047ccfdb43de1e1f6155afad0c"
        hash = "f6fe2cc9ea31f85273c26e84422137df21cfce4b9e972b0db94fe3a67b54f6ca"
        hash = "ec4d0828196926bd36325f4b021895d37cfaaa024f754b36618c78b2574f0122"
        hash = "2a89f263d85da8fb0c934d287b5b524744479741491c740aaa46ac9f694f6d1b"
        hash = "c8d0122974fc10a7d82c62f3e6573a94379c026dd741fd73497afdf36d3929be"
        hash = "0345f71876bc4c888deadba7284565a8da112901f343e54b8522279968abd1b2"
        hash = "6c0e10650be9e795dc6adfbe8aad8c1c3a8657e4c45cb82a7d5188ee24021ca0"
        hash = "90b8d9c4ff3e4e0a0342e0d91da3a25be2fead29f3b32888bb35f8575845259d"
        hash = "0310400c9e62c3fe08dc6506313e26f7c5c89035c81b0141ce57543910c1c42e"
        hash = "b0da0316443f878aad0b3d9764b631d5df60e119ab59324c37640da1b431893a"
        hash = "cc4bd06f27a5f266bc8825a08e5f45dcaa4352eb6d69214b5037d28cc8de6908"
        hash = "2d4b7c6931203923db9a07e1ac92124e799f3747ab20e95e191e99c7b98f3fbd"
        hash = "b5965de0d883fd0602037f3dc26fd4461e6328612f1a34798cff0066142e13c4"
        hash = "86ce17183ddf32379db53ecaedefe0811252165b05cd326025bb8eca2e6a25d7"
        hash = "6edca16d5aa751aa4c212e6477121d51e4d9b9432896d25b41938a27a554bbe7"
        hash = "cdd8966e0cf08a6578e34de7498a44413a6adabae04d81ef3129f26305966db2"
        hash = "df890974589ed2435f53b8c8f147a06752f1b37404afd4431362c1938fcb451e"
        hash = "3e05d8abaaa95af359e5b09efb30546d0aa693859ebc8a0970a2641556ea644c"
        hash = "1c8ddf4b9c99c8f1945abf1527c7fa93141430680ac156a405d9a927d32f3b5e"
        hash = "5d2ed5930ab1a650f9fb9293f49a9f35737139fdfa9f14e46a07e5d4d721ae3e"
        hash = "18834de3e4844a418970c2184cc78c2d7cb61d18e9f7c7c0e88e994b4212edc5"
        hash = "a6b6fc94d8e582059af0fe30c2c93c687fccd5a0073a6a26a2cd097ea96adc7c"
        hash = "28b40fa160c915f13f046d36725c055d6c827a4d28674ea33c75a9b410321290"
        hash = "efab0fbf77dc67a792efd1fe2b3f46bbdfdee30a9321acc189c53a6c5e90f05c"
        hash = "348781221d1a2886923de089d1b7b12c32cfdd38628b71203da925b5736561e9"
        hash = "a1a5f410e6eab2445d64bfcd742fe1a802a0a2d9af45c7ab398f84894dd5dc3d"
        hash = "9de05ce0d9e9de05ebdc2859a5156f044f98bb180723f427a779d36b1913e5d3"
        hash = "eeff7e85c50a7f11fc8a99f7048953719fb1d2a6451161a0796eac43119ece21"
        hash = "383cc025800a3b3d089f7697e78fe4d5695a8d1ee26dcad0b0956ad6800ccae4"
        hash = "41be6f393cea4d8d5869fff526c4d75ec66c855f7e9c176042c39b9682ea9c14"
        hash = "71552e65433c8bbf14e5bcbc35a708bc10d6fded740c5f4783edce84aea4aabf"
        hash = "3c1b3e8666b58a78c70f36ed557c7ecc52e84457e87e5884b42e5cd9e8c1a303"
        hash = "4288d7113031151a2636a164c0dc6fce78c86f322271afec9ef2d4b54494c334"
        hash = "f73a39332be393a9bc23ec27ff6d025bc90d7320dde97f37cc585ecf6c0436a2"
        hash = "018f5103635992aa9ddc1c46cafe2b7ba659fcfbc8f8ab29dcea28e155b033ee"
        hash = "fe650fc138dcfbbd4ab6aa5718bf3cd36f50898ae19d3aceaa12f7d4f39d0b43"
        hash = "fa21b39cd5a24ba35433e90cae486454b7400b50e7f7f5c190fdbec6704b4352"
        hash = "3dd36c798cc89bfad7cdbf58d7da90ba113fe043ca46bdbcab7ae7fb9dc2f42b"
        hash = "674f4444f0de5c81c766c376a65fbdf1f7116228a61c71ffb504995c9e160183"
        hash = "cd3d25b2842bb2d6a5580f72e819acd344ce7f3a2478fb6d53ff668ad6531228"
        hash = "1668f4eb8a85914db46ff308b9f8a5040a024acc93259dfc004ea2b80ab6bcf1"
        hash = "4f31cab6c011b79bf862bb6acea3086308b0576afe33affdb09039c97e723beb"
        hash = "6b0ff48b8113076d2875edb7bea7f120b7b9d9a990ae296a5b5a95660ae7edfc"
        hash = "956a00dd6382e83d3f7490378ae98e4fc8d9b8ec2cd549519f007091e3ccce1f"
        hash = "8c7f938cf55728d8d41a7fa6b9953c4f81cf05ed3d7b7435ec8999e130257f7f"
        hash = "427ee4d4d18fc0c1196326215e94947f7d8c03794de36d0127231690bf5bf3c0"
        hash = "b6f3ece5bf7b9f6ecf99104d3c76b9007106fad98d20500956dd1e42d4ec5e8d"
        hash = "47a0ad6150c5a1de4c788827662a9cafbd2816a7d32be2028721e49a464acbed"
        hash = "8743ac81384fd10c0459f3574489d626e13c95dd73274dcf1d872bcd3630b9e8"
        hash = "a1755415a12f85bea3f65807860f902cf41e56b0ab2c155ac742af3166ef1dfd"
        hash = "3f5a91500bfade2d9708e1fbe76ae81dacdb7b0f65f335fee598546ccfc267e3"
        hash = "5be43b773dbde6542d6a0d53cd6616ea95a49dd38659edc6ba0d580a0d9777ab"
        hash = "90e080a63916c768b0b65787fe5695fd903d44e1b0b688d06c14988ba30b5ea7"
        hash = "d1184ee3f26919b8f5a4b1a6d089f14e79e0c89260590156111f72a979c8e446"
        hash = "c13ddd2bafcfdfc00fb5cb87d8eb533ae094b0dd5784df77c98bddeac9d72725"
        hash = "9bb3035610bd09ba769c0335f23f98dd85c2f32351cdd907d4761b41ab5d099c"
        hash = "1703025c4aed71d0ca29a3cd0e15047c24cc9adbb5239765f63e205ef7d65753"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"
        hash = "5654ed1205de6860e66383a27231e4ac2bb7639b07504121d313a8503ece3305"
        hash = "5d1e3c495d08982459b4bd4fd2ab073ed2078fce9347627718a7c25adee152e9"
        hash = "458702ae1b2ef8a113344be76af185ee137b7aac3646ece626d2eeeadcc9e003"
        hash = "2c703e562a6266175379fa48f06f58aab109dbe56e0cde24b4b0db5f22f810a3"
        hash = "49faf70c0978c21a68bc8395cf326f50c491e379f55b5df7d17f0af953861ece"
        hash = "a2b16bbef0a7cb545597828466cd13225efaba6e7006bfbf59040bbff54c463c"
        hash = "b08449d42f140c7e4d070c5f81ce7509f48282a5bb0e06948b7ed65053696a37"
        hash = "c1633ad8c9e6c2b4cc23578655fc6cf5cd0122cfd24395d1551af1d092f89db2"
        hash = "01f42f949a37d9d479b8021f27dcf0d0e6f0b0b6cd2e0883c6b4b494f0a1d32a"
        hash = "4943d53a38ac123ed7c04ad44742a67ea06bb54ea02fa241d9c4ebadab4cb99a"
        hash = "597ce12c9fbecc71299ba6fc3e4df36cc49222878d0e080c4c35bbfdffd30083"
        hash = "0265fbd9cfc27c26c42374fce7cf0ef11f38e086308d51648b45f040d767c51d"
        hash = "0dc92a1a6fd27144b3e35a9900038653892d25c2db8ede8b9e0aee04839f165a"
        hash = "682582c324cb1eafacf80090f6108c1580fee12dbfdfe8b51771d429fdcce718"
        hash = "e9e6f6e22b5924f80164fbad45be28299e9ec0bd2f404551b6ca772509a7135a"
        hash = "a8db750f82906fb9cf9fb371ec65be76275d9b81b95e351fcb3db4ef345884ab"
        hash = "e900b4016177259d07011139a55c0571c1e824fb7e9dddc11df493b3c8209173"
        hash = "f8a7a26d51a5e938325deee86cbf5aa8263d3a50818c15d5a395b98658630c18"
        hash = "861b87fc6c4758cfe1e26c7a038cffb64054ad633b7ea81319c9a98b7b49df0d"
        hash = "848fdb491307ed7b002dbdf99796df2b286d53b2e0066d78f3554f2f38a2c438"
        hash = "4b0c05bc33c9e7d0ed2d97dbefb6292469b9d74d650d5cfb2691345a11c0f54a"
        hash = "948d47b9386b2b3247b7e9796ab2f2078889264559ad04ccd9362b03dbbf8534"
        hash = "edd527d978b591d146d24d075bb4c24177e0eca6a27b5d92f35be68635cc3767"
        hash = "c642dc125fbd83e004d2c527933996589e0fcad06313a5a56679a265b8966529"
        hash = "cfa3a48bf0c683834d1d198a653ebced8a8faae9d0cbb38f3e859b45da81d554"
        hash = "bb8f5d123aebdde5542724db5be8430d62a80f86f590a272aac9087d097f395c"
        hash = "e41e10673db41b13ba17c828beb94fc39e8d3aa43b01f9fe437a2f6e0b8ae443"
        hash = "a132e31db9f9761d6bd2c375415e615bb0a548fb02c4fd6373e9f7d1568de1dc"
        hash = "5084c6e20b88adeea6a28508cf172048d7cf20adeaa52abdd361fc2207411055"
        hash = "525320e3631a23a3286481710533ba15cd6268ee10be98962a55e2afead1ffbf"
        hash = "16c74f288f4f929e74cd8e16443303aec3a64cfef64aabc14553f4c1e58c9ede"
        hash = "4b482ebf88bcb55e7b0769690ccca4d08856c879af82ad7165436b82a315d742"
        hash = "79c9acadd99ab1251dbba3bff7d0b67de4252f913f485465d63f4f0c4d9a6419"
        hash = "9bcc3f36c32e3efbf8bdcba7670658042db65dd617dad0709d92c554ba841b57"

        id = "13151f9b-22cb-551f-81b4-a60a301f0bfc"
    strings:
        // works well enough with string search so no need to use the pe module
        $cert1 = "91210242MA0YGH36" wide ascii ///serialNumber=91210242MA0YGH36XJ/jurisdictionC=CN/businessCategory=Private Organization/C=CN/ST=\xE8\xBE\xBD\xE5\xAE\x81\xE7\x9C\x81
        $cert2 = "Copyright (C) 2013-2021 QuickZip. All rights reserved." wide ascii 
        $cert3 = "Qi Lijun" wide ascii // short but no fp
        $cert4 = {51 00 69 00 20 00 4c 00 69 00 6a 00 75 00 6e} // string above in hex(utf16-be minus first 00) because of https://github.com/VirusTotal/yara/issues/1891
        $cert5 = "Luck Bigger Technology Co., Ltd" wide ascii
        $cert6 = {4c 00 75 00 63 00 6b 00 20 00 42 00 69 00 67 00 67 00 65 00 72 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 20 00 43 00 6f 00 2e 00 2c 00 20 00 4c 00 74 00 64 } // above in hex
        $cert7 = "XinSing Network Service Co., Ltd" wide ascii
        $cert8 = "Hangzhou Shunwang Technology Co.,Ltd" wide ascii
        $cert9 = "Zhuhai liancheng Technology Co., Ltd." wide ascii
        $cert10 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert11 = { e5 8c 97 e4 ba ac e5 bc 98 e9 81 93 e9 95 bf e5 85 b4 e5 9b bd e9 99 85 e8 b4 b8 e6 98 93 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert12 = { e7 a6 8f e5 bb ba e5 a5 a5 e5 88 9b e4 ba 92 e5 a8 b1 e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }
        $cert13 = { e5 8e a6 e9 97 a8 e6 81 92 e4 bf a1 e5 8d 93 e8 b6 8a e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 0a }
        $cert14 = { e5 a4 a7 e8 bf 9e e7 ba b5 e6 a2 a6 e7 bd 91 e7 bb 9c e7 a7 91 e6 8a 80 e6 9c 89 e9 99 90 e5 85 ac e5 8f b8 }

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        filesize < 20MB and
        any of ( $cert* )

}
rule INDICATOR_KB_CERT_0989c97804c93ec0004e2843 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "98549ae51b7208bda60b7309b415d887c385864b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shanghai Hintsoft Co., Ltd." and
            pe.signatures[i].serial == "09:89:c9:78:04:c9:3e:c0:00:4e:28:43"
        )
}
rule DeepPanda_htran_exe {
	meta:
		description = "Hack Deep Panda - htran-exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
		id = "2a551e82-aff1-5a77-bc5e-d06e49dca8bc"
	strings:
		$s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s2 = "\\Release\\htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s8 = "======================== htran V%s =======================" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s15 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
	condition:
		1 of them
}
rule MAL_LNX_LinaDoor_Rootkit_May22 {
   meta:
      description = "Detects LinaDoor Linux Rootkit"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2022-05-19"
      modified = "2023-05-16"
      score = 85
      hash1 = "25ff1efe36eb15f8e19411886217d4c9ec30b42dca072b1bf22f041a04049cd9"
      hash2 = "4792e22d4c9996af1cb58ed54fee921a7a9fdd19f7a5e7f268b6793cdd1ab4e7"
      hash3 = "9067230a0be61347c0cf5c676580fc4f7c8580fc87c932078ad0c3f425300fb7"
      hash4 = "940b79dc25d1988dabd643e879d18e5e47e25d0bb61c1f382f9c7a6c545bfcff"
      hash5 = "a1df5b7e4181c8c1c39de976bbf6601a91cde23134deda25703bc6d9cb499044"
      hash6 = "c4eea99658cd82d48aaddaec4781ce0c893de42b33376b6c60a949008a3efb27"
      hash7 = "c5651add0c7db3bbfe0bbffe4eafe9cd5aa254d99be7e3404a2054d6e07d20e7"
      id = "e2f250b4-9a8a-5d70-83d7-5d12ad3763fb"
   strings:
      $s1 = "/dev/net/.../rootkit_/" ascii
      $s2 = "did_exec" ascii fullword
      $s3 = "rh_reserved_tp_target" ascii fullword
      $s4 = "HIDDEN_SERVICES" ascii fullword
      $s5 = "bypass_udp_ports" ascii fullword
      $s6 = "DoBypassIP" ascii fullword

      $op1 = { 74 2a 4c 89 ef e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 4c 39 f2 }
      $op2 = { e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 4c 39 f2 48 0f 46 c3 5b }
      $op3 = { 48 89 c3 74 2a 4c 89 ef e8 00 00 00 00 48 89 da 4c 29 e2 48 01 c2 31 c0 }
      $op4 = { 4c 29 e2 48 01 c2 31 c0 4c 39 f2 48 0f 46 c3 5b 41 5c 41 5d }

      $fp1 = "/wgsyncdaemon.pid"
   condition:
      uint16(0) == 0x457f and
      filesize < 2000KB and 2 of them 
      and not 1 of ($fp*)
      or 4 of them
}
rule Linux_Trojan_Winnti_61215d98 {
    meta:
        author = "Elastic Security"
        id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
        fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Winnti"
        reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }
    condition:
        all of them
}
rule pwnlnx_backdoor_variant_3 {

    meta:
    
        description = "Rule to detect the backdoor pwnlnx variant"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Pwnlnx"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "08f29e234f0ce3bded1771d702f8b5963b144141727e48b8a0594f58317aac75"
    
    strings:

        /*

        7F454C4602010103000000000000000002003E000100000000044000000000004000000000000000B0BA3A0000000000000000004000380005004000270024000100000005000000000000000000000000004000000000000000400000000000BAA40C0000000000BAA40C000000000000002000000000000100000006000000C0A40C0000000000C0A46C0000000000C0A46C000000000050130000000000008890000000000000000020000000000004000000040000005801000000000000580140000000000058014000000000002000000000000000200000000000000004000000000000000700000004000000C0A40C0000000000C0A46C0000000000C0A46C000000000028000000000000007800000000000000080000000000000051E5746406000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000040000001000000001000000474E550000000000020000000400000000000000C0A56C00000000002500000000000000E084420000000000C8A56C00000000002500000000000000D037420000000000D0A56C000000000025000000000000008073420000000000D8A56C0000000000250000000000000050DA420000000000E0A56C00000000002500000000000000F024480000000000E8A56C00000000002500000000000000A084420000000000F0A56C00000000002500000000000000F083430000000000F8A56C00000000002500000000000000305E42000000000000A66C00000000002500000000000000506F42000000000008A66C00000000002500000000000000109142000000000010A66C00000000002500000000000000707542000000000018A66C00000000002500000000000000B01442000000000020A66C00000000002500000000000000B02448000000000028A66C00000000002500000000000000509142000000000030A66C0000000000250000000000000050134200000000004883EC08E843010000E862020000E84D9409004883C408C3FF25C2A22C006800000000E900000000FF25BAA22C006800000000E900000000FF25B2A22C006800000000E900000000FF25AAA22C006800000000E900000000FF25A2A22C006800000000E900000000FF259AA22C006800000000E900000000FF2592A22C006800000000E900000000FF258AA22C006800000000E900000000FF2582A22C006800000000E900000000FF257AA22C006800000000E900000000FF2572A22C006800000000E900000000FF256AA22C006800000000E900000000FF2562A22C006800000000E900000000FF255AA22C006800000000E900000000FF2552A22C006800000000E90000000000000000000000000000000000000000000000000000000031ED4989D15E4889E24883E4F0505449C7C0C0BC400048C7C100BD400048C7C7D02E4000E8A7B20000F490904883EC08488B0569A12C004885C07402FFD04883C408C390909090909090909090909090B817B86C0055482D10B86C004883F80E4889E5761BB8000000004885C074115DBF10B86C00FFE0660F1F8400000000005DC366666666662E0F1F840000000000BE10B86C00554881EE10B86C0048C1FE034889E54889F048C1E83F4801C648D1FE7415B8000000004885C0740B5DBF10B86C00FFE00F1F005DC3660F1F440000803D69B32C00007573554889E553BB10A56C004881EB00A56C004883EC08488B0553B32C0048C1FB034883EB014839D87324660F1F4400004883C00148890535B32C00FF14C500A56C00488B0527B32C004839D872E2E825FFFFFFB8708E49004885C0740ABFB8904B00E831890900C605FAB22C00014883C4085B5DF3C3669055B8508B49004885C04889E5740FBE60B86C00BFB8904B00E8E3850900BF18A56C0048833F0075085DE912FFFFFF6690B8000000004885C074EEFFD0EBEA9090554889E5534881ECD820000089BD2CDFFFFF48C745E0000000008B45143D001000007605E9F50100008B451489C2488D8DC0EFFFFF8B852CDFFFFF4889CE89C7E8C941000085C07505E9D00100008B451489C2488D85C0EFFFFF89D64889C7E870030000488D85C0EFFFFFBE24A549004889C7E828320100488945E048837DE0007505E996010000488D9530DFFFFF488D85C0EFFFFF4889D64889C7E82FCD030085C07405E968010000488B8560DFFFFF488945D8C7451400000000488B45D8894524488B45D848C1F8208945204883EC08FF7520FF7518FF7510E8585200004883C420894510BE18000000488D7D10E8DF0200008B852CDFFFFFBA18000000488D751089C7E82843000085C07505E9FE0000008B852CDFFFFFBA18000000488D751089C7E8E440000085C07505E9DF000000BE18000000488D7D10E8930200008B5D104883EC08FF7520FF7518FF7510E8E25100004883C42039C37405E9AF0000008B452089C048C1E0204889C28B452489C04801D0488945D0488B4DD0488B45E0BA000000004889CE4889C7E8AD4A0100488B45D0488945E8EB6B488B55E0488D85C0DFFFFF4889D1BA00100000BE010000004889C7E8F33001008945CC837DCC007F02EB4A8B55CC488D85C0DFFFFF89D64889C7E8F80100008B45CC4863D0488D8DC0DFFFFF8B852CDFFFFF4889CE89C7E83A42000085C07502EB138B45CC4898480145E8488B45E8483B45D87C8B488B45E04889C7E842270100B800000000488B5DF8C9C3554889E5534881ECD80100004889BD28FEFFFFE8BF7F00004889C7E8677F0000C745ECFFFFFFFF488B8528FEFFFF8B40088945E8488B8528FEFFFF8B008945E4488B8528FEFFFF8B40048945E08B4DE08B45E4BA0A00000089CE89C7E8063B00008945EC837DECFF7505E927010000488D45C0BA18000000BE000000004889C7E85AFBFFFFC745CC00000000C745C4860100008B45E88945C84883EC08FF75D0FF75C8FF75C0E8645000004883C4208945C0488D45C0BE180000004889C7E8E8000000488D4DC08B45ECBA180000004889CE89C7E83141000085C07505E9B4000000488D8530FEFFFF4889C7E8F6BD0300488D8530FEFFFFBE860100004889C7E8A6000000488D8D30FEFFFF8B45ECBA860100004889CE89C7E8EC40000085C07502EB72488D4DC08B45ECBA180000004889CE89C7E8AB3E000085C07502EB56488D45C0BE180000004889C7E85A0000008B5DC04883EC08FF75D0FF75C8FF75C0E8A94F00004883C42039C37402EB268B45CC83F8037402EB1C8B45EC4883EC08FF75D0FF75C8FF75C089C7E846FCFFFF4883C420908B45EC89C7E8C79A0000B800000000488B5DF8C9C3554889E548897DE88975E4C745F010000000488B45E8488945F8C745F400000000EB2C488B45F80FB6088B45F499F77DF089D048980FB68050A66C0031C189CA488B45F888108345F401488345F8018B45F43B45E47CCC488B45E85DC3554889E548897DE88975E4488B45E8488945F8C745F400000000EB1F488B45F80FB6100FB605659C2C0031C2488B45F888108345F401488345F8018B45F43B45E47CD9488B45E85DC39090554889E5534881ECD840000089BD2CBFFFFF48C745E80000000048C745D80000000048C745D0000000008B451489C2488D8DC0EFFFFF8B852CBFFFFF4889CE89C7E84C3D000085C07505E9400300008B451489C2488D85C0EFFFFF89D64889C7E8F3FEFFFF488D95C0DFFFFF488D85C0EFFFFF4889D64889C7E896180100488D95C0DFFFFF488D85C0CFFFFF4889D1BA28A54900BE001000004889C7B800000000E86E1F0100488D85C0CFFFFF4889C7E83F3A02004883C0014889C7E863E80100488945E848837DE8007505E9BE020000488D95C0CFFFFF488B45E84889D64889C7E815F8FFFF488D75C0488D85C0DFFFFFB980C44300BA000000004889C7E830B703008945CC837DCC000F8E72020000C745E400000000E95A010000488B45C08B55E44863D248C1E2034801D0488B00488D4813488D95C0DFFFFF488D85C0BFFFFF4989C84889D1BA6BA54900BE001000004889C7B800000000E8B41E0100488D9530BFFFFF488D85C0BFFFFF4889D64889C7E8DBC7030085C00F85F200000048C745D860A66C0048C745D060A66C00488D8530BFFFFF4883C0584889C7E8C08C03004889C7E8988C03004989C0488B9560BFFFFF8B8548BFFFFF25FF01000089C78B8548BFFFFF2500F0000089C6488B45C08B4DE44863C948C1E1034801C8488B00488D4813488D85C0CFFFFF415052FF75D0FF75D84189F94189F0BA78A54900BE001000004889C7B800000000E8FF1D01004883C420488B45E84889C7E8CF3802004889C3488D85C0CFFFFF

        */

        $bp = { 7F??4C4602??01??000000000000000002??3E????0000000004??00000000??????000000000000B0??3A??000000000000000040??????????????????????01??000005????????0000000000000000??????0000000000004000000000????????????0000????????????00000000????00000000????0000????0000????A40C??00000000C0??????????????C0??????????????5013??00000000????????????00000000????00000000??????000004??00005801??00000000??????4000000000??????4000000000????000000000000????000000000000??????000000000000070000??????0000C0??????????????C0??????????????C0??????????????28??00000000000078??00000000000008??00000000000051E5??64??000000000000000000000000000000000000000000000000000000000000000000000000000000000000????000000000000??????000010??000001??0000474E5500000000????0000??????000000000000C0????????????????????????0000????84????00000000C8??????0000000025????????0000????374200000000????A56C00000000????????????0000????????????0000????A56C00000000????????????0000??????4200000000????A56C00000000????????????0000????24??00000000????A56C00000000????????????0000????????????0000????A56C00000000????????????0000????83??????0000????A56C00000000????????????0000????5E42000000000000A66C00000000????????????0000??????4200000000????A66C00000000????????????0000????914200000000????A66C00000000????????????0000??????4200000000????A66C00000000????????????0000????????????0000????A66C00000000????????????0000????????????0000????A66C00000000????????????0000??????4200000000????A66C00000000????????????0000??????4200000000??????EC08??4301??????62??0000E8????????4883????C3FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????FF??????????68????????E9????????00000000000000000000000000000000000000000000000031??4989??5E4889??4883????505449C7??????????48C7??????????48C7??????????E8????????F490904883????488B??????????4885??74??FF??4883????C390909090909090909090909090B8????????55482D????????4883????4889??76??B8????????4885??74??5DBF????????FF??660F1F????????????5DC366666666????????????????????BE????????554881??????????48C1????4889??4889??48C1????4801??48D1??74??B8????????4885??74??5DBF????????FF??0F1F??5DC3660F1F??????80????????????75??554889??53BB????????4881??????????4883????488B??????????48C1????4883????4839??73??660F1F??????4883????4889??????????FF????????????488B??????????4839??72??E8????????B8????????4885??74??BF????????E8????????C6????????????4883????5B5DF3??669055B8????????4885??4889??74??BE????????BF????????E8????????BF????????4883????75??5DE9????????6690B8????????4885??74??FF??EB??9090554889??534881??????????89??????????48C7????????????8B????3D????????76??E9????????8B????89??488D??????????8B??????????4889??89??E8????????85??75??E9????????8B????89??488D??????????89??4889??E8????????488D??????????BE????????4889??E8????????4889????4883??????75??E9????????488D??????????488D??????????4889??4889??E8????????85??74??E9????????488B??????????4889????C7????????????488B????89????488B????48C1????89????4883????FF????FF????FF????E8????????4883????89????BE????????488D????E8????????8B??????????BA????????488D????89??E8????????85??75??E9????????8B??????????BA????????488D????89??E8????????85??75??E9????????BE????????488D????E8????????8B????4883????FF????FF????FF????E8????????4883????39??74??E9????????8B????89??48C1????4889??8B????89??4801??4889????488B????488B????BA????????4889??4889??E8????????488B????4889????EB??488B????488D??????????4889??BA????????BE????????4889??E8????????89????83??????7F??EB??8B????488D??????????89??4889??E8????????8B????4863??488D??????????8B??????????4889??89??E8????????85??75??EB??8B????48984801????488B????483B????7C??488B????4889??E8????????B8????????488B????C9C3554889??534881??????????4889??????????E8????????4889??E8????????C7????????????488B??????????8B????89????488B??????????8B??89????488B??????????8B????89????8B????8B????BA????????89??89??E8????????89????83??????75??E9????????488D????BA????????BE????????4889??E8????????C7????????????C7????????????8B????89????4883????FF????FF????FF????E8????????4883????89????488D????BE????????4889??E8????????488D????8B????BA????????4889??89??E8????????85??75??E9????????488D??????????4889??E8????????488D??????????BE????????4889??E8????????488D??????????8B????BA????????4889??89??E8????????85??75??EB??488D????8B????BA????????4889??89??E8????????85??75??EB??488D????BE????????4889??E8????????8B????4883????FF????FF????FF????E8????????4883????39??74??EB??8B????83????74??EB??8B????4883????FF????FF????FF????89??E8????????4883????908B????89??E8????????B8????????488B????C9C3554889??4889????89????C7????????????488B????4889????C7????????????EB??488B????0FB6??8B????99F7????89??48980FB6??????????31??89??488B????88??83??????4883??????8B????3B????7C??488B????5DC3554889??4889????89????488B????4889????C7????????????EB??488B????0FB6??0FB6??????????31??488B????88??83??????4883??????8B????3B????7C??488B????5DC39090554889??534881??????????89??????????48C7????????????48C7????????????48C7????????????8B????89??488D??????????8B??????????4889??89??E8????????85??75??E9????????8B????89??488D??????????89??4889??E8????????488D??????????488D??????????4889??4889??E8????????488D??????????488D??????????4889??BA????????BE????????4889??B8????????E8????????488D??????????4889??E8????????4883????4889??E8????????4889????4883??????75??E9????????488D??????????488B????4889??4889??E8????????488D????488D??????????B9????????BA????????4889??E8????????89????83??????0F8E????????C7????????????E9????????488B????8B????4863??48C1????4801??488B??488D????488D??????????488D??????????4989??4889??BA????????BE????????4889??B8????????E8????????488D??????????488D??????????4889??4889??E8????????85??0F85????????48C7????????????48C7????????????488D??????????4883????4889??E8????????4889??E8????????4989??488B??????????8B??????????25????????89??8B??????????25????????89??488B????8B????4863??48C1????4801??488B??488D????488D??????????415052FF????FF????4189??4189??BA????????BE????????4889??B8????????E8????????4883????488B????4889??E8????????4889??488D?????????? }

        condition:

            uint16(0) == 0x457f and 
            filesize < 4000KB and 
            all of them
}
rule SUSP_XORed_MSDOS_Stub_Message {
   meta:
      description = "Detects suspicious XORed MSDOS stub message"
      author = "Florian Roth"
      reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
      date = "2019-10-28"
      modified = "2023-10-11"
      score = 55
      id = "9ab52434-9162-5fd5-bf34-8b163f6aeec4"
   strings:
      $xo1 = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
      $xo2 = "This program must be run under Win32" xor(0x01-0xff) ascii wide

      $fp1 = "AVAST Software" fullword wide ascii
      $fp2 = "AVG Netherlands" fullword wide ascii
      $fp3 = "AVG Technologies" ascii wide
      $fp4 = "Malicious Software Removal Tool" wide
      $fp5 = "McAfee Labs" fullword ascii wide
      $fp6 = "Kaspersky Lab" fullword ascii wide
      $fp7 = "<propertiesmap>" ascii wide  /* KasperSky Lab XML profiles */
      $fp10 = "Avira Engine Module" wide /* Program Files (x86)/Avira/Antivirus/aeheur.dll */
      $fp11 = "syntevo GmbH" wide fullword /* Program Files (x86)/DeepGit/bin/deepgit64.exe */
      $fp13 = "SophosClean" ascii /* ProgramData/Sophos/Update Manager/Update Manager/Warehouse/4d7da8cfbfbb16664dac79e78273a1e8x000.dat */
      $fp14 = "SophosHomeClean" wide
   condition:
      1 of ($x*)
      and not 1 of ($fp*)
      and not uint16(0) == 0xb0b0 // AV sigs file
      and not uint16(0) == 0x5953 // AV sigs file
}
rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $s2 = "eventvwr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}
rule MAL_ARM_LNX_Mirai_Mar13_2022 {
   meta:
      description = "Detects new ARM Mirai variant"
      author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
      date = "2022-03-16"
      hash1 = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"
      id = "54d8860e-fc45-5571-b68c-66590c67a705"
   strings:
      $str1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
      $str4 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
      $attck1 = "attack.c"
      $attck2 = "attacks.c"
      $attck3 = "anti_gdb_entry"
      $attck4 = "resolve_cnc_addr"
      $attck5 = "attack_gre_eth"
      $attck6 = "attack_udp_generic"
      $attck7 = "attack_get_opt_ip"
      $attck8 = "attack_icmpecho"
   condition:
      uint16(0) == 0x457f and ( 3 of ($str*) or 4 of ($attck*) )
}
rule MAL_ARM_LNX_Mirai_Mar13_2022 {
   meta:
      description = "Detects new ARM Mirai variant"
      author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
      date = "2022-03-16"
      hash1 = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"
      id = "54d8860e-fc45-5571-b68c-66590c67a705"
   strings:
      $str1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
      $str3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
      $str4 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
      $attck1 = "attack.c"
      $attck2 = "attacks.c"
      $attck3 = "anti_gdb_entry"
      $attck4 = "resolve_cnc_addr"
      $attck5 = "attack_gre_eth"
      $attck6 = "attack_udp_generic"
      $attck7 = "attack_get_opt_ip"
      $attck8 = "attack_icmpecho"
   condition:
      uint16(0) == 0x457f and ( 3 of ($str*) or 4 of ($attck*) )
}
rule ZXshell_20171211_chrsben {
   meta:
      description = "Detects ZxShell variant surfaced in Dec 17"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/snc85M"
      date = "2017-12-11"
      hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"
      id = "3bbfddb8-011a-52dd-b0c8-b35e6f740507"
   strings:
      $x1 = "ncProxyXll" fullword ascii

      $s1 = "Uniscribe.dll" fullword ascii
      $s2 = "GetModuleFileNameDll" fullword ascii
      $s4 = "$Hangzhou Shunwang Technology Co.,Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        pe.imphash() == "de481441d675e9aca4f20bd8e16a5faa" or
        pe.exports("PerfectWorld") or
        pe.exports("ncProxyXll") or
        1 of ($x*) or
        2 of them
      )
}
rule PassCV_Sabre_Malware_2 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "475d1c2d36b2cf28b28b202ada78168e7482a98b42ff980bbb2f65c6483db5b4"
      hash2 = "009645c628e719fad2e280ef60bbd8e49bf057196ac09b3f70065f1ad2df9b78"
      hash3 = "92479c7503393fc4b8dd7c5cd1d3479a182abca3cda21943279c68a8eef9c64b"
      hash4 = "0c7b952c64db7add5b8b50b1199fc7d82e9b6ac07193d9ec30e5b8d353b1f6d2"
      id = "dd9eb5f6-9faa-584d-b3b5-6dcfdc3f359c"
   strings:
      $x1 = "ncProxyXll" fullword ascii

      $s1 = "Uniscribe.dll" fullword ascii
      $s2 = "WS2_32.dll" ascii
      $s3 = "ProxyDll" fullword ascii
      $s4 = "JDNSAPI.dll" fullword ascii
      $s5 = "x64.dat" fullword ascii
      $s6 = "LSpyb2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and $x1 ) or ( all of them )
}
rule APT_stolen_certificates {

    meta:

        description = "Rule to detect samples digitally signed from these stolen certificates"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Pwnlnx"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "ce3424524fd1f482a0339a3f92e440532cff97c104769837fa6ae52869013558"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp"  and
         pe.signatures[i].serial == "3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a" or
         pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp"  and
         pe.signatures[i].serial == "3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a" or
         pe.signatures[i].subject contains "/C=KR/ST=Seoul/L=Gangnam-gu/O=LivePlex Corp/CN=LivePlex Corp" or
         pe.signatures[i].serial == "3f:55:42:e2:e7:1d:8d:b3:57:04:1c:9d:d4:5b:95:0a")
}
rule pwnlnx_backdoor_variant_1 {

    meta:
    
        description = "Rule to detect the backdoor pwnlnx variant 1"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Pwnlnx"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "0f6033d6f82ce758b576e2d8c483815e908e323d0b700040fbdab5593fb5282b"
    
    strings:

        /*

        7F454C4602010100000000000000000002003E0001000000101A4000000000004000000000000000608C0000000000000000000040003800080040001D001A000600000005000000400000000000000040004000000000004000400000000000C001000000000000C001000000000000080000000000000003000000040000000002000000000000000240000000000000024000000000001C000000000000001C0000000000000001000000000000000100000005000000000000000000000000004000000000000000400000000000E476000000000000E476000000000000000020000000000001000000060000000080000000000000008060000000000000806000000000003808000000000000800C00000000000000002000000000000200000006000000288000000000000028806000000000002880600000000000A001000000000000A001000000000000080000000000000004000000040000001C020000000000001C024000000000001C0240000000000020000000000000002000000000000000040000000000000050E57464040000009C6D0000000000009C6D4000000000009C6D400000000000DC01000000000000DC01000000000000040000000000000051E57464060000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000002F6C696236342F6C642D6C696E75782D7838362D36342E736F2E3200040000001000000001000000474E5500000000000200000006000000090000000000000002000000500000000100000006000000000000000200002000000000500000007DF85A5800000000000000000000000000000000000000000000000000000000150100001200000000000000000000004101000000000000820100001200000000000000000000002500000000000000A301000012000000000000000000000025000000000000005300000012000000000000000000000062000000000000006A0100001200000000000000000000001B0B0000000000007E0200001200000000000000000000008B00000000000000490200001200000000000000000000002500000000000000BD0100001200000000000000000000006C00000000000000590000001200000000000000000000008E00000000000000F4010000120000000000000000000000250000000000000088010000120000000000000000000000F200000000000000FA010000120000000000000000000000A9010000000000000100000020000000000000000000000000000000000000001000000020000000000000000000000000000000000000005002000012000000000000000000000025000000000000007C010000120000000000000000000000EE00000000000000D20000001200000000000000000000000800000000000000230100001200000000000000000000009700000000000000CD000000120000000000000000000000F100000000000000170200001200000000000000000000008000000000000000CE010000120000000000000000000000240200000000000066020000120000000000000000000000A501000000000000710100001200000000000000000000002500000000000000C301000012000000000000000000000028000000000000009B010000120000000000000000000000E700000000000000380100001200000000000000000000003300000000000000E80000001200000000000000000000002901000000000000870200001200000000000000000000008A010000000000003D000000120000000000000000000000340C000000000000EC01000012000000000000000000000043000000000000004B01000012000000000000000000000025000000000000001C0100001200000000000000000000002500000000000000DC010000120000000000000000000000AB0400000000000078020000120000000000000000000000080000000000000043020000120000000000000000000000B9010000000000008C0000001200000000000000000000000A000000000000003F01000012000000000000000000000025000000000000005F020000120000000000000000000000F000000000000000D5010000120000000000000000000000BC010000000000002F020000120000000000000000000000EC01000000000000900100001200000000000000000000002800000000000000840000001200000000000000000000008000000000000000080200001200000000000000000000002700000000000000560200001200000000000000000000007401000000000000BF0000001200000000000000000000002500000000000000160200001200000000000000000000004601000000000000FA00000012000000000000000000000087000000000000005E0000001200000000000000000000001100000000000000A801000012000000000000000000000044000000000000001C0200001200000000000000000000005A00000000000000040100001200000000000000000000002901000000000000C6000000120000000000000000000000DC0000000000000044010000120000000000000000000000F100000000000000D80000001200000000000000000000006C00000000000000A00000001200000000000000000000005200000000000000BC0100001200000000000000000000000602000000000000E5010000120000000000000000000000340000000000000034000000120000000000000000000000A1000000000000000D010000120000000000000000000000A6000000000000008C0200001200000000000000000000004B00000000000000F10000001200000000000000000000002A000000000000006F00000012000000000000000000000005000000000000005E010000120000000000000000000000310000000000000074000000120000000000000000000000FF000000000000005E02000012000000000000000000000007000000000000004C000000120000000000000000000000A1000000000000007701000012000000000000000000000025000000000000000F0200001200000000000000000000006301000000000000DE0000001200000000000000000000007B01000000000000300100001200000000000000000000007504000000000000D90000001200000000000000000000000E00000000000000250200001200000000000000000000001100000000000000100200001200000000000000000000008000000000000000990000001200000000000000000000008000000000000000AF000000120000000000000000000000C20000000000000039020000120000000000000000000000C0000000000000002A01000012000000000000000000000025000000000000008B0100001200000000000000000000001200000000000000B20100001200000000000000000000006501000000000000520100001200000020174000000000001300000000000000005F5F676D6F6E5F73746172745F5F005F4A765F5265676973746572436C6173736573006C6962707468726561642E736F2E30007265637666726F6D00707468726561645F6372656174650073656E64746F0070617573650077616974005F5F6572726E6F5F6C6F636174696F6E00666F726B00707468726561645F7369676D61736B00636F6E6E65637400707468726561645F73656C660061636365707400707468726561645F6465746163680066636E746C006C6962632E736F2E3600736F636B65740073747263707900657869740068746F6E73007372616E6400696E65745F61746F6E00676574707775696400636C6F736564697200696E65745F6E746F61006765746772676964007374726E637079006461656D6F6E006C697374656E0073656C656374006D6B646972007265616C6C6F6300676574706964006B696C6C00737472746F6B006C63686F776E00616C706861736F7274363400736967656D707479736574006D656D73657400726D6469720062696E6400667365656B0063686469720061736374696D6500676574736F636B6F7074006772616E74707400647570320073696761646473657400696E65745F616464720066636C6F736500736574736F636B6F7074006D616C6C6F6300737472636174007265616C706174680072656D6F7665006F70656E64697200696F63746C00676574686F737462796E616D65006578656376650066777269746500667265616400756E6C6F636B7074006C6F63616C74696D65007363616E64697236340072656164646972363400736C6565700073657473696400756E616D65006D656D6D6F766500666F70656E3634005F5F6C6962635F73746172745F6D61696E006E746F687300736E7072696E74660066726565005F5F7873746174363400474C4942435F322E322E3500474C4942435F322E3300000002000200020003000200020002000300030002000200020000000000020002000200020002000300020002000200020002000200020002000300020002000200040002000200030002000300020002000200030002000200020002000200030002000200020002000200020003000200020003000200020002000300020003000200030002000200020002000200020003000300030002000200020002000200000001000100240000001000000020000000751A690900000300960200000000000001000200B500000010000000000000001369690D00000400A202000010000000751A6909000002009602000000000000C881600000000000060000000D0000000000000000000000E88160000000000007000000010000000000000000000000F08160000000000007000000020000000000000000000000F881600000000000070000000300000000000000000000000082600000000000070000000400000000000000000000000882600000000000070000000500000000000000000000001082600000000000070000000600000000000000000000001882600000000000070000000700000000000000000000002082600000000000070000000800000000000000000000002882600000000000070000000900000000000000000000003082600000000000070000000A00000000000000000000003882600000000000070000000B00000000000000000000004082600000000000070000000C00000000000000000000004882600000000000070000000F00000000000000000000005082600000000000070000001000000000000000000000005882600000000000070000001100000000000000000000006082600000000000070000001200000000000000000000006882600000000000070000001300000000000000000000007082600000000000070000001400
        
        */

        $bp = { 7F??4C4602??01??000000000000000002??3E????0000????1A????0000000040000000000000??????0000000000000000000040??????????????1D????????0000????????????000000000000??????4000000000??????4000000000????01??00000000????01??00000000????000000000000????0000??????0000????000000000000????4000000000000002????000000001C??0000000000001C??00000000000001??00000000000001??000005????????0000000000000000??????0000000000004000000000????76??00000000????76??000000000000????00000000????0000????0000000080????00000000????????????0000????????????000038??00000000000080??????00000000000020??0000000002??0000060000????80????0000000028??????????000028??????????0000A0????????0000????????????0000????000000000000??????000004??00001C??0000000000001C??4000000000??????4000000000????000000000000????000000000000??????00000000000050E5??6404??00009C6D0000000000009C6D4000000000??????????????0000DC??000000000000DC??00000000000004??00000000000051E5??64??000000000000000000000000000000000000000000000000000000000000000000000000000000000000????000000000000????6C69????????????2D????????78??78??362D????????6F2E32??04??000010??000001??0000474E5500000000????0000????0000????000000000000????0000??????000001??000006000000000000????000020??0000??????00007D??5A580000000000000000000000000000000000000000000000000000000015????????00000000000000000000??????00000000000082????????00000000000000000000????????????0000????????????00000000000000000000????????????0000??????000012??0000000000000000000062??0000000000006A??000012??000000000000000000001B??0000000000007E??000012??000000000000000000008B??0000000000004902??????00000000000000000000????????????0000????????????00000000000000000000????????00000000??????000012??000000000000000000008E??000000000000F401??????00000000000000000000????????????0000????????????00000000000000000000????000000000000????01??????00000000000000000000????????????0000????0000????000000000000000000000000000000000000????0000????000000000000000000000000000000000000??????000012??0000000000000000000025????????0000????????????00000000000000000000????000000000000????0000????00000000000000000000????000000000000????01??????00000000000000000000????????????0000????0000????00000000000000000000????000000000000????02??????00000000000000000000????????????0000????01??????00000000000000000000??????0000000000006602??????00000000000000000000????????????0000??????000012??0000000000000000000025????????0000????01??????00000000000000000000????000000000000????????????00000000000000000000????000000000000????01??????00000000000000000000????000000000000????0000????00000000000000000000????01??00000000????????????00000000000000000000????????????0000????????????00000000000000000000??????000000000000EC01??????00000000000000000000??????0000000000004B01??????00000000000000000000????????????0000??????000012??0000000000000000000025????????0000????01??????00000000000000000000????????????0000??????000012??0000000000000000000008??0000000000004302??????00000000000000000000????????????0000??????????????000000000000000000000A??0000000000003F01??????00000000000000000000????????????0000??????000012??00000000000000000000F0????00000000????01??????00000000000000000000??????????????00002F02??????00000000000000000000????01??00000000????????????00000000000000000000????000000000000??????????????0000000000000000000080????00000000????02??????00000000000000000000????000000000000??????000012??0000000000000000000074??000000000000BF????????00000000000000000000????????????0000????02??????00000000000000000000??????000000000000FA0000????00000000000000000000????????????0000??????000012??0000000000000000000011??000000000000A8??000012??0000000000000000000044000000000000??????000012??000000000000000000005A000000000000??????000012??0000000000000000000029??000000000000C6????????00000000000000000000????000000000000????????????00000000000000000000????000000000000????0000????00000000000000000000????????00000000????????????00000000000000000000??????000000000000BC????????00000000000000000000????02??00000000????01??????00000000000000000000??????00000000000034??000012??00000000000000000000A1????????0000????????????00000000000000000000????????????0000??????????????000000000000000000004B000000000000????0000????00000000000000000000????000000000000??????000012??0000000000000000000005????????0000??????000012??0000000000000000000031??00000000000074??000012??00000000000000000000FF??0000000000005E02??????00000000000000000000????000000000000????????????00000000000000000000????????????0000??????000012??0000000000000000000025????????0000????02??????00000000000000000000??????000000000000DE??000012??000000000000000000007B??00000000000030??000012??0000000000000000000075??000000000000D9??000012??000000000000000000000E000000000000????????????00000000000000000000????000000000000????02??????00000000000000000000????????????0000????????????00000000000000000000????????????0000????????????00000000000000000000????000000000000????02??????00000000000000000000????000000000000????01??????00000000000000000000????????????0000????????????00000000000000000000????000000000000????????????00000000000000000000??????0000000000005201??????0000????174000000000????00000000000000005F5F676D6F6E5F73??6172??5F5F??????76??52656769????????????6173??6573??6C69????????????61642E????2E30??72??63????72??6D??????68????????5F63????6174????????6E6474????????75??65??????69??????????????6E6F5F6C6F63????69????????????6B????74??72??6164??73??676D6173????????6E6E6563??????74??72??6164??73??6C66??????63????74??70??68????????5F6465????63????6663????6C????????63??73??2E????????63????74??73??72??70????????69????????????????????616E64??????6574??6174??6E??????74??77??69??????????????6469????????????5F6E74??61??????74??72??69??????????????70??????????6D6F6E????????74??6E??????6C6563??????6B????????72??616C6C6F63??676574??69??????????????73??72??6F6B????63????77????????70??6173??72??3634??73??67656D70??79??6574??6D656D73??74??72??6469??????????????????6565??????68????????6173??74??6D65??????74??6F63????70????????616E74??74??6475??32??73??67616464????74??69????????????6472??6663??????65??????74??6F63????70????????6C6C6F63??73??72??6174??72??616C70??74????????6D6F76????????656E6469????????????6C??????74??6F73??62????616D65??????6563??????????72??74????????656164??????6C6F63????74??6C6F63????74??6D65??????616E6469????????????616464??????????????6565????73??74??69????????????????????6D6D6F76????????70??6E3634??5F5F6C69????????????72??5F6D6169????????????73??73??70??69????????????65????????78??74??74??34??474C4942435F32??32??35????????42435F32??33??000002??02??02??03??02??02??02??03??03??02??02??02??0000000002??02??02??02??02??03??02??02??02??02??02??02??02??02??03??02??02??02??04??02??02??03??02??03??02??02??02??03??02??02??02??02??02??03??02??02??02??02??02??02??03??02??02??03??02??02??02??03??02??03??02??03??02??02??02??02??02??02??03??03??03??02??02??02??02??02??000001??01??24??000010??000020??000075??69??????????9602??00000000????????????????????000000000000????69????????????A2????????0000??????69??????????9602??00000000????81????????????060000????????????000000000000????81????????????070000????00000000000000000000????81????????????070000????00000000000000000000????81????????????070000????00000000000000000000000082??????0000????0000??????0000000000000000000008??????????0000070000????????????000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000????82??????0000????0000????00000000000000000000??????6000000000????0000??????000000000000000000004882??????0000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000????00000000000000000000??????6000000000????0000?????? }
    
    condition:

        uint16(0) == 0x457f and 
        filesize < 100KB and 
        all of them
}
rule Impacket_Tools_Generic_1 {
   meta:
      description = "Compiled Impacket Tools"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      super_rule = 1
      hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
      hash2 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
      hash3 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
      hash4 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
      hash5 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"
      hash6 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
      hash7 = "dc85a3944fcb8cc0991be100859c4e1bf84062f7428c4dc27c71e08d88383c98"
      hash8 = "0f7f0d8afb230c31fe6cf349c4012b430fc3d6722289938f7e33ea15b2996e1b"
      hash9 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
      hash10 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"
      hash11 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
      hash12 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
      hash13 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
      hash14 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
      hash15 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
      hash16 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
      hash17 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"
      hash18 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
      hash19 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
      hash20 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
      id = "d2ce6426-d165-5569-a992-268f05622653"
   strings:
      $s1 = "bpywintypes27.dll" fullword ascii
      $s2 = "hZFtPC" fullword ascii
      $s3 = "impacket" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and all of ($s*) ) or ( all of them )
}
rule win_winnti_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.winnti."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winnti"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 51 52 8bce e8???????? 53 8bf8 ff15???????? }
            // n = 7, score = 200
            //   51                   | mov                 esi, eax
            //   52                   | add                 esp, 4
            //   8bce                 | test                esi, esi
            //   e8????????           |                     
            //   53                   | jne                 0x12
            //   8bf8                 | pop                 edi
            //   ff15????????         |                     

        $sequence_1 = { ff15???????? 663dffff 747b 663dfeff 7475 8b942494020000 83c9ff }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   663dffff             | pop                 esi
            //   747b                 | or                  eax, 0xffffffff
            //   663dfeff             | push                1
            //   7475                 | push                edx
            //   8b942494020000       | push                2
            //   83c9ff               | mov                 dword ptr [esp + 0x3c], esi

        $sequence_2 = { c22000 8b4d00 56 6a03 68c8000000 51 ff15???????? }
            // n = 7, score = 200
            //   c22000               | mov                 eax, dword ptr [esi + 0x3c]
            //   8b4d00               | xor                 edx, edx
            //   56                   | add                 esp, 4
            //   6a03                 | test                ebx, ebx
            //   68c8000000           | je                  0xe2
            //   51                   | push                ebp
            //   ff15????????         |                     

        $sequence_3 = { 8bf0 83c404 85f6 7509 5f 5e 83c8ff }
            // n = 7, score = 200
            //   8bf0                 | lea                 edx, [0x16e1]
            //   83c404               | mov                 cl, 0x2e
            //   85f6                 | dec                 eax
            //   7509                 | sub                 edx, eax
            //   5f                   | dec                 esp
            //   5e                   | sub                 eax, ecx
            //   83c8ff               | nop                 dword ptr [eax]

        $sequence_4 = { 807a025c 75bf 83c203 8a0a 56 33f6 b801000000 }
            // n = 7, score = 200
            //   807a025c             | mov                 ebp, dword ptr [esp + 0x30]
            //   75bf                 | push                esi
            //   83c203               | push                edi
            //   8a0a                 | mov                 dword ptr [esi + 8], ebx
            //   56                   | mov                 dword ptr [esi + 0xc], ebx
            //   33f6                 | call                edi
            //   b801000000           | push                eax

        $sequence_5 = { 895e08 895e0c ffd7 50 }
            // n = 4, score = 200
            //   895e08               | inc                 edi
            //   895e0c               | lea                 ecx, [edx + ebx]
            //   ffd7                 | jne                 0xfffffffa
            //   50                   | dec                 eax

        $sequence_6 = { 83c404 85db 0f84da000000 55 8b6c2430 56 57 }
            // n = 7, score = 200
            //   83c404               | dec                 eax
            //   85db                 | add                 esi, edi
            //   0f84da000000         | dec                 esp
            //   55                   | add                 esi, edi
            //   8b6c2430             | inc                 ecx
            //   56                   | dec                 edx
            //   57                   | nop                 word ptr [eax + eax]

        $sequence_7 = { 6a01 52 6a02 8974243c 89742430 c644244800 ff15???????? }
            // n = 7, score = 200
            //   6a01                 | inc                 ecx
            //   52                   | movzx               eax, byte ptr [eax + ecx + 1]
            //   6a02                 | mov                 byte ptr [ecx], dl
            //   8974243c             | ret                 
            //   89742430             | mov                 ecx, dword ptr [esi + 0x54]
            //   c644244800           | inc                 esp
            //   ff15????????         |                     

        $sequence_8 = { 488d8a40000000 e9???????? 488b8a40000000 4883c108 e9???????? 488b8a80000000 e9???????? }
            // n = 7, score = 100
            //   488d8a40000000       | push                ebx
            //   e9????????           |                     
            //   488b8a40000000       | mov                 edi, eax
            //   4883c108             | cmp                 ax, 0xffff
            //   e9????????           |                     
            //   488b8a80000000       | je                  0x81
            //   e9????????           |                     

        $sequence_9 = { 48037c2470 48897c2478 488b8c2400010000 4885c9 741f 4183fe01 7513 }
            // n = 7, score = 100
            //   48037c2470           | inc                 ecx
            //   48897c2478           | push                edi
            //   488b8c2400010000     | dec                 eax
            //   4885c9               | sub                 esp, 0x30
            //   741f                 | dec                 esp
            //   4183fe01             | mov                 esi, ecx
            //   7513                 | xor                 edi, edi

        $sequence_10 = { 4c8d25b6f10000 498b0c24 4d8bc5 488bd3 e8???????? 85c0 }
            // n = 6, score = 100
            //   4c8d25b6f10000       | inc                 esp
            //   498b0c24             | mov                 dword ptr [ecx + edi + 0x1c], ebx
            //   4d8bc5               | dec                 ecx
            //   488bd3               | arpl                bx, cx
            //   e8????????           |                     
            //   85c0                 | dec                 eax

        $sequence_11 = { 4803f7 4c03f7 41ffca 660f1f840000000000 478d0c1a }
            // n = 5, score = 100
            //   4803f7               | inc                 ecx
            //   4c03f7               | cmp                 esi, 1
            //   41ffca               | jne                 0x2b
            //   660f1f840000000000     | dec    eax
            //   478d0c1a             | lea                 edx, [esp + 0x50]

        $sequence_12 = { 75f8 488d15e1160000 b12e 482bd0 }
            // n = 4, score = 100
            //   75f8                 | inc                 esp
            //   488d15e1160000       | cmp                 byte ptr [esp + 0x50], dh
            //   b12e                 | je                  0xc
            //   482bd0               | nop                 

        $sequence_13 = { 4963f9 48897db7 453bc5 0f8e4f020000 418bc0 412bc5 448be0 }
            // n = 7, score = 100
            //   4963f9               | cmp                 ax, 0xfffe
            //   48897db7             | je                  0x81
            //   453bc5               | mov                 edx, dword ptr [esp + 0x294]
            //   0f8e4f020000         | or                  ecx, 0xffffffff
            //   418bc0               | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   412bc5               | mov                 eax, dword ptr [esp + 0x164]
            //   448be0               | mov                 ecx, edx

        $sequence_14 = { 3918 0f4c18 3bcb 0f8d87000000 488d3d979c0a00 ba58000000 488bcd }
            // n = 7, score = 100
            //   3918                 | and                 ecx, 3
            //   0f4c18               | push                eax
            //   3bcb                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   0f8d87000000         | mov                 ecx, dword ptr [esp + 0x164]
            //   488d3d979c0a00       | dec                 eax
            //   ba58000000           | lea                 ebx, [0xadeb]
            //   488bcd               | dec                 eax

        $sequence_15 = { 4c2bc1 0f1f00 410fb6440801 8811 }
            // n = 4, score = 100
            //   4c2bc1               | dec                 eax
            //   0f1f00               | inc                 edx
            //   410fb6440801         | dec                 eax
            //   8811                 | mov                 dword ptr [esp + 0x10], edx

        $sequence_16 = { 4d85ed 7429 488d15fcd70a00 498bcd }
            // n = 4, score = 100
            //   4d85ed               | mov                 edx, ecx
            //   7429                 | dec                 eax
            //   488d15fcd70a00       | sar                 edx, 0x10
            //   498bcd               | dec                 ecx

        $sequence_17 = { 4c8bc7 48894768 488d4567 ba18822200 }
            // n = 4, score = 100
            //   4c8bc7               | dec                 esp
            //   48894768             | mov                 eax, edi
            //   488d4567             | dec                 eax
            //   ba18822200           | mov                 dword ptr [edi + 0x68], eax

        $sequence_18 = { 4889542410 53 4881ecb0000000 33db }
            // n = 4, score = 100
            //   4889542410           | mov                 ecx, dword ptr [esp + 0x100]
            //   53                   | dec                 eax
            //   4881ecb0000000       | test                ecx, ecx
            //   33db                 | je                  0x31

        $sequence_19 = { 488d542450 4438742450 740a 6690 48ffc2 }
            // n = 5, score = 100
            //   488d542450           | dec                 eax
            //   4438742450           | add                 edi, dword ptr [esp + 0x70]
            //   740a                 | dec                 eax
            //   6690                 | mov                 dword ptr [esp + 0x78], edi
            //   48ffc2               | dec                 eax

        $sequence_20 = { 488d1debad0000 488d3d64ae0000 eb0e 488b03 4885c0 7402 }
            // n = 6, score = 100
            //   488d1debad0000       | push                ecx
            //   488d3d64ae0000       | cmp                 byte ptr [edx + 2], 0x5c
            //   eb0e                 | jne                 0xffffffc1
            //   488b03               | add                 edx, 3
            //   4885c0               | mov                 cl, byte ptr [edx]
            //   7402                 | push                esi

        $sequence_21 = { 8a45d9 4b8b8cf800a20b00 88443139 4b8b84f800a20b00 8854303a eb4c 493bde }
            // n = 7, score = 100
            //   8a45d9               | lea                 edi, [0xae64]
            //   4b8b8cf800a20b00     | jmp                 0x17
            //   88443139             | dec                 eax
            //   4b8b84f800a20b00     | mov                 eax, dword ptr [ebx]
            //   8854303a             | dec                 eax
            //   eb4c                 | test                eax, eax
            //   493bde               | je                  0x13

        $sequence_22 = { 57 4156 4157 4883ec30 4c8bf1 33ff }
            // n = 6, score = 100
            //   57                   | dec                 eax
            //   4156                 | lea                 eax, [ebp + 0x67]
            //   4157                 | mov                 edx, 0x228218
            //   4883ec30             | push                edi
            //   4c8bf1               | inc                 ecx
            //   33ff                 | push                esi

        $sequence_23 = { 44895c391c 4963cb 488bd1 48c1fa10 498b8680000000 }
            // n = 5, score = 100
            //   44895c391c           | xor                 esi, esi
            //   4963cb               | mov                 eax, 1
            //   488bd1               | push                ecx
            //   48c1fa10             | push                edx
            //   498b8680000000       | mov                 ecx, esi

    condition:
        7 of them and filesize < 1581056
}
rule pwnlnx_backdoor_variant_4 {

    meta:
    
        description = "Rule to detect the backdoor pwnlnx variant 4"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Pwnlnx"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "2590ab56d46ff344f2aa4998efd1db216850bdddfc146d5d37e4b7d07c7336fc"
    
    strings:

        /*

        7F454C4602010100000000000000000001003E000100000000000000000000000000000000000000A82803000000000000000000400000000000400031002E00040000001400000003000000474E5500089FECFBE5E7F9736AEBF52A0D3FF3394571C0BD000000000000000000000000554889E553E800000000FF1425000000004889C74889C34881E7FFFFFEFFFF1425000000004889D85BC9C30F1F440000554889E5E800000000FF142500000000C9C366666666662E0F1F840000000000554889E5E8000000004885FF74524C8B47184D85C0744965488B0425000000008B80A80400004889150000000048C7C20000000089C1C1F91FC1E91601C825FF03000029C848984C8904C500000000FF1500000000C9C3660F1F84000000000031C0C9C36666662E0F1F840000000000554889E5E8000000004889150000000048C7C200000000FF1500000000C9C390554889E5E8000000008B96C0000000488B8ED0000000488D14110FB642093C06400F94C73C11410F94C174144084FF750FB801000000C9C30F1F8400000000008B050000000039420C74253B421074204584C9742B8B86BC0000004801C10FB705000000006639017406663B410275C14889F741FFD0B802000000C9C30F1F004084FF74AC8B86BC0000004801C10FB7050000000066390175D0EBD40F1F4000554889E5534883EC08E80000000031D24889F331F6E800000000483D00F0FFFF772F4885DB7417488B5018488B5210488B52E8488B525848899AF800000031F64889C7E80000000031C04883C4085BC9C383C8FFEBF4662E0F1F840000000000554889E5415453E8000000004989F44889D331F631D2E800000000483D00F0FFFF7733488B501831F64889C7488B5210488B52E8488B5258488B8AF800000049890C2448899AF8000000E80000000031C05B415CC9C383C8FFEBF60F1F440000554889E5534883EC08E80000000031D24889F331F6E800000000483D00F0FFFF772F4885DB7417488B5018488B5210488B52E8488B525848899A0001000031F64889C7E80000000031C04883C4085BC9C383C8FFEBF4662E0F1F840000000000554889E5415453E8000000004989F44889D331F631D2E800000000483D00F0FFFF7733488B501831F64889C7488B5210488B52E8488B5258488B8A0001000049890C2448899A00010000E80000000031C05B415CC9C383C8FFEBF60F1F440000554889E5534883EC08E80000000031D24889F3BE00000100E800000000483D00F0FFFF77204885DB7408488B502048895A3031F64889C7E80000000031C04883C4085BC9C383C8FFEBF4660F1F440000554889E5415453E8000000004989F44889D3BE0000010031D2E800000000483D00F0FFFF7725488B502031F64889C7488B523049891424488B502048895A30E80000000031C05B415CC9C383C8FFEBF6554889E54157415641554154534883EC28E8000000004889F3488D75C84989FF4189D54889DFBA0A0000004989CC44894DB84D89C6E800000000488B1500000000448B4DB84881FA00000000488D4AF87517EB340F1F4000488B51084881FA00000000488D4AF8741F0FB752F84839D075E64883C42831C05B415C415D415E415FC9C30F1F4400004D89F04C89E14489EA4889DE4C89FFFF15000000004883C4285B415C415D415E415FC9C30F1F4000554889E54157415641554154534883EC38E80000000065488B04250000000048897DB848894DB04189D48B80A80400004889F3B90200000048C7C6000000004889DF4D89C54589CE89C2C1FA1FC1EA1601D025FF03000029D0F3A648984C8B3CC5000000000F84D5000000B90300000048C7C6000000004889DFF3A60F84BE00000031F64585E44889D848895DC8448965C47431418D5424FF31F6488D7C13010FB6084883C0014889CA48C1E10448C1EA044801CA4801F24839F8488D0C92488D344A75DB8975C0488D75C04C89FFE8000000004885C04889C10F84A1000000488B41104885C07446817854FFCB00F10F847A000000488B0500000000483D000000004C8D78F87517EB350F1F440000498B4708483D000000004C8D78F87420498B374889DFE80000000085C075E131C04883C4385B415C415D415E415FC9C34589F14D89E8488B4DB04489E24889DE488B7DB8FF15000000004883C4385B415C415D415E415FC9C30F1F8000000000817850852DB6950F8579FFFFFF31C0EBB0488D75C04C89FFE8000000004885C04889C1749A498B7F10488B87F8000000488B40084885C0748631D24889CE48894DA8FFD04885C0488B4DA80F841FFFFFFF31C0E969FFFFFF0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E5534883EC08E80000000089FA488B3D000000004881FF00000000488D5FF87425663957F8750CEB240F1F4000663950F8741A488B4308483D00000000488D58F84889C775E74883C4085BC9C3E8000000004889DFE8000000004883C4085BC9C36666662E0F1F840000000000554889E541554154534883EC08E8000000004C8B25000000004989FD4981FC00000000498D5C24F87518EB3D0F1F40004C8B63084981FC00000000498D5C24F87427488B334C89EFE80000000085C075DF4C89E7E800000000488B3BE8000000004889DFE8000000004883C4085B415C415DC9C36666662E0F1F840000000000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5534883EC08E800000000488B3500000000BAD000000089FBBF18000000E8000000004885C0741A668918488B1500000000488D780848C7C600000000E8000000004883C4085BC9C30F1F4000554889E5

        */

        $bp = { 7F??4C4602??01??000000000000000001??3E????000000000000000000000000000000000000????????????000000000000??????0000000040??????????????000014??000003??0000474E55????9FECFBE5??F973??EB??2A??????????71??BD????????0000000000000000554889??53E8????????FF????????????4889??4889??4881??????????FF????????????4889??5BC9C30F1F??????554889??E8????????FF????????????C9C366666666????????????????????554889??E8????????4885??74??4C8B????4D85??74??65??8B????????????8B??????????4889??????????48C7??????????89??C1????C1????01??25????????29??48984C89????????????FF??????????C9C3660F1F????????????31??C9C36666662E????????????????554889??E8????????4889??????????48C7??????????FF??????????C9C390554889??E8????????8B??????????488B??????????488D????0FB6????3C??400F94??3C??410F94??74??4084??75??B8????????C9C30F1F????????????8B??????????39????74??3B????74??4584??74??8B??????????4801??0FB7??????????66????74??66??????75??4889??41FF??B8????????C9C30F1F??4084??74??8B??????????4801??0FB7??????????66????75??EB??0F1F????554889??534883????E8????????31??4889??31??E8????????483D????????77??4885??74??488B????488B????488B????488B????4889??????????31??4889??E8????????31??4883????5BC9C383????EB??662E0F1F????????????554889??415453E8????????4989??4889??31??31??E8????????483D????????77??488B????31??4889??488B????488B????488B????488B??????????4989????4889??????????E8????????31??5B415CC9C383????EB??0F1F??????554889??534883????E8????????31??4889??31??E8????????483D????????77??4885??74??488B????488B????488B????488B????4889??????????31??4889??E8????????31??4883????5BC9C383????EB??662E0F1F????????????554889??415453E8????????4989??4889??31??31??E8????????483D????????77??488B????31??4889??488B????488B????488B????488B??????????4989????4889??????????E8????????31??5B415CC9C383????EB??0F1F??????554889??534883????E8????????31??4889??BE????????E8????????483D????????77??4885??74??488B????4889????31??4889??E8????????31??4883????5BC9C383????EB??660F1F??????554889??415453E8????????4989??4889??BE????????31??E8????????483D????????77??488B????31??4889??488B????4989????488B????4889????E8????????31??5B415CC9C383????EB??554889??4157415641554154534883????E8????????4889??488D????4989??4189??4889??BA????????4989??4489????4D89??E8????????488B??????????448B????4881??????????488D????75??EB??0F1F????488B????4881??????????488D????74??0FB7????4839??75??4883????31??5B415C415D415E415FC9C30F1F??????4D89??4C89??4489??4889??4C89??FF??????????4883????5B415C415D415E415FC9C30F1F????554889??4157415641554154534883????E8????????65??8B????????????4889????4889????4189??8B??????????4889??B9????????48C7??????????4889??4D89??4589??89??C1????C1????01??25????????29??F3A648984C8B????????????0F84????????B9????????48C7??????????4889??F3A60F84????????31??4585??4889??4889????4489????74??418D??????31??488D??????0FB6??4883????4889??48C1????48C1????4801??4801??4839??488D????488D????75??89????488D????4C89??E8????????4885??4889??0F84????????488B????4885??74??81????????????0F84????????488B??????????483D????????4C8D????75??EB??0F1F??????498B????483D????????4C8D????74??498B??4889??E8????????85??75??31??4883????5B415C415D415E415FC9C34589??4D89??488B????4489??4889??488B????FF??????????4883????5B415C415D415E415FC9C30F1F??????????81????????????0F85????????31??EB??488D????4C89??E8????????4885??4889??74??498B????488B??????????488B????4885??74??31??4889??4889????FF??4885??488B????0F84????????31??E9????????0F1F????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??534883????E8????????89??488B??????????4881??????????488D????74??66??????75??EB??0F1F????66??????74??488B????483D????????488D????4889??75??4883????5BC9C3E8????????4889??E8????????4883????5BC9C36666662E????????????????554889??41554154534883????E8????????4C8B??????????4989??4981??????????498D??????75??EB??0F1F????4C8B????4981??????????498D??????74??488B??4C89??E8????????85??75??4C89??E8????????488B??E8????????4889??E8????????4883????5B415C415DC9C36666662E????????????????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889??534883????E8????????488B??????????BA????????89??BF????????E8????????4885??74??66????488B??????????488D????48C7??????????E8????????4883????5BC9C30F1F????554889?? }

        condition:

            uint16(0) == 0x457f and 
            filesize < 400KB and 
            all of them
}
