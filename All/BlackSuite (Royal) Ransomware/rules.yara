private rule is_executable {

	condition:
  
		uint32(uint32(0x3C)) == 0x00004550
}

rule obfuscates_dlls {

	strings:

		// Code for unscrambling names of true DLL imports
		$code_load_obfuscated = {
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
			c6 84 24 ?? 00 00 00 ??
		}
		// c6 84 24 ?? 00 00 00 ?? | MOV byte ptr [ESP + ??], ??
		$code_deobfuscate = { 99 f7 ?? 8d ?? ?? 99 f7 ?? 88}
			// 99 | CDQ
			// f7 ?? | IDIV ??
			// 8d ?? ?? | LEA ??, ??
			// 99 | CDQ
			// f7 ?? | IDIV ??
			// 88 | MOV
  
	condition:
  
		all of them
}

rule calls_rsa_function {

	strings:
		
		// Code for function calls using RSA key
		$code_rsa_function_1 = { 8d4c2410 6a?? 6a?? 51 6a?? 6a?? 6a?? 68???????? ffd0 }
			// 8d 4c 24 10 | LEA ECX, [esp + 0x10]
			// 6a ?? | PUSH ??
			// 6a ?? | PUSH ??
			// 51 | PUSH ECX
			// 6a ?? | PUSH ??
			// 6a ?? | PUSH ??
			// 6a ?? | PUSH ??
			// 68 ?? ?? ?? ?? | PUSH (address of RSA string)
			// ff d0 | CALL EAX
		$code_rsa_function_2 = { 8d4c2410 6a?? 6a?? 51 56 6a?? 6a?? 68???????? ffd0 }
			// 8d 4c 24 10 | LEA ECX, [esp + 0x10]
			// 6a ?? | PUSH ??
			// 6a ?? | PUSH ??
			// 51 | PUSH ECX
			// 56 | PUSH ESI
			// 6a ?? | PUSH ??
			// 6a ?? | PUSH ??
			// 68 ?? ?? ?? ?? | PUSH (address of RSA string)
			// ff d0 | CALL EAX
  
	condition:
  
		any of them
}

rule xor_decoder_functions {

	strings:
  
		// Functions 402e00 and 402f00 both appear to contain a xor-decoding loop
		// 402e00
		$code_xor_loop_1 = { 0f a4 ce ?? 0f ac d5 ?? c1 e1 ?? c1 ea ?? 0b cd 0b f2 99 33 c8 }
			// 0f a4 ce ?? | SHLD ESI, param_1, ??
			// 0f ac d5 ?? | SHRD EBP, EDX, ??
			// c1 e1 ?? | SHL param_1, ??
			// c1 ea ?? | SHR EDX, 0x19
			// 0b cd | OR param_1, EBP
			// 0b f2 | OR ESI, EDX
			// 99 | CDQ
			// 33 c8 | XOR param_1, EAX
			// 402f00
		$code_xor_loop_2 = { 0f a4 ce ?? c1 ea ?? 0b f2 c1 e1 ?? 0b c8 0f be c3 8a 1f 99 33 c8 }
			// 0f a4 ce ?? | SHLD ESI, param_1, ??
			// c1 ea ?? | SHR EDX, ??
			// 0b f2 | OR ESI, EDX
			// c1 e1 ?? | SHL, param_1, ??
			// 0b c8 | OR param_1, EDX
			// 0f be c3 | MOVSX EAX, BL
			// 8a 1f | BL, byte ptr [EDI]
			// 99 | CDQ
			// 33 c8 | XOR param_1, EAX
  
	condition:
  
		any of them
}

rule win_BlackSuit_manual {
  
	meta:
  
		author = "CVH - Raleigh"
		date = "2024-07-12"
		version = "1"
		description = "Detects win.BlackSuit. Rules were manually constructed and results should not be considered conclusive."
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.BlackSuit"
  
	strings:
  
		// Somehow keeps this in plaintext, although in UTF-16
		$string_readme = "readme.BlackSuit.txt" nocase wide ascii
		
		// RSA key for encrypting AES encryption key present in plaintext
		$string_rsa_key = "BEGIN RSA PUBLIC KEY" nocase wide ascii
		
		// Unusual debug strings
		$string_debug_1 = ".rdata$voltmd"
		$string_debug_2 = ".rdata$zzzdbg"
		
		// Relevant functions calls
		$import_1 = "MultiByteToWideChar"
		$import_2 = "EnterCriticalSection"
		$import_3 = "GetProcessHeap"

	condition:
  
		(is_executable and $string_readme)
			Or
			($string_readme and
				(obfuscates_dlls or calls_rsa_function or xor_decoder_functions)
			)
			or
			2 of (obfuscates_dlls, calls_rsa_function, xor_decoder_functions)
			or
			1 of (obfuscates_dlls, calls_rsa_function, xor_decoder_functions) and any of them
}
