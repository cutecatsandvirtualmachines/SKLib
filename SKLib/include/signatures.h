#pragma once

/**

 * Returns a 16-bit signature built from 2 ASCII characters.

 *

 * This macro returns a 16-bit value built from the two ASCII characters

 * specified by A and B.

 *

 * @A: The first ASCII character.

 * @B: The second ASCII character.

 *

 * @return: A 16-bit value built from the two ASCII characters specified by

 *          A and B.

 */

#define SIGNATURE_16(A, B)	((A) | (B << 8))

 /**

  * Returns a 32-bit signature built from 4 ASCII characters.

  *

  * This macro returns a 32-bit value built from the four ASCII characters

  * specified by A, B, C, and D.

  *

  * @A: The first ASCII character.

  * @B: The second ASCII character.

  * @C: The third ASCII character.

  * @D: The fourth ASCII character.

  *

  * @return: A 32-bit value built from the two ASCII characters specified by

  *          A, B, C and D.

  */

#define SIGNATURE_32(A, B, C, D)	\
	(SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))

/**

 * Returns a 64-bit signature built from 8 ASCII characters.

 *

 * This macro returns a 64-bit value built from the eight ASCII characters

 * specified by A, B, C, D, E, F, G,and H.

 *

 * @A: The first ASCII character.

 * @B: The second ASCII character.

 * @C: The third ASCII character.

 * @D: The fourth ASCII character.

 * @E: The fifth ASCII character.

 * @F: The sixth ASCII character.

 * @G: The seventh ASCII character.

 * @H: The eighth ASCII character.

 *

 * @return: A 64-bit value built from the two ASCII characters specified by

 *          A, B, C, D, E, F, G and H.

 */

#define SIGNATURE_64(A, B, C, D, E, F, G, H)	\
	(SIGNATURE_32(A, B, C, D) | ((u64)(SIGNATURE_32(E, F, G, H)) << 32))

namespace signatures {
	constexpr PCHAR PsEnumProcesses = (PCHAR)"\x33\xD2\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x33\x00\x33\xC9";
	constexpr PCHAR PsEnumProcessThreads = (PCHAR)"\x0F\x84\x00\x00\x00\x00\x4C\x8B\xC6\x48\x8D\x15\x00\x00\x00\x00\x48\x8B\x00\xE8";
	constexpr PCHAR NtCreateUserProcess = (PCHAR)"\x33\xD2\x48\x8D\x8D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x89\xBD";
	constexpr PCHAR PspInsertProcess = (PCHAR)"\x44\x8B\x84\x24\x00\x00\x00\x00\x49\x8B\x00\x48\x8B\x8C\x24\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B";
	constexpr PCHAR PspTerminateProcess = (PCHAR)"\xE8\x00\x00\x00\x00\xBA\x50\x73\x54\x65\x00\x8B\x00\x8B";
	constexpr PCHAR PspCreateProcess = (PCHAR)"\x41\x8B\xD3\x49\x8B\xCA\xE8\x00\x00\x00\x00\x48\x83\xC4";
	constexpr PCHAR NtResumeThread = (PCHAR)"\x48\x89\x44\x24\x28\xC7\x44\x24\x20\x50\x73\x53\x75";
	constexpr PCHAR NtCreateUserThread = (PCHAR)"\x24\x60\x4C\x89\x7C\x24\x28\x4C\x89\x74\x24\x20\xE8\x00\x00\x00\x00\x85\xC0";
	constexpr PCHAR KeResumeThread = (PCHAR)"\x8D\xB3\xE0\x02\x00\x00\x00\x8B\xCE\xE8";
	constexpr PCHAR PspCreateThread = (PCHAR)"\x4C\x8B\x45\x00\x8B\x55\x00\x48\x8B\xCE\xE8";

	namespace masks {
		constexpr PCHAR PsEnumProcesses = (PCHAR)"xxxxx????x????x?xx";
		constexpr PCHAR PsEnumProcessThreads = (PCHAR)"xx????xxxxxx????xx?x";
		constexpr PCHAR NtCreateUserProcess = (PCHAR)"xxxxx????x????xxx";
		constexpr PCHAR PspInsertProcess = (PCHAR)"xxxx????xx?xxxx????x????x";
		constexpr PCHAR PspTerminateProcess = (PCHAR)"x????xxxxx?x?x";
		constexpr PCHAR PspCreateProcess = (PCHAR)"xxxxxxx????xxx";
		constexpr PCHAR NtResumeThread = (PCHAR)"xxxxxxxxxxxxx";
		constexpr PCHAR NtCreateUserThread = (PCHAR)"xxxxxxxxxxxxx????xx";
		constexpr PCHAR KeResumeThread = (PCHAR)"xxxxxx?xxx";
		constexpr PCHAR PspCreateThread = (PCHAR)"xxx?xx?xxxx";
	}
}