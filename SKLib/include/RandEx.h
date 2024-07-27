#pragma once

#include <immintrin.h>

#include "macros.h"
#include "cpp.h"
#include "cpu.h"
#include "StringEx.h"
#include "std.h"

#define RND_STRING_MAX_LEN 256

namespace random {
	enum class SecurityLevel {
		PSEUDO = 0,
		SECURE,
		PREDICTABLE
	};
	class Random {
	private:
		SecurityLevel _eSecLevel;
		ULONG _seed;
		ULONG64 _xorKey;
		ULONG getRandom();

	public:
		Random(SecurityLevel eSecLevl = SecurityLevel::PREDICTABLE);
		Random(ULONG seed);

		void setSeed(ULONG seed);
		void setSecLevel(SecurityLevel eSecLevel);

		size_t Next(size_t begin, size_t end);
		int Next(int begin, int end);
		size_t NextPredictable(size_t begin, size_t end);
		int NextPredictable(int begin, int end);
		size_t XorPredictable(size_t number);
		int XorPredictable(int number);
#ifdef _KERNEL_MODE
		string String(size_t sz);
		void bytes(char* pOut, size_t sz);
		void c_str(char* pOut, size_t sz);
		void w_str(wchar_t* pOut, size_t sz);
		void c_str_upper(char* pOut, size_t sz);
		void w_str_upper(wchar_t* pOut, size_t sz);
		void c_str_hex(char* pOut, size_t sz);
		void w_str_hex(wchar_t* pOut, size_t sz);

		template<typename T>
		void random_shuffle(T* pStr, int sz) {
			for (int i = sz - 1; i >= 0; --i) {
				cpp::swap(pStr[i], pStr[Next(0, i + 1)]);
			}
		}

		template<typename T>
		void random_shuffle_ignore_chars(T* pStr, int sz, T* ignore = "", int ignoreLen = 0) {
			for (int i = sz - 1; i >= 0; --i) {
				auto rndSelect = Next(0, i + 1);
				bool bIgnore = false;
				for (int j = 0; j < ignoreLen; j++) {
					if (ignore[j] == pStr[i]) {
						bIgnore = true;
						break;
					}
					while (ignore[j] == pStr[rndSelect]) {
						rndSelect = (++rndSelect) % (i + 1);
					}
				}
				if (!bIgnore) {
					cpp::swap(pStr[i], pStr[rndSelect]);
				}
			}
		}

		template<typename T>
		void predictable_shuffle(T* pStr, int sz) {
			for (int i = sz - 1; i >= 0; --i) {
				cpp::swap(pStr[i], pStr[NextPredictable(0, i)]);
			}
		}

		template<typename T>
		void predictable_xor(T* pStr, int sz) {
			static char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			for (int i = sz - 1; i >= 0; --i) {
				pStr[i] = (T)XorPredictable((int)pStr[i]);
				pStr[i] = charset[pStr[i] % sizeof(charset)];
			}
		}
#endif
	};

	extern Random rnd;

	void Regenerate(SecurityLevel eSecLevl = SecurityLevel::PSEUDO);

	size_t Next(size_t begin, size_t end);
	size_t NextHardware(size_t begin, size_t end);
	int Next32(int begin, int end);
#ifdef _KERNEL_MODE
	string String(size_t sz);
	void c_str(char* pOut, size_t sz);
	void w_str(wchar_t* pOut, size_t sz);
#endif
}