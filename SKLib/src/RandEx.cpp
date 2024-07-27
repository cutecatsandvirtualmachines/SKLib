#include "RandEx.h"

random::Random random::rnd;

ULONG random::Random::getRandom() {
#ifndef ENABLE_PREDICTABLE_RANDOM
	if (_eSecLevel == SecurityLevel::PREDICTABLE)
		_eSecLevel = SecurityLevel::SECURE;
#endif

	if (_eSecLevel == random::SecurityLevel::PREDICTABLE) {
		if (_seed == 0) {
			_seed = 987654321;
		}
		_seed = 8253729 * _seed + 2396403;
	}
	else if (_eSecLevel == SecurityLevel::PSEUDO) {
		_seed = KeQueryTimeIncrement();
	}
	else {
		if (!_rdrand32_step((unsigned int*)&_seed)) {
			if (_seed == 0) {
				_seed = 987654321;
			}
			_seed = 8253729 * _seed + 2396403;
		}
	}
	return _seed;
}

random::Random::Random(SecurityLevel eSecLevl)
{
	if (eSecLevl == SecurityLevel::PSEUDO) {
		_seed = KeQueryTimeIncrement();
	}
	else if (eSecLevl == SecurityLevel::PREDICTABLE) {
		_seed = 0;
	}
	else {
		if (!_rdrand32_step((unsigned int*)&_seed)) {
			_seed = KeQueryTimeIncrement(); //Fallback to pseudo random seed
			DbgMsg("[RANDOM] Error: could not fetch an hardware generated random seed");
		}
	}

	_eSecLevel = eSecLevl;
	_xorKey = this->Next(1ull, MAXULONG64);
}

random::Random::Random(ULONG seed)
{
	_eSecLevel = SecurityLevel::PREDICTABLE;
	_seed = seed;
	_xorKey = this->Next(1ull, MAXULONG64);
}

void random::Random::setSeed(ULONG seed)
{
	_eSecLevel = SecurityLevel::PREDICTABLE;
	_seed = seed;
}

void random::Random::setSecLevel(SecurityLevel eSecLevel)
{
	_eSecLevel = eSecLevel;
}

size_t random::Random::Next(size_t begin, size_t end)
{
	size_t ret = 0;
	ret = getRandom();
	ret <<= 32;
	ret |= getRandom();
	ret %= end;
	if (ret < begin)
		ret += begin;
	return ret;
}

int random::Random::Next(int begin, int end)
{
	return (int)Next((size_t)begin, (size_t)end);
}

size_t random::Random::NextPredictable(size_t begin, size_t end)
{
	if (!end) {
		return 1;
	}
	size_t ret = 0;
	ret = begin ^ (size_t)_AddressOfReturnAddress();
	ret <<= 32;
	ret |= begin ^ _xorKey;
	ret %= end;
	if (ret < begin)
		ret += begin;
	return ret;
}

int random::Random::NextPredictable(int begin, int end)
{
	return (int)NextPredictable((size_t)begin, (size_t)end);
}

size_t random::Random::XorPredictable(size_t number) {
	if (_xorKey == 0) {
		_xorKey = 987654321;
	}
	_xorKey = 8253729 * _xorKey + 2396403;
	return number ^ _xorKey;
}

int random::Random::XorPredictable(int number) {
	return (int)XorPredictable((size_t)number);
}

string random::Random::String(size_t sz)
{
	char pBuf[RND_STRING_MAX_LEN] = { 0 };

	if (sz < RND_STRING_MAX_LEN - 1) {
		c_str(pBuf, sz);
	}
	else {
		DbgMsg("[RANDOM] Warning: attempted to generate %lld characters, current max is %d", sz, RND_STRING_MAX_LEN - 1);
	}

	return pBuf;
}

void random::Random::bytes(char* pOut, size_t sz) {
	for (int n = 0; n < sz; n++)
	{
		pOut[n] = (char)getRandom();
	}
}

void random::Random::c_str(char* pOut, size_t sz)
{
	static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	for (int n = 0; n < sz; n++)
	{
		int key = getRandom() % (int)(sizeof(charset) - 1);
		pOut[n] = charset[key];
	}
	pOut[sz] = 0;
}

void random::Random::w_str(wchar_t* pOut, size_t sz)
{
	static wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	for (int n = 0; n < sz; n++)
	{
		int key = getRandom() % (int)((sizeof(charset) / 2) - 1);
		pOut[n] = charset[key];
	}
	pOut[sz] = 0;
}

void random::Random::c_str_upper(char* pOut, size_t sz)
{
	static char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	for (int n = 0; n < sz; n++)
	{
		int key = getRandom() % (int)(sizeof(charset) - 1);
		pOut[n] = charset[key];
	}
	pOut[sz] = 0;
}

void random::Random::w_str_upper(wchar_t* pOut, size_t sz)
{
	static wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	for (int n = 0; n < sz; n++)
	{
		int key = getRandom() % (int)((sizeof(charset) / 2) - 1);
		pOut[n] = charset[key];
	}
	pOut[sz] = 0;
}

void random::Random::c_str_hex(char* pOut, size_t sz)
{
	static char charset[] = "ABCDEF0123456789";

	for (int n = 0; n < sz; n++)
	{
		int key = getRandom() % (int)(sizeof(charset) - 1);
		pOut[n] = charset[key];
	}
	pOut[sz] = 0;
}

void random::Random::w_str_hex(wchar_t* pOut, size_t sz)
{
	static wchar_t charset[] = L"ABCDEF0123456789";

	for (int n = 0; n < sz; n++)
	{
		int key = getRandom() % (int)((sizeof(charset) / 2) - 1);
		pOut[n] = charset[key];
	}
	pOut[sz] = 0;
}

void random::Regenerate(SecurityLevel eSecLevl)
{
	Random r(eSecLevl);
	rnd = r;
}

size_t random::Next(size_t begin, size_t end)
{
	return rnd.Next(begin, end);
}

size_t random::NextHardware(size_t begin, size_t end)
{
	ULONGLONG seed;
	_rdrand64_step(&seed);
	seed %= end;
	if (seed < begin)
		seed += begin;
	return seed;
}

int random::Next32(int begin, int end)
{
	return rnd.Next(begin, end);
}

string random::String(size_t sz)
{
	return rnd.String(sz);
}

void random::c_str(char* pOut, size_t sz)
{
	rnd.c_str(pOut, sz);
}

void random::w_str(wchar_t* pOut, size_t sz)
{
	rnd.w_str(pOut, sz);
}
