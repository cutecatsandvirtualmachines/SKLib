#include "StringEx.h"

#pragma warning (disable : 4267)

//Length without null terminator
void mbstowcs(wchar_t* dst, char* src, size_t len)
{
	for (size_t i = 0; i < len + 1; i++) {
		*(char*)&dst[i] = src[i];
		*((char*)&dst[i] + 1) = 0x00;
	}
}

void wcstombs(char* dst, wchar_t* src, size_t len) {
	for (size_t i = 0; i < len + 1; i++) {
		dst[i] = *(char*)&src[i];
	}
}

string::string()
{
	len = 0;
	pBuffer = nullptr;
	uBuffer.Buffer = nullptr;
	lpBuffer = nullptr;
	bDisposed = false;
	lock.Init();
}

string::string(const char* pString) {
	len = strlen(pString);
	pBuffer = (char*)cpp::kMalloc((size_t)len + 1, PAGE_READWRITE);
	strcpy((char*)pBuffer, pString);
	uBuffer.Buffer = nullptr;
	lpBuffer = nullptr;
	bDisposed = false;
}

string::string(const wchar_t* pWString)
{
	len = wcslen(pWString);
	pBuffer = (char*)cpp::kMalloc((size_t)len + 1, PAGE_READWRITE);
	for (int i = 0; i <= len; i++) {
		pBuffer[i] = (char)pWString[i];
	}
	uBuffer.Buffer = nullptr;
	lpBuffer = nullptr;
	bDisposed = false;
}

string::string(UNICODE_STRING* pWString) {
	len = pWString->Length / 2;
	pBuffer = (char*)cpp::kMalloc((size_t)len + 1, PAGE_READWRITE);
	for (int i = 0; i <= len; i++) {
		pBuffer[i] = (char)pWString->Buffer[i];
	}
	uBuffer.Buffer = nullptr;
	lpBuffer = nullptr;
	bDisposed = false;
}

void string::Dispose()
{
	lock.Lock();
	bDisposed = true;
	if (pBuffer) {
		cpp::kFree((void*)pBuffer);
		pBuffer = nullptr;
	}
	if (uBuffer.Buffer) {
		cpp::kFree((void*)uBuffer.Buffer);
		uBuffer.Buffer = nullptr;
	}
	if (lpBuffer) {
		cpp::kFree((void*)lpBuffer);
		lpBuffer = nullptr;
	}
	lock.Unlock();
}

string* string::create(const char* pString)
{
	auto pNewString = (string*)cpp::kMallocZero((size_t)sizeof(string));
	pNewString->len = strlen(pString);
	pNewString->pBuffer = (char*)cpp::kMalloc(pNewString->len + 1, PAGE_READWRITE);
	pNewString->uBuffer.Buffer = nullptr;
	pNewString->lpBuffer = nullptr;
	strcpy((char*)pNewString->pBuffer, pString);
	pNewString->bDisposed = false;
	return pNewString;
}

string::string(string&& obj)
{
	len = obj.len;
	pBuffer = nullptr;
	lpBuffer = nullptr;
	uBuffer = { 0 };

	if (obj.pBuffer) {
		pBuffer = (char*)cpp::kMalloc(len + 1, PAGE_READWRITE);
		memcpy(pBuffer, obj.pBuffer, len + 1);
	}
	if (obj.lpBuffer) {
		lpBuffer = (wchar_t*)cpp::kMalloc((len + 1) * 2, PAGE_READWRITE);
		memcpy(lpBuffer, obj.lpBuffer, (len + 1) * 2);
	}
	if (obj.uBuffer.Buffer) {
		uBuffer = obj.uBuffer;
		uBuffer.Buffer = (wchar_t*)cpp::kMalloc((len + 1) * 2, PAGE_READWRITE);
		memcpy(uBuffer.Buffer, obj.uBuffer.Buffer, (len + 1) * 2);
	}
}

string::string(string& obj)
{
	len = obj.len;
	pBuffer = nullptr;
	lpBuffer = nullptr;
	uBuffer = { 0 };

	if (obj.pBuffer) {
		pBuffer = (char*)cpp::kMalloc(len + 1, PAGE_READWRITE);
		memcpy(pBuffer, obj.pBuffer, len + 1);
	}
	if (obj.lpBuffer) {
		lpBuffer = (wchar_t*)cpp::kMalloc((len + 1) * 2, PAGE_READWRITE);
		memcpy(lpBuffer, obj.lpBuffer, (len + 1) * 2);
	}
	if (obj.uBuffer.Buffer) {
		uBuffer = obj.uBuffer;
		uBuffer.Buffer = (wchar_t*)cpp::kMalloc((len + 1) * 2, PAGE_READWRITE);
		memcpy(uBuffer.Buffer, obj.uBuffer.Buffer, (len + 1) * 2);
	}
}

string::~string()
{
	Dispose();
}

UNICODE_STRING& string::unicode()
{
	lock.Lock();
	if (!uBuffer.Buffer) {
		wchar_t* buf = (wchar_t*)cpp::kMalloc((len + 1) * 2, PAGE_READWRITE);
		mbstowcs(buf, (char*)pBuffer, len);
		RtlInitUnicodeString(&uBuffer, buf);
	}
	lock.Unlock();

	return uBuffer;
}

string string::substring(int index)
{
	lock.Lock();
	char* char_arr = (char*)cpp::kMalloc(len - index + 1, PAGE_READWRITE);
	memcpy(char_arr, pBuffer + index, len - index);
	char_arr[len - index] = 0;
	string pRetValue(char_arr);

	cpp::kFree(char_arr);
	lock.Unlock();
	return pRetValue;
}

string string::substring(int index, int length)
{
	lock.Lock();
	char* char_arr = (char*)cpp::kMalloc(len - index + 1, PAGE_READWRITE);
	if (len < (index + length)) {
		memcpy(char_arr, this->c_str() + index, len - index);
		char_arr[len - index + 1] = 0;
	}
	else {
		memcpy(char_arr, this->c_str() + index, length);
		char_arr[len - index] = 0;
	}
	string pRetValue(char_arr);
	cpp::kFree(char_arr);
	lock.Unlock();
	return pRetValue;
}

int string::last_of(char to_find)
{
	lock.Lock();
	for (int i = len; i > 0; i--) {
		if (this->c_str()[i] == to_find) {
			lock.Unlock();
			return i;
		}
	}
	lock.Unlock();
	return 0;
}

int string::first_of(char to_find)
{
	lock.Lock();
	for (int i = 0; i < len; i++) {
		if (this->c_str()[i] == to_find) {
			lock.Unlock();
			return i;
		}
	}
	lock.Unlock();
	return 0;
}

char* string::to_lower()
{
	lock.Lock();
	for (char* p = (char*)this->c_str(); *p; p++) *p = (char)tolower(*p);
	lock.Unlock();
	return (char*)this->c_str();
}

char* string::to_upper()
{
	lock.Lock();
	for (char* p = (char*)this->c_str(); *p; p++) *p = (char)toupper(*p);
	lock.Unlock();
	return (char*)this->c_str();
}

wchar_t* string::to_lowerw()
{
	lock.Lock();
	for (wchar_t* p = (wchar_t*)this->w_str(); *p; p++) *p = (wchar_t)towlower(*p);
	lock.Unlock();
	return (wchar_t*)this->w_str();
}

wchar_t* string::to_upperw()
{
	lock.Lock();
	for (wchar_t* p = (wchar_t*)this->w_str(); *p; p++) *p = (wchar_t)towupper(*p);
	lock.Unlock();
	return (wchar_t*)this->w_str();
}

bool string::contains(const char* pSubstring)
{
	lock.Lock();
	int substrLen = strlen(pSubstring);
	if (substrLen > len
		|| !substrLen) {
		lock.Unlock();
		return false;
	}

	for (int i = 0; i <= len - substrLen; i++) {
		if (!memcmp(pSubstring, &pBuffer[i], substrLen)) {
			lock.Unlock();
			return true;
		}
	}
	lock.Unlock();
	return false;
}

size_t string::Length()
{
	return len;
}

const char* string::c_str() {
	if (bDisposed)
		return "";

	return pBuffer;
}

const wchar_t* string::w_str()
{
	if (bDisposed)
		return L"";

	lock.Lock();
	if (!lpBuffer) {
		lpBuffer = (wchar_t*)cpp::kMalloc((len + 1) * 2, PAGE_READWRITE);
		mbstowcs(lpBuffer, pBuffer, len);
	}
	lock.Unlock();
	return lpBuffer;
}
