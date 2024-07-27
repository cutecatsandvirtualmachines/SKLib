#pragma once

#include "cpp.h"
#include "spinlock.h"

#ifdef _KERNEL_MODE
#ifndef _WDMDDK_
#include <ntifs.h>
#endif

void mbstowcs(wchar_t* dst, char* src, size_t len);
void wcstombs(char* dst, wchar_t* src, size_t len);

struct string {
private:
	bool bDisposed;
	size_t len;
	Spinlock lock;
public:
	char* pBuffer;
	wchar_t* lpBuffer;
	UNICODE_STRING uBuffer;

	string();
	string(const char* pString);
	string(const wchar_t* pWString);
	string(UNICODE_STRING* pWString);
	string(string&& obj);
	string(string& obj);
	static string* create(const char* pString);
	~string();
	void Dispose(); //c# style memory free
	size_t Length();
	const char* c_str();
	const wchar_t* w_str();
	UNICODE_STRING& unicode();
	string substring(int index);
	string substring(int index, int length);
	int last_of(char to_find);
	int first_of(char to_find);
	char* to_lower();
	char* to_upper();
	wchar_t* to_lowerw();
	wchar_t* to_upperw();
	bool contains(const char* pSubstring);

	string& operator+(const char* pString) {
		if (pString == nullptr)
			return *this;

		lock.Lock();
		auto length = len + (int)strlen(pString);
		auto buffer = (char*)cpp::kMallocZero((size_t)length + 1);
		if (buffer == nullptr) return *this;
		RtlZeroMemory((void*)buffer, (size_t)length + 1);
		memcpy((void*)buffer, pBuffer, len);
		strcat((char*)buffer, pString);
		lock.Unlock();

		return *string::create(buffer);
	}
	string& operator+(string& pString) {
		return *this + pString.c_str();
	}
	void operator+=(const char* pString) {
		if (pString == nullptr)
			return;

		lock.Lock();
		auto length = len + (int)strlen(pString);
		auto buffer = (char*)cpp::kMalloc((size_t)length + 1);
		if (buffer == nullptr) {
			lock.Unlock();
			return;
		}
		RtlZeroMemory((void*)buffer, (size_t)length + 1);
		memcpy((void*)buffer, pBuffer, len);
		strcat((char*)buffer, pString);
		lock.Unlock();
		Dispose();
		lock.Lock();
		bDisposed = false;
		this->pBuffer = buffer;
		this->len = length;
		lock.Unlock();
	}
	void operator+=(string& string) {
		lock.Lock();
		auto length = len + (int)string.Length();
		auto buffer = (char*)cpp::kMalloc((size_t)length + 1);
		if (buffer == nullptr) {
			lock.Unlock();
			return;
		}
		RtlZeroMemory((void*)buffer, (size_t)length + 1);
		memcpy((void*)buffer, pBuffer, len);
		strcat((char*)buffer, string.c_str());
		lock.Unlock();
		Dispose();
		lock.Lock();
		bDisposed = false;
		this->pBuffer = buffer;
		this->len = length;
		lock.Unlock();
	}
	void operator=(const string& obj) {
		if (&obj == this
			|| obj.pBuffer == this->pBuffer
			)
			return;
		Dispose();
		lock.Lock();
		bDisposed = false;
		pBuffer = (char*)cpp::kMalloc((size_t)obj.len + 1);
		//RtlZeroMemory((void*)pBuffer, (size_t)obj.len + 1);
		memcpy((void*)pBuffer, obj.pBuffer, obj.len + 1);
		len = obj.len;
		lock.Unlock();
	}
	void operator=(const char* pString) {
		Dispose();
		lock.Lock();
		bDisposed = false;
		len = strlen(pString);
		pBuffer = (char*)cpp::kMalloc((size_t)len + 1);
		strcpy((char*)pBuffer, pString);
		lock.Unlock();
	}
	bool operator==(string& rhs) {
		lock.Lock();
		bool bSuccess = !strcmp(this->c_str(), rhs.c_str());
		lock.Unlock();
		return bSuccess;
	}
	bool operator!=(string& rhs) {
		return !(*this == rhs);
	}
	bool operator==(string&& rhs) {
		return *this == rhs;
	}
	bool operator!=(string&& rhs) {
		return !(*this == rhs);
	}

	static string* alloc(char* s) {
		string* pString = (string*)cpp::kMalloc(sizeof(*pString));
		RtlZeroMemory(pString, sizeof(*pString));
		pString->len = 0;
		pString->pBuffer = nullptr;
		pString->uBuffer.Buffer = nullptr;
		pString->lpBuffer = nullptr;
		pString->bDisposed = false;
		pString->lock.Init();

		*pString = s;
		return pString;
	}
};
#endif