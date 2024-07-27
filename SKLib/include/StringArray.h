#pragma once
#include "cpp.h"

template<typename T>
class StringArray {
private:
	T* _array;
	int _length;
	int _sz;

	int strlen(const T* pString) {
		int i = 0;
		while (pString[i] != 0) {
			i++;
		}
		return i;
	}
	void strcpy(T* dst, T* src) {
		int i = 0;
		while (src[i] != 0) {
			dst[i] = src[i];
			i++;
		}
		dst[i] = 0;
	}
public:
#ifdef _KERNEL_MODE
	void Init(const T* pString) {
		_length = this->strlen(pString) + 1;
		_array = (T*)cpp::kMalloc(_length + 2);
		this->strcpy((T*)_array, (T*)pString);
		_array[_length] = 0;
		_sz = 1;
	}
	void Dispose() {
		cpp::kFree(_array);
	}

	StringArray() {
		T t[2] = { 0 };
		t[0] = ' ';
		Init(t);
	}
	StringArray(const T* pString) {
		Init(pString);
	}
	~StringArray() {
		Dispose();
	}

	T* Append(T* pString) {
		if (!_array) {
			Init(pString);
			return &_array[0];
		}
		int len = this->strlen(pString);
		T* pNewArray = (T*)cpp::kMalloc(_length + len + 3);

		RtlCopyMemory(pNewArray, _array, _length + 1);
		strcpy(pNewArray + _length + 1, pString);
		_length += len + 1;
		_sz++;
		cpp::kFree(_array);
		_array = pNewArray;
		_array[_length] = 0;
		return &_array[_length + 1];
	}
#endif

	T* at(int i) {
		int currLen = 0;
		for (int idx = 0; idx < min(i, _sz); idx++) {
			currLen += this->strlen(_array + currLen) + 1;
		}
		return _array + currLen;
	}

	T* operator[](int i) {
		return this->at(i);
	}

	int length() {
		return _length;
	}
	int size() {
		return _sz;
	}
};
