#pragma once

#include "cpp.h"
#include "macros.h"
#include "spinlock.h"

template <class N>
class vIterator
{
private:
	N* pCurNode;
	int length;
	int index;

public:
	vIterator(N* pT, int len) :
		pCurNode(pT),
		length(len),
		index(0)	{};
	vIterator() :
		pCurNode(nullptr),
		length(0),
		index(0)	{};

	bool IsNull() {
		return pCurNode == nullptr;
	}
	N& operator*() const {
		return *pCurNode;
	}
	void operator++() {
		if (pCurNode && index + 1 < length) {
			index++;
			pCurNode += 1;
		}
		else if (index + 1 >= length) {
			pCurNode = nullptr;
		}
	}
	bool operator==(vIterator<N> it) {
		bool bNull = it.IsNull();
		if (pCurNode && !bNull) {
			return *pCurNode == *it;
		}
		if (IsNull() && bNull)
			return true;
		return false;
	}
	bool operator!=(vIterator<N> it) {
		return !(*this == it);
	}
};

template<typename T>
class vector {
private:
	T* pArray;
	int szLen;
	int szMax;
	Spinlock lock;
	const static int szDefaultReserve = 4;

#ifdef _KERNEL_MODE
	T& bracketOverload(int i) {
		lock.Lock();
		if (i > szMax - 1) {
			T* pNewBuf = (T*)cpp::kMalloc(sizeof(T) * (i));
			memcpy(pNewBuf, pArray, sizeof(T) * szLen);
			cpp::kFree(pArray);
			pArray = pNewBuf;

			szMax = i;
		}
		if (i < 0) {
			i = szLen - i;
		}
		if (i < 0) {
			return pArray[0];
		}
		if (i > szLen - 1) {
			szLen = i + 1;
		}
		lock.Unlock();
		return pArray[i];
	}

public:
	void Init() {
		lock.Init();
		lock.Lock();
		pArray = (T*)cpp::kMalloc(sizeof(T) * szDefaultReserve);
		szMax = szDefaultReserve;
		szLen = 0;
		lock.Unlock();
	}
	void Dispose() {
		cpp::kFree(pArray);
	}
	vector() {
		Init();
	}
	vector(int szReserve) {
		pArray = (T*)cpp::kMalloc(sizeof(T) * szReserve);
		szLen = 0;
		szMax = szReserve;
	}
	~vector() {
		Dispose();
	}

	int Insert(T& obj, int i) {
		lock.Lock();
		if (i > szLen)
			throw_std();
		if (i < 0)
			i += szLen;
		if (i < 0)
			throw_std();

		//If it doesn't fit 
		if (szLen - 1 - i > szMax) {
			T* pNewBuf = (T*)cpp::kMalloc(sizeof(T) * (szDefaultReserve + szMax + szLen));
			memcpy(pNewBuf, pArray, sizeof(T) * szLen);
			cpp::kFree(pArray);
			pArray = pNewBuf;

			szMax += szDefaultReserve;
		}
		//Move objects up
		RtlCopyMemory(&pArray[i + 1], &pArray[i], sizeof(T) * (length() - 1 - i));
		//Insert object
		new(&pArray[i]) T;
		pArray[i] = obj;

		szLen++;
		lock.Unlock();
	}
	int Insert(T&& obj, int i) {
		return Insert(obj, i);
	}
	int Append(T& obj) {
		lock.Lock();

		szLen++;

		if (szLen > szMax) {
			T* pNewBuf = (T*)cpp::kMalloc(sizeof(T) * (szMax + szLen + szDefaultReserve));
			memcpy(pNewBuf, pArray, sizeof(T) * szLen);
			cpp::kFree(pArray);
			pArray = pNewBuf;

			szMax += szDefaultReserve;
		}

		new(&pArray[szLen - 1]) T;
		pArray[szLen - 1] = obj;
		lock.Unlock();

		return length() - 1;
	}
	int Append(T&& obj) {
		return Append(obj);
	}
	template <typename ... C>
	int emplace_back(C& ... c) {
		T obj(c ...);
		lock.Lock();

		szLen++;

		if (szLen > szMax) {
			T* pNewBuf = (T*)cpp::kMalloc(sizeof(T) * (szMax + szLen + szDefaultReserve));
			memcpy(pNewBuf, pArray, sizeof(T) * szLen);
			cpp::kFree(pArray);
			pArray = pNewBuf;

			szMax += szDefaultReserve;
		}

		new(&pArray[szLen - 1]) T;
		pArray[szLen - 1] = obj;
		lock.Unlock();

		return length() - 1;
	}
	void RemoveAt(int i) {
		lock.Lock();
		if (i > size())
			throw_std();
		if (i < 0)
			i += length();
		if (i < 0)
			throw_std();
		RtlZeroMemory(&pArray[i], sizeof(T));
		if(i + 1 < length())
			RtlCopyMemory(&pArray[i], &pArray[i + 1], sizeof(T) * (length() - 1 - i));
		szLen--;
		lock.Unlock();
	}
	void Clean() {
		lock.Lock();
		RtlZeroMemory(pArray, sizeof(T) * szMax);
		szLen = 0;
		lock.Unlock();
	}
	void reserve(int szReserve) {
		lock.Lock();
		T* pNewBuf = (T*)cpp::kMalloc(sizeof(T) * (szReserve + szMax));
		memcpy(pNewBuf, pArray, sizeof(T) * szLen);
		cpp::kFree(pArray);
		pArray = pNewBuf;

		szMax += szReserve;
		lock.Unlock();
	}
	inline int size() {
		return szMax;
	}
	inline int length() {
		return szLen;
	}

	T& at(int i) {
		return bracketOverload(i);
	}
	const T& operator[](int i) const {
		return bracketOverload(i);
	}
	T& operator[](int i) {
		return bracketOverload(i);
	}
	vector<T>& operator=(vector<T>& rhs) {
		rhs.lock.Lock();
		lock.Lock();
		if (szLen < rhs.szLen) {
			szLen = rhs.szLen;
			szMax = rhs.szMax;
			cpp::kFree(pArray);
			pArray = (T*)cpp::kMalloc(szMax * sizeof(T));
		}

		for (int i = 0; i < length(); i++) {
			*(T*)&pArray[i] = rhs.pArray[i];
		}
		lock.Unlock();
		rhs.lock.Unlock();

		return *this;
	}
	bool operator==(vector<T>& rhs) {
		rhs.lock.Lock();
		lock.Lock();
		bool bRes = true;
		if (pArray != rhs.pArray) {
			for (int i = 0; i < length(); i++) {
				if (pArray[i] != rhs.pArray[i]) {
					bRes = false;
					break;
				}
			}
		}
		lock.Unlock();
		rhs.lock.Unlock();
		return bRes;
	}
	bool operator!=(vector<T>& rhs) {
		return !(rhs == *this);
	}

	void DisableLock() {
		lock.Disable();
	}

	vIterator<T> begin() {
		if (!length())
			return end();
		vIterator<T> it(pArray, length());
		return it;
	}
	vIterator<T> end() {
		vIterator<T> it(nullptr, 0);
		return it;
	}
#endif 
};
