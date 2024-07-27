#pragma once

#include "cpp.h"
#include "spinlock.h"

#ifdef _KERNEL_MODE
template <typename T>
struct node
{
	T obj;
	node<T>* fLink;
	node<T>* bLink;

	static node<T>* create(T* _obj = nullptr, node<T>* _bLink = nullptr, bool collect = true) {
		if (_obj == nullptr) return nullptr;
		node<T>* n;
		if (collect)
			n = (node<T>*) cpp::kMalloc(sizeof(node<T>));
		else
			n = (node<T>*) ExAllocatePool(NonPagedPoolNx, sizeof(node<T>));

		if (n == nullptr) return nullptr;

		n->obj = *_obj;

		n->fLink = n;
		if (_bLink == nullptr)
			n->bLink = n;
		else
			n->bLink = _bLink;
		return n;
	};
};

template <class N>
class lIterator 
{
private:
	node<N>* pCurNode;

public:
	lIterator(node<N>* pT) :
		pCurNode(pT) {};
	lIterator() :
		pCurNode(nullptr) {};

	bool IsNull() {
		return pCurNode == nullptr;
	}
	N& operator*() const {
		return pCurNode->obj;
	}
	void operator++() {
		if (pCurNode)
			if (pCurNode->fLink != pCurNode)
				pCurNode = pCurNode->fLink;
			else
				pCurNode = nullptr;
	}
	bool operator==(lIterator<N> it) {
		bool bNull = it.IsNull();
		if (pCurNode && !bNull) {
			return pCurNode->obj == *it;
		}
		if (IsNull() && bNull)
			return true;
		return false;
	}
	bool operator!=(lIterator<N> it) {
		return !(*this == it);
	}
};

//Here list is a single linked list of which last node fLink points to itself
template <class T>
class list
{
public:
	void Init(bool collect = true) {
		lock.Init();
		lock.Lock();
		firstNode = (node<T>*)this;
		lastNode = firstNode;
		length = 0;
		bCollect = collect;
		lock.Unlock();
	}
	//Constructors - Destructors
	list(bool collect = true) {
		Init(collect);
	}
	list(T&& obj, bool collect = true) {
		Init(collect);
		firstNode = node<T>::create(&obj);
		lastNode = firstNode;
		length = 1;
	};
	static list<T>* create() {
		auto vec = (list<T>*)cpp::kMalloc(sizeof(list<T>), NonPagedPoolNx, false);
		new (vec) list<T>;
		return vec;
	}
	//This will dispose of every node, but the vec obj must be disposed of manually
	void Dispose() {
		node<T>* curNode = firstNode;
		lock.Lock();
		for (size_t i = 0; i < length; i++) {
			auto nextNode = curNode->fLink;
			if (bCollect)
				cpp::kFree((void*)curNode);
			else
				ExFreePool((void*)curNode);
			curNode = nextNode;
		}
		length = 0;
		lock.Unlock();
	}
	~list() {
		Dispose();
	}

	//Methods
	int Length() {
		return length;
	}
	node<T>* FirstNode() {
		return firstNode;
	}
	node<T>* LastNode() {
		return lastNode;
	}
	T& First() {
		return firstNode->obj;
	}
	T& Last() {
		return lastNode->obj;
	}
	T& at(int index) {
		return (*this)[index];
	}
	void Remove(T& obj) {
		bool bFound = false;
		node<T>* curNode = firstNode;
		lock.Lock();
		for (size_t i = 0; i < length; i++) {
			if (obj == curNode->obj) {
				bFound = true;
				break;
			}
			curNode = curNode->fLink;
		}
		if (curNode == firstNode) {
			firstNode = curNode->fLink;
			firstNode->bLink = firstNode;
			if (length == 1) {
				//It means this is also the last node
				firstNode = (node<T>*)this;
				lastNode = firstNode;
			}
		}
		else if (curNode == lastNode) {
			if (bFound) {
				lastNode = curNode->bLink;
				lastNode->fLink = lastNode;
			}
			else {
				lock.Unlock();
				return;
			}
		}
		else {
			curNode->bLink->fLink = curNode->fLink;
			curNode->fLink->bLink = curNode->bLink;
		}
		if (bCollect)
			cpp::kFree((void*)curNode);
		else
			ExFreePool((void*)curNode);
		length--;
		lock.Unlock();
	}

	template<typename F>
	void RemoveWhere(F pCallback) {
		bool bFound = false;
		node<T>* curNode = firstNode;
		lock.Lock();
		for(size_t i = 0; i < length; i++) {
			if (pCallback(curNode->obj)) {
				bFound = true;
				break;
			}
			curNode = curNode->fLink;
		}
		if (curNode == firstNode) {
			firstNode = curNode->fLink;
			firstNode->bLink = firstNode;
			if (length == 1) {
				//It means this is also the last node
				firstNode = (node<T>*)this;
				lastNode = firstNode;
			}
		}
		else if (curNode == lastNode) {
			if (bFound) {
				lastNode = curNode->bLink;
				lastNode->fLink = lastNode;
			}
			else {
				lock.Unlock();
				return;
			}
		}
		else {
			curNode->bLink->fLink = curNode->fLink;
			curNode->fLink->bLink = curNode->bLink;
		}
		if (bCollect)
			cpp::kFree((void*)curNode);
		else
			ExFreePool((void*)curNode);
		length--;
		lock.Unlock();
	}
	bool Append(T& obj) {
		node<T>* n = node<T>::create(&obj, lastNode, bCollect);

		lock.Lock();
		n->bLink = lastNode;
		if (lastNode == firstNode)
			lastNode = n;
		lastNode->fLink = n;
		lastNode = n;
		n->fLink = n;

		//Check that firstNode is initialized
		if ((size_t)firstNode == (size_t)this)
			firstNode = lastNode;
		if (firstNode->fLink == firstNode) {
			firstNode->fLink = lastNode;
		}
		length++;
		lock.Unlock();
		return true;
	}

	template <typename ... C>
	bool emplace_back(C& ... c) {
		T obj(c ...);
		node<T>* n = node<T>::create(&obj, lastNode, bCollect);

		lock.Lock();
		if (lastNode == firstNode)
			lastNode = n;
		n->bLink = lastNode;
		lastNode->fLink = n;
		lastNode = n;
		n->fLink = n;

		if ((size_t)firstNode == (size_t)this)
			firstNode = lastNode;
		if (firstNode->fLink == firstNode) {
			firstNode->fLink = lastNode;
		}
		length++;
		lock.Unlock();
		return true;
	}
	template <typename ... C>
	bool emplace_back(C&& ... c) {
		return emplace_back(c ...);
	}
	T Pop(int index = length) {
		T ret;
		node<T>* curNode = nullptr;

		lock.Lock();
		if (index + 1 == length) {
			curNode = lastNode;
			lastNode->bLink->fLink = lastNode->bLink;
			lastNode = lastNode->bLink;
			goto _end;
		}
		if (index < length / 2) {
			curNode = firstNode;
			int t = 0;
			while (t < index) {
				curNode = curNode->fLink;
				t++;
			}
			if (!t) {
				firstNode = firstNode->fLink;
				firstNode->fLink->bLink = firstNode->fLink;
			}
		}
		else {
			curNode = lastNode;
			int t = length - 1;
			while (t > index) {
				curNode = curNode->bLink;
				t--;
			}

		}
		if (curNode == firstNode) {
			firstNode = curNode->fLink;
			firstNode->bLink = firstNode;
		}
		else if (curNode == lastNode) {
			lastNode = curNode->bLink;
			lastNode->fLink = lastNode;
		}
		else {
			curNode->bLink->fLink = curNode->fLink;
			curNode->fLink->bLink = curNode->bLink;
		}

_end:
		ret = curNode->obj;
		if (bCollect)
			cpp::kFree((void*)curNode);
		else
			ExFreePool((void*)curNode);
		length--;
		lock.Unlock();
		return ret;
	}
	void RemoveAt(int index) {
		Pop(index);
	}

	//Operators
	const T& operator[](int i) const {
		return BracketOverload(i);
	}
	T& operator[](int i) {
		return BracketOverload(i);
	}
	list<T>& operator =(list<T>& rhs) {
		lock.Lock();
		this->firstNode = rhs->firstNode;
		this->lastNode = rhs->lastNode;
		this->length = rhs->length;
		lock.Unlock();
		return *this;
	}

	//Iterable
	lIterator<T> begin() {
		if (!length)
			return end();
		return this->firstNode;
	}
	lIterator<T> end() {
		return nullptr;
	}
private:
	//Private functions used by overloads
	T& BracketOverload(int i) {
		node<T>* curNode;

		lock.Lock();
		if (i + 1 >= length) {
			curNode = lastNode;
			goto _end;
		}
		if (i < 0)
			i += length;
		if (i < 0) {
			curNode = firstNode;
			goto _end;
		}

		if (i < length / 2) {
			curNode = firstNode;
			int t = 0;
			while (t != i) {
				curNode = curNode->fLink;
				t++;
			}
		}
		else {
			curNode = lastNode;
			int t = length - 1;
			while (t != i) {
				curNode = curNode->bLink;
				t--;
			}

		}

_end:
		lock.Unlock();
		return curNode->obj;
	}

	//Variables
	Spinlock lock;
	node<T>* firstNode;
	node<T>* lastNode;
	int length;

	//Set to false if this list needs NOT to use the garbage collector
	bool bCollect;
};
#endif