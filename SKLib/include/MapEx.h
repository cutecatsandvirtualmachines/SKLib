#pragma once
#ifdef _KERNEL_MODE

#include "cpp.h"
#include "ListEx.h"
#include "spinlock.h"

#pragma warning (disable:4311)
#pragma warning (disable:4302)

#define DEFAULT_MAP_SIZE 10

template<typename K, typename V>
struct MapItem {
	K key;
	V value;

	bool bValid;

	MapItem(K k, V v, bool isValid = true) {
		key = k;
		value = v;
		bValid = isValid;
	}
};

template<typename K, typename V>
class unordered_map {
public:
	void Init() {
		lock.Init();
		lock.Lock();
		length = 0;
		size = DEFAULT_MAP_SIZE;
		items = (list<MapItem<K, V>>*)cpp::kMalloc(sizeof(*items) * size);
		for (int i = 0; i < size; i++) {
			items[i].Init();
			items[i].emplace_back(K(), V());
		}
		lock.Unlock();
	}
	void Dispose() {
		lock.Lock();
		for (int i = 0; i < size; i++)
			items[i].Dispose();
		cpp::kFree(items);
		items = nullptr;
		size = 0;
		lock.Unlock();
	}
	unordered_map() {
		Init();
	}
	~unordered_map() {
		Dispose();
	}

	void Append(K& key, V& value) {
		int index = Hash(key);
		lock.Lock();
		if (!items[index].Length())
			items[index].emplace_back(key, value, false);
		MapItem<K, V>& curItem = items[index].Last();
		if (!curItem.bValid) {
			//Item is not used
			if (length == size) {
				int oldSize = size;
				size += DEFAULT_MAP_SIZE;
				list<MapItem<K, V>>* newItems = (list<MapItem<K, V>>*)cpp::kMalloc(sizeof(*newItems) * size);

				RtlZeroMemory(newItems, sizeof(*newItems) * size);
				RtlCopyMemory(newItems, items, sizeof(*newItems) * oldSize);

				cpp::kFree(items);
				items = newItems;
			}

			curItem.key = key;
			curItem.value = value;
			curItem.bValid = true;

			length++;
		}
		else {
			if (curItem.key == key) {
				curItem.value = value;
				lock.Unlock();
				return;
			}

			items[index].emplace_back(key, value, false);
		}
		lock.Unlock();
	}

	void Append(K&& key, V&& value) {
		Append(key, value);
	}
	void Append(K& key, V&& value) {
		Append(key, value);
	}
	void Append(K&& key, V& value) {
		Append(key, value);
	}
	void Clean() {
		lock.Lock();
		length = 0;
		RtlRtlZeroMemory(items, sizeof(*items) * size);
		lock.Unlock();
	}
	void reserve(int amount) {
		if (amount <= 0)
			return;

		lock.Lock();
		int oldSize = size;
		size += amount;
		list<MapItem<K, V>>* newItems = (list<MapItem<K, V>>*)cpp::kMalloc(sizeof(*items) * size);

		RtlZeroMemory(newItems, sizeof(*newItems) * size);
		RtlCopyMemory(newItems, items, sizeof(*newItems) * oldSize);

		cpp::kFree(items);
		items = newItems;

		for (int i = oldSize; i < size; i++)
			items[i].Init();
		lock.Unlock();
	}
	bool Contains(K&& key) {
		int index = Hash(key);
		return items[index].Length();
	}
	bool Contains(K& key) {
		int index = Hash(key);
		return items[index].Length();
	}

	V& Value(K&& key) {
		return BracketOverload(key);
	}
	V& Value(K& key) {
		return BracketOverload(key);
	}
	const V& operator[](K&& key) const {
		return BracketOverload(key);
	}
	V& operator[](K&& key) {
		return BracketOverload(key);
	}
	const V& operator[](K& key) const {
		return BracketOverload(key);
	}
	V& operator[](K& key) {
		return BracketOverload(key);
	}

	void DisableLock() {
		lock.Unlock();
	}

private:
	int length;
	int size;
	list<MapItem<K, V>>* items;
	Spinlock lock;

	ULONG Hash(K& value) {
		ULONG val = 0;

		for (int i = 0; i < sizeof(value) / 4; i++) {
			if(i & 1)
				val |= ((ULONG*)&value)[i];
			else
				val ^= ((ULONG*)&value)[i];
		}

		val %= size;
		return val;
	}

	V& BracketOverload(K&& key) {
		return BracketOverload(key);
	}

	V& BracketOverload(K& key) {
		lock.Lock();
		int index = Hash(key);
		if (!items[index].Length()) {
			throw_std();
		}
		MapItem<K, V>& curItem = items[index].Last();

		if (!curItem.bValid || curItem.key != key)
			throw_std();

		lock.Unlock();
		return curItem.value;
	}
};

#pragma warning (default:4311)
#pragma warning (default:4302)

#endif