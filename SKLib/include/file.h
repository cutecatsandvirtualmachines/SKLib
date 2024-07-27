#pragma once

#include "cpp.h"
#include "winternlex.h"

namespace file {
	class fstream {
	private:
		HANDLE hFile;
		OBJECT_ATTRIBUTES ObjectAttributes;

	public:
		fstream(string&& path);
		fstream(string& path);
		~fstream();

		HANDLE Handle();
	};
}
