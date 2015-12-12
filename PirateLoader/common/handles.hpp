#pragma once

#include <memory>
#include <Windows.h>

using std::unique_ptr;

namespace common {
namespace handles {

struct file_deleter {
	void operator()(HANDLE h)
	{
		::CloseHandle(h);
	}
	typedef HANDLE pointer;
};
using FileHandle = std::unique_ptr<HANDLE, file_deleter>;
inline bool valid(const FileHandle& file_handle) {
	return INVALID_HANDLE_VALUE != file_handle.get();
}


struct virtual_memory_deleter {
	void operator()(LPVOID p)
	{
		::VirtualFree(p, 0, MEM_RELEASE);
	}
	typedef LPVOID pointer;
};
using VirtualMemoryPtr = std::unique_ptr<LPVOID, virtual_memory_deleter>;
inline bool valid(const VirtualMemoryPtr& ptr) {
	return NULL != ptr.get();
}

template <typename T>
bool invalid(const T& p) {
	return !valid(p);
}

}
}

