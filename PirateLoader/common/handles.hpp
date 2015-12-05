#pragma once

#include <memory>
#include <Windows.h>

namespace common {
namespace handles {

using std::unique_ptr;

struct file_deleter {
	void operator()(HANDLE h)
	{
		::CloseHandle(h);
	}
	typedef HANDLE pointer;
};
using FileHandle = std::unique_ptr<HANDLE, file_deleter>;
bool valid(const FileHandle& file_handle) { return INVALID_HANDLE_VALUE != file_handle.get(); }


struct virtual_memory_deleter {
	void operator()(LPVOID p)
	{
		::VirtualFree(p, 0, MEM_RELEASE);
	}
	typedef LPVOID pointer;
};
using VirtualMemoryPtr = std::unique_ptr<LPVOID, virtual_memory_deleter>;
bool valid(const VirtualMemoryPtr& ptr) { return NULL != ptr.get(); }

template <typename T>
bool invalid(const T& p) {
	return !valid(p);
}


}
}

