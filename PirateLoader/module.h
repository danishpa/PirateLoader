#pragma once

#include <vector>
#include <string>
#include <windows.h>
#include "common/common.h"

using std::vector;
using std::string;

namespace pirateloader {
namespace dllloader {

	using DllEntryProc = BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID);
	using DllExportedFunction = void *;


	class Module {

	public:
		Module(const vector<byte>& dll_buffer);
		virtual ~Module();

		DllExportedFunction get_proc_address(const string& export_name);
		string get_module_name();

	private:
		VirtualMemoryPtr m_base_memory;
		string m_name;

		void allocate_and_copy_headers(const vector<byte>& dll_buffer);
		void allocate_and_copy_sections(const vector<byte>& dll_buffer);
		void perform_base_relocations();
		void resolve_imports();
		void fixup_sections();
		void call_dllmain(DWORD reason);
	};

}
}
