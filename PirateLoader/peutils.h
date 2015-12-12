#pragma once

#include <vector>
#include <string>
#include <Windows.h>
#include "common/common.h"

using std::vector;
using std::string;

namespace pirateloader {
namespace peutils {

	void verify_dll_magic(const vector<byte>& buffer);

	PIMAGE_NT_HEADERS32 get_pe_header_pointer(const VirtualMemoryPtr& memory);

	PIMAGE_NT_HEADERS32 get_pe_header_pointer(const vector<byte>& dll_buffer);

	string format_timestamp(DWORD raw_timestamp);

	void display_pe_header_statistics(const PIMAGE_NT_HEADERS32& pe_header);

	PIMAGE_SECTION_HEADER get_first_section(const PIMAGE_NT_HEADERS32& pe_header);

	string get_section_name(const PIMAGE_SECTION_HEADER& section_header);

	vector<byte> get_dll_buffer(const string& path);

}
}