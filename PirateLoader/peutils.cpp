#include "peutils.h"

#include <ctime>
#include <vector>
#include <string>
#include <Windows.h>
#include "common/common.h"

using std::vector;
using std::string;

namespace pirateloader {
namespace peutils {
	
	static const DWORD PE_HEADER_MAGIC = 0x00004550;
	static const size_t PE_TIMESTAMP_CTIME_FORMAT_MAX_BUFFER_SIZE = 150;

#ifdef _WIN64
	static const WORD EXPECTED_MACHINE_VERSION = IMAGE_FILE_MACHINE_AMD64;
#else
	static const WORD EXPECTED_MACHINE_VERSION = IMAGE_FILE_MACHINE_I386;
#endif

	void verify_pe(const vector<byte>& buffer) {
		if (buffer.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER)) {
			TRACE_AND_THROW(DllMagicException, "Buffer is too small to be a dll (size=%lu)", buffer.size());
		}

		auto magic = ((PIMAGE_DOS_HEADER)(buffer.data()))->e_magic;
		if (IMAGE_DOS_SIGNATURE != magic) {
			TRACE_AND_THROW(DllMagicException, "Dll magic MZ does not appear! (actual=%hu)", magic);
		}

		auto pe_header = get_pe_header_pointer(buffer);
		if (PE_HEADER_MAGIC != pe_header->Signature) {
			TRACE_AND_THROW(PEMagicException, "PE Magic mismatch (expected=0x%x, actual=0x%x)", PE_HEADER_MAGIC, pe_header->Signature);
		}

		// Check architecture
		if (EXPECTED_MACHINE_VERSION != pe_header->FileHeader.Machine) {
			TRACE_AND_THROW(ArchitectureException, "Architecure mismatch (expected=%lu, actual=%lu)", EXPECTED_MACHINE_VERSION, pe_header->FileHeader.Machine);
		}

		TRACE("Dll Magic and Architecture verified")
	}

	PIMAGE_NT_HEADERS get_pe_header_pointer(HMODULE module) {
		return (PIMAGE_NT_HEADERS)((PBYTE)(module) + ((PIMAGE_DOS_HEADER)(module))->e_lfanew);
	}
	
	PIMAGE_NT_HEADERS get_pe_header_pointer(const VirtualMemoryPtr& memory) {
		return get_pe_header_pointer((HMODULE)memory.get());
	}

	PIMAGE_NT_HEADERS get_pe_header_pointer(const vector<byte>& dll_buffer) {
		return (PIMAGE_NT_HEADERS)(dll_buffer.data() + ((PIMAGE_DOS_HEADER)(dll_buffer.data()))->e_lfanew);
	}

	string format_timestamp(DWORD raw_timestamp) {
		auto timestamp = static_cast<__time32_t>(raw_timestamp);
		vector<byte> timestamp_vector(PE_TIMESTAMP_CTIME_FORMAT_MAX_BUFFER_SIZE, 0);

		auto res = _ctime32_s((char *)(timestamp_vector.data()), timestamp_vector.size(), &timestamp);
		if (0 != res) {
			TRACE_AND_THROW(TimeStampFormatException, "_ctime32_s Failed (res=%d)", res);
		}

		auto timestamp_string = string((const char *)timestamp_vector.data());
		timestamp_string.pop_back(); // remove newline
		return timestamp_string;
	}

	void display_pe_header_statistics(const PIMAGE_NT_HEADERS32& pe_header) {
		if (PE_HEADER_MAGIC != pe_header->Signature) {
			TRACE_AND_THROW(PEMagicException, "PE Magic mismatch (expected=0x%x, actual=0x%x)", PE_HEADER_MAGIC, pe_header->Signature);
		}

		cout << "PE Header Statistics" << endl;
		cout << "\tTimestamp: " << format_timestamp(pe_header->FileHeader.TimeDateStamp) << endl;
		cout << "\tSections: " << pe_header->FileHeader.NumberOfSections << endl;
		cout << "\tOptionalHeaderSize: " << pe_header->FileHeader.SizeOfOptionalHeader << endl;
	}

	PIMAGE_SECTION_HEADER get_first_section(const PIMAGE_NT_HEADERS32& pe_header) {
		return IMAGE_FIRST_SECTION(pe_header);
	}

	string get_section_name(const PIMAGE_SECTION_HEADER& section_header) {
		string section_name((const char *)section_header->Name, (const char *)section_header->Name + sizeof(section_header->Name));
		section_name.push_back(0);
		return section_name;
	}

	DWORD get_page_protection(const PIMAGE_SECTION_HEADER& section) {
		auto characteristics = section->Characteristics;
		if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
			return  PAGE_EXECUTE_READ;
		}
		else if ((characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE)) {
			return PAGE_READWRITE;
		}
		else if (characteristics & IMAGE_SCN_MEM_READ) {
			return PAGE_READONLY;
		}

		return PAGE_NOACCESS;
	}

	vector<byte> get_dll_buffer(const string& path) {
		// Open dll
		FileHandle handle(CreateFile(path.c_str(), FILE_READ_ACCESS, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
		if (invalid(handle)) {
			TRACE_AND_THROW_WINAPI(CreateFileFailedException, CreateFile);
		}

		// Detrmine size of dll to allocate buffer
		LARGE_INTEGER file_size = { 0 };
		if (!GetFileSizeEx(handle.get(), &file_size)) {
			TRACE_AND_THROW_WINAPI(GetFileSizeFailedException, GetFileSize);
		}
		if (0 != file_size.HighPart) {
			TRACE_AND_THROW(DllTooLargeException, "Dll is too large to load (name=%hs, size=%llu)", path.c_str(), file_size.QuadPart);
		}
		TRACE("Found Dll \"%hs\", size=%lu", path.c_str(), file_size.LowPart);

		// Read dll into buffer
		DWORD bytes_read = 0;
		vector<byte> buffer(file_size.LowPart, 0);
		if (!ReadFile(handle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, NULL)) {
			TRACE_AND_THROW_WINAPI(ReadFileFailedException, ReadFile);
		}
		if (bytes_read != buffer.size()) {
			TRACE_AND_THROW(ReadFileSizeMismatchException, "FileRead did not read expected byte count (expected=%lu, read=%lu)", buffer.size(), bytes_read);
		}

		return std::move(buffer);
	}

}
}