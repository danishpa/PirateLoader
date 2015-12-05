#include <memory>
#include <ctime>
#include "common/common.h"
#include <Windows.h>

static const DWORD PE_HEADER_MAGIC = 0x00004550;
static const size_t PE_TIMESTAMP_CTIME_FORMAT_MAX_BUFFER_SIZE = 150;
void verify_dll_magic(const vector<byte>& buffer) {
	if (buffer.size() < 2) {
		LOG_AND_THROW(DllMagicException, "Dll is too small to contain magic (size=%lu)", buffer.size());
	}

	if (buffer[0] != 'M' || buffer[1] != 'Z') {
		LOG_AND_THROW(DllMagicException, "Dll magic MZ does not appear! (actual=%02x%02x)", buffer[0], buffer[1]);
	}

	TRACE("Dll Magic Verified")
}

auto get_dll_buffer(string path) {
	// Open dll
	FileHandle handle(CreateFile(path.c_str(), FILE_READ_ACCESS, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL));
	if (invalid(handle)) {
		LOG_AND_THROW_WINAPI(CreateFileFailedException, CreateFile);
	}
		
	// Detrmine size of dll to allocate buffer
	LARGE_INTEGER file_size = { 0 };
	if (!GetFileSizeEx(handle.get(), &file_size)) {
		LOG_AND_THROW_WINAPI(GetFileSizeFailedException, GetFileSize);
	}
	if (0 != file_size.HighPart) {
		LOG_AND_THROW(DllTooLargeException, "Dll is too large to load (name=%hs, size=%llu)", path.c_str(), file_size.QuadPart);
	}
	TRACE("Found Dll \"%hs\", size=%lu", path.c_str(), file_size.LowPart);
	
	// Read dll into buffer
	DWORD bytes_read = 0;
	vector<byte> buffer(file_size.LowPart, 0);
	if (!ReadFile(handle.get(), buffer.data(), buffer.size(), &bytes_read, NULL)) {
		LOG_AND_THROW_WINAPI(ReadFileFailedException, ReadFile);
	}
	if (bytes_read != buffer.size()) {
		LOG_AND_THROW(ReadFileSizeMismatchException, "FileRead did not read expected byte count (expected=%lu, read=%lu)", buffer.size(), bytes_read);
	}

	verify_dll_magic(buffer);
	return std::move(buffer);
}

auto get_pe_header_pointer(const vector<byte>& dll_buffer) {
	return (PIMAGE_NT_HEADERS32)(dll_buffer.data() + ((PIMAGE_DOS_HEADER)(dll_buffer.data()))->e_lfanew);
}

auto format_pe_timestamp(const PIMAGE_NT_HEADERS32 pe_header) {
	auto timestamp = static_cast<__time32_t>(pe_header->FileHeader.TimeDateStamp);
	vector<byte> timestamp_string(PE_TIMESTAMP_CTIME_FORMAT_MAX_BUFFER_SIZE, 0);

	auto res = _ctime32_s((char *)(timestamp_string.data()), timestamp_string.size(), &timestamp);
	if (0 != res) {
		LOG_AND_THROW(TimeStampFormatException, "_ctime32_s Failed (res=%d)", res);
	}

	return string((const char *)timestamp_string.data());
}

void display_pe_header_statistics(const PIMAGE_NT_HEADERS32 pe_header) {
	if (PE_HEADER_MAGIC != pe_header->Signature) {
		LOG_AND_THROW(PEMagicException, "PE Magic mismatch (expected=0x%x, actual=0x%x)", PE_HEADER_MAGIC, pe_header->Signature);
	}

	cout << "PE Header Statistics" << endl;
	cout << "\tTimestamp: " << format_pe_timestamp(pe_header);
	cout << "\tSections: " << pe_header->FileHeader.NumberOfSections << endl;
	cout << "\tSymbol Table Offset: " << pe_header->FileHeader.PointerToSymbolTable << endl;
	cout << "\tSymbols: " << pe_header->FileHeader.NumberOfSymbols << endl;
	cout << "\tOptionalHeaderSize: " << pe_header->FileHeader.SizeOfOptionalHeader << endl;
}

auto get_section_name(const PIMAGE_SECTION_HEADER section_header) {
	string section_name((const char *)section_header->Name, (const char *)section_header->Name + sizeof(section_header->Name));
	section_name.push_back(0);
	return section_name;
}

auto allocate_and_copy_sections(const vector<byte>& dll_buffer) {
	// Reserve memory for the entire image
	auto pe_header = get_pe_header_pointer(dll_buffer);
	VirtualMemoryPtr base_address(VirtualAlloc(
		NULL, // Will always relocate
		pe_header->OptionalHeader.SizeOfImage,
		MEM_RESERVE,
		PAGE_READWRITE));
	if (invalid(base_address)) {
		LOG_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
	}
	TRACE("MEM_RESERVE for Image. Got 0x%x:%x", base_address.get(), pe_header->OptionalHeader.SizeOfImage);
	// Commit each section, and copy it
	auto first_section = IMAGE_FIRST_SECTION(pe_header);

	for (auto i = 0; i < pe_header->FileHeader.NumberOfSections; ++i) {
		auto section = first_section + i;
		TRACE("%hs -> Commiting memory for section...", get_section_name(section).c_str());

		// Determine size_to_commit 
		auto size_to_commit = section->SizeOfRawData;
		if (0 == size_to_commit) {
			TRACE("Section SizeOfRawData == 0");
			if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
				size_to_commit = pe_header->OptionalHeader.SizeOfInitializedData;
				TRACE("IMAGE_SCN_CNT_INITIALIZED_DATA is set, using OptionalHeader.SizeOfInitializedData");
			}
			else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA){
				size_to_commit = pe_header->OptionalHeader.SizeOfUninitializedData;
				TRACE("IMAGE_SCN_CNT_UNINITIALIZED_DATA is set, using OptionalHeader.SizeOfUninitializedData");
			}
		}

		// If size_to_commit is bigger than 0, commit the memory. if it isn't, don't.
		if (size_to_commit > 0) {
			auto virtual_address_for_section = (LPVOID)((const PBYTE)base_address.get() + section->VirtualAddress);
			TRACE("MEM_COMMIT 0x%x:%04x...", virtual_address_for_section, size_to_commit);
			VirtualMemoryPtr section_memory(VirtualAlloc(
				virtual_address_for_section,
				size_to_commit,
				MEM_COMMIT,
				PAGE_READWRITE));
			if (invalid(section_memory)) {
				LOG_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
			}
			TRACE("Copying section RawData...")
			CopyMemory(section_memory.get(), (LPVOID)(dll_buffer.data() + section->PointerToRawData), size_to_commit);

		}
		else {
			TRACE("size_to_commit==0, will not MEM_COMMIT");
		}
		TRACE("Section Done.")
	}
	TRACE("All Sections Done.\n");
	return base_address;
}

void perform_base_relocations(const vector<byte>& dll_buffer, VirtualMemoryPtr& base_memory) {

}

int main(int argc, char *argv[]) {
	try {
		// 1. Get Buffer of DLL Check DOSHeader, PEHeader
		// 2. Try to allocate a memory block of PEHeader.OptionalHeader.SizeOfImage bytes at position PEHeader.OptionalHeader.ImageBase.
		// 3. Parse section headers and copy sections to their addresses.
		//    The destination address for each section, relative to the base of the allocated memory block, is stored in the VirtualAddress attribute of the IMAGE_SECTION_HEADER structure.
		// 4. If the allocated memory block differs from ImageBase, various references in the code and/or data sections must be adjusted. This is called Base relocation.
		// 5. The required imports for the library must be resolved by loading the corresponding libraries.
		// 6. The memory regions of the different sections must be protected depending on the section�s characteristics.
		//    Some sections are marked as discardable and therefore can be safely freed at this point.
		//    These sections normally contain temporary data that is only needed during the import, like the informations for the base relocation.
		// 7. Now the library is loaded completely. It must be notified about this by calling the entry point using the flag DLL_PROCESS_ATTACH.

		// Step 1 (No checks tho)
		auto dll_buffer = get_dll_buffer(argv[1]);
		display_pe_header_statistics(get_pe_header_pointer(dll_buffer));

		// Step 2
		auto base_memory = allocate_and_copy_sections(dll_buffer);

		// Step 3
		perform_base_relocations(dll_buffer, base_memory);


	}
	catch (const CommonException&) {
		TRACE("Caught Exception");
	}

	return 0;
}