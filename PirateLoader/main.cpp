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
	if (!ReadFile(handle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, NULL)) {
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

auto format_timestamp(DWORD raw_timestamp) {
	auto timestamp = static_cast<__time32_t>(raw_timestamp);
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
	cout << "\tTimestamp: " << format_timestamp(pe_header->FileHeader.TimeDateStamp);
	cout << "\tSections: " << pe_header->FileHeader.NumberOfSections << endl;
	cout << "\tOptionalHeaderSize: " << pe_header->FileHeader.SizeOfOptionalHeader << endl;
}

auto get_first_section(PIMAGE_NT_HEADERS32 pe_header) {
	return IMAGE_FIRST_SECTION(pe_header);
}

auto get_first_section(const vector<byte>& dll_buffer) {
	return get_first_section(get_pe_header_pointer(dll_buffer));
}

auto get_section_name(const PIMAGE_SECTION_HEADER section_header) {
	string section_name((const char *)section_header->Name, (const char *)section_header->Name + sizeof(section_header->Name));
	section_name.push_back(0);
	return section_name;
}

size_t get_actual_section_size(PIMAGE_NT_HEADERS32 pe_header, PIMAGE_SECTION_HEADER section) {
	// It's probably incorrect, need to check which one is true..
	auto size_to_commit = section->Misc.VirtualSize;
	
	if (0 == size_to_commit) {
		TRACE("Section SizeOfRawData == 0");
		if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			size_to_commit = pe_header->OptionalHeader.SizeOfInitializedData;
			TRACE("IMAGE_SCN_CNT_INITIALIZED_DATA is set, using OptionalHeader.SizeOfInitializedData");
		}
		else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			size_to_commit = pe_header->OptionalHeader.SizeOfUninitializedData;
			TRACE("IMAGE_SCN_CNT_UNINITIALIZED_DATA is set, using OptionalHeader.SizeOfUninitializedData");
		}
	}
	return size_to_commit;
}

auto allocate_and_copy_sections(const vector<byte>& dll_buffer) {
	// Reserve memory for the entire image
	auto pe_header = get_pe_header_pointer(dll_buffer);
	VirtualMemoryPtr base_address(VirtualAlloc(
		// NULL, // Will always relocate
		(PVOID)0x02000000,
		pe_header->OptionalHeader.SizeOfImage,
		MEM_RESERVE,
		PAGE_READWRITE));
	if (invalid(base_address)) {
		LOG_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
	}
	TRACE("MEM_RESERVE for Image. Got 0x%x:%x", base_address.get(), pe_header->OptionalHeader.SizeOfImage);
	// Commit each section, and copy it
	auto first_section = get_first_section(pe_header);

	TRACE("Iterating %hu sections", pe_header->FileHeader.NumberOfSections);
	for (auto i = 0; i < pe_header->FileHeader.NumberOfSections; ++i) {
		auto section = first_section + i;
		TRACE("%hs -> Commiting memory for section...", get_section_name(section).c_str());

		// Determine size_to_commit 
		auto size_to_commit = get_actual_section_size(pe_header, section);

		// If size_to_commit is bigger than 0, commit the memory. if it isn't, don't.
		if (size_to_commit > 0) {
			auto virtual_address_for_section = (LPVOID)((const PBYTE)base_address.get() + section->VirtualAddress);
			TRACE("MEM_COMMIT 0x%x:%04x...", virtual_address_for_section, size_to_commit);
			LPVOID section_memory = VirtualAlloc(
				virtual_address_for_section,
				size_to_commit,
				MEM_COMMIT,
				PAGE_READWRITE);
			if (NULL == section_memory) {
				LOG_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
			}
			TRACE("Copying section RawData...");
			
			CopyMemory(section_memory, (LPVOID)(dll_buffer.data() + section->PointerToRawData), section->SizeOfRawData);

		}
		else {
			TRACE("size_to_commit==0, will not MEM_COMMIT");
		}
		TRACE("Section Done.")
	}
	TRACE("All Sections Done.\n");
	return std::move(base_address);
}

void perform_base_relocations(const vector<byte>& dll_buffer, VirtualMemoryPtr& base_memory) {
	TRACE("Starting address base relocations...")

	auto pe_header = get_pe_header_pointer(dll_buffer);
	auto image_base = (PBYTE)base_memory.get();
	auto expected_image_base = pe_header->OptionalHeader.ImageBase;
	TRACE("ActualImageBase=0x%x, ExpectedImageBase=0x%x", image_base, expected_image_base);

	auto relocation_table_data_directory = (PIMAGE_DATA_DIRECTORY)(&(pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]));
	auto table_start = image_base + relocation_table_data_directory->VirtualAddress;
	auto table_end = table_start + relocation_table_data_directory->Size;
	TRACE("Found Relocation table 0x%x<->0x%x (0x%x)", table_start, table_end, relocation_table_data_directory->Size);

	auto block = (PIMAGE_BASE_RELOCATION)table_start;
	while ((PBYTE)(block) < table_end) {
		TRACE("RelocationBlock [0x%x]: VirtualAddress=0x%x, SizeOfBlock=0x%x", block, block->VirtualAddress, block->SizeOfBlock);
		
		// Some nasty pointer arithmatic.
		// We start at the block, right after the VA+SizeOfBlock descriptor, and continue until the end of the block
		auto block_end = (PBYTE)(block) + block->SizeOfBlock;
		auto block_data = (PBYTE)(block) + sizeof(IMAGE_BASE_RELOCATION);

		for (auto relocation = (PWORD)block_data; (PBYTE)relocation < block_end; relocation++) {
			// This is fucking hard to do without bit manipulation because of endianness
			auto type = (*relocation) >> 12;
			auto offset = (*relocation) & 0x0FFF;

			// All relocations need to be of types IMAGE_REL_BASED_HIGHLOW (actual relocation) or IMAGE_REL_BASED_ABSOLUTE (do nothing).
			if (IMAGE_REL_BASED_HIGHLOW == type) {
				// Find Address for the current relocation to extract RVA
				auto address_to_relocated_value = (PDWORD)(image_base + block->VirtualAddress + offset);
				auto expected_va = *address_to_relocated_value;

				// Do relocation by substituting the expected VA, with a new VA, where the image base is fixed
				auto new_va = (DWORD)(image_base + expected_va - expected_image_base);
				*address_to_relocated_value = new_va;
				//TRACE("[0x%08x] expected_va=0x%x -> new_va=0x%x", address_to_relocated_value, expected_va, new_va);
			}
			// IMAGE_REL_BASED_ABSOLUTE is no op, the rest we can't handle...
			else if (IMAGE_REL_BASED_ABSOLUTE != type) {
				LOG_AND_THROW(RelocationTypeUnkownException, "Cannot handle base relocation type %u", type);
			}
		}
		// Advance to next block
		block = (PIMAGE_BASE_RELOCATION)((PBYTE)block + block->SizeOfBlock);
	}

	TRACE("Base relocations Done\n");
}

void resolve_imports(const vector<byte>& dll_buffer, VirtualMemoryPtr& base_memory) {
	TRACE("Starting to resolve imports...");

	auto pe_header = get_pe_header_pointer(dll_buffer);
	auto image_base = (PBYTE)base_memory.get();
	auto import_table_data_directory = (PIMAGE_DATA_DIRECTORY)(&(pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
	auto table_start = (PBYTE)image_base + import_table_data_directory->VirtualAddress;
	auto table_end = table_start + import_table_data_directory->Size;
	TRACE("Found import table 0x%x<->0x%x (0x%x)", table_start, table_end, import_table_data_directory->Size);
	
	size_t descriptor_count = import_table_data_directory->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	// -1, because last descriptor is nullified Descriptor
	for (size_t i = 0; i < descriptor_count - 1; i++) {
		auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(table_start) + i;
		if (!import_descriptor->Name) {
			LOG_AND_THROW(ImportDescriptorInvalidException, "Import descriptor %d's Name's RVA is NULL!", i);
		}
		
		auto module_name = string((const char *)(image_base + import_descriptor->Name));
		TRACE("Found import descriptor for %hs", module_name.c_str());
		if (import_descriptor->ForwarderChain != -1) {
			// Currently will do absolutly nothing about it... mainly because I don't know what I should do.
			// TRACE("ForwarderChain=%lu", import_descriptor->ForwarderChain);
		}

		if (import_descriptor->TimeDateStamp != 0) {
			if (import_descriptor->TimeDateStamp == -1) {
				TRACE("Dll was previously bound (new bind?)");
			} else {
				TRACE("Dll was previously bound (%hs)", format_timestamp(import_descriptor->TimeDateStamp).c_str());
			}
		}

		// Do actual importing

		// TODO: In the final version, we shouldn't use LoadLibrary, GetProcAddress, etc., but use the pirateloader recursively to load the dependencies
		//       Also, need to refcount the dll's and stuff
		
		auto module = LoadLibraryA(module_name.c_str());
		if (NULL == module) {
			LOG_AND_THROW_WINAPI(LoadLibraryFailedException, LoadLibraryA);
		}
		string pretty_module_name(module_name.begin(), module_name.end() - string(".dll").size());

		auto import_address_list = (PDWORD)(image_base + import_descriptor->FirstThunk);
		auto import_name_list = (PDWORD)(image_base + import_descriptor->OriginalFirstThunk);

		for (; *import_address_list && *import_name_list; import_address_list++, import_name_list++) {
			auto name_data = (PIMAGE_IMPORT_BY_NAME)(image_base + *import_name_list);
			TRACE("Importing %hs.%hs (Hint(Ordinal?)=%hu)", pretty_module_name.c_str(), name_data->Name, name_data->Hint);

			// TODO: Yey! not x64 support!
			FARPROC function_address = GetProcAddress(module, name_data->Name);
			if (NULL == function_address) {
				LOG_AND_THROW_WINAPI(GetProcAddressFailedException, GetProcAddress);
			}
			*import_address_list = (DWORD)(function_address);
		}

		// TODO: We didn't free the DLL! In the final version, this should be a part of the cleanup routine
	}

	TRACE("Done resolving imports\n");
}

#define IS_SECTION_READ(section) (section->Characteristics & IMAGE_SCN_MEM_READ)
#define IS_SECTION_WRITE(section) (section->Characteristics & IMAGE_SCN_MEM_WRITE)
#define IS_SECTION_EXECUTE(section) (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)

void fixup_sections(const vector<byte>& dll_buffer, VirtualMemoryPtr& base_memory) {
	TRACE("Starting to fix sections protection...");

	auto pe_header = get_pe_header_pointer(dll_buffer);
	auto image_base = (PBYTE)base_memory.get();
	auto first_section = get_first_section(pe_header);

	TRACE("Iterating %hu sections", pe_header->FileHeader.NumberOfSections);
	for (auto i = 0; i < pe_header->FileHeader.NumberOfSections; ++i) {
		auto section = first_section + i;
		
		// TODO: Should check for discard sections here and shit
		
		auto section_size = get_actual_section_size(pe_header, section);
		if (section_size > 0) {
			auto section_address = (LPVOID)(image_base + section->VirtualAddress);
			/*if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
				VirtualFree(section_address, section_size, MEM_DECOMMIT);
				continue;
			}*/
			
			DWORD new_protection = PAGE_NOACCESS;
			if (IS_SECTION_EXECUTE(section)) {
				new_protection = PAGE_EXECUTE_READ;
			}
			else if (IS_SECTION_READ(section)) {
				new_protection = PAGE_READWRITE;
			}
			
			// TODO: Need to map 
			//		IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE
			// Into:
			//		PAGE_NOACCESS
			//		PAGE_WRITECOPY
			//		PAGE_READONLY
			//		PAGE_READWRITE
			//		PAGE_EXECUTE
			//		PAGE_EXECUTE_WRITECOPY
			//		PAGE_EXECUTE_READ
			//		PAGE_EXECUTE_READWRITE
			// For now, we'll just give all permissions and hope for the best
			
			TRACE("%hs -> Setting section protection. 0x%08x:%04x (new_protection=0x%08x)", get_section_name(section).c_str(), section_address, section_size, new_protection);
			DWORD previous_protection = 0;
			if (!VirtualProtect(
				section_address,
				section_size,
				new_protection,
				&previous_protection)) {
				LOG_AND_THROW_WINAPI(VirtualProtectFailedException, VirtualProtect);
			}
		}
	}
	TRACE("All Sections Done.\n");
}

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

void call_dllmain(const vector<byte>& dll_buffer, VirtualMemoryPtr& base_memory) {
	TRACE("Starting DllMain Call...");

	auto pe_header = get_pe_header_pointer(dll_buffer);
	auto image_base = (PBYTE)base_memory.get();

	DllEntryProc entry = (DllEntryProc)(image_base + pe_header->OptionalHeader.AddressOfEntryPoint);
	TRACE("DllMain 0x%08x", entry);
	(*entry)((HINSTANCE)image_base, DLL_PROCESS_ATTACH, 0);

	TRACE("DllMain call completed");
}


int main(int argc, char *argv[]) {
	try {
		// 1. Get Buffer of DLL Check DOSHeader, PEHeader
		// 2. Try to allocate a memory block of PEHeader.OptionalHeader.SizeOfImage bytes (We are randoming the position instead of using PEHeader.OptionalHeader.ImageBase)
		// 3. Parse section headers and copy sections to their addresses.
		//    The destination address for each section, relative to the base of the allocated memory block, is stored in the VirtualAddress attribute of the IMAGE_SECTION_HEADER structure.
		// 4. If the allocated memory block differs from ImageBase, various references in the code and/or data sections must be adjusted. This is called Base relocation.
		// 5. The required imports for the library must be resolved by loading the corresponding libraries.
		// 6. The memory regions of the different sections must be protected depending on the section’s characteristics.
		//    Some sections are marked as discardable and therefore can be safely freed at this point.
		//    These sections normally contain temporary data that is only needed during the import, like the informations for the base relocation.
		// 7. Now the library is loaded completely. It must be notified about this by calling the entry point using the flag DLL_PROCESS_ATTACH.

		// Step 1 (No checks tho)
		auto dll_buffer = get_dll_buffer(argv[1]);
		display_pe_header_statistics(get_pe_header_pointer(dll_buffer));

		// Step 2 + Step 3
		auto base_memory = allocate_and_copy_sections(dll_buffer);

		// Step 4
		//perform_base_relocations(dll_buffer, base_memory);

		// Step 5
		resolve_imports(dll_buffer, base_memory);

		// Step 6
		fixup_sections(dll_buffer, base_memory);

		// Step 7
		call_dllmain(dll_buffer, base_memory);

	}
	catch (const CommonException&) {
		TRACE("Caught Exception");
	}

	return 0;
}
