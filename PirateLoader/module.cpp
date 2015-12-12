#include "module.h"
#include <vector>
#include <string>
#include <windows.h>
#include "common\common.h"
#include "peutils.h"

using std::vector;
using std::string;

using namespace pirateloader::peutils;

namespace pirateloader {
namespace dllloader {

	auto Module::get_new_section_protection(const PIMAGE_SECTION_HEADER& section) {
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

	void Module::allocate_and_copy_headers(const vector<byte>& dll_buffer) {
		TRACE("Commiting memory for headers");

		auto dos_headers_size = ((PIMAGE_DOS_HEADER)(dll_buffer.data()))->e_lfanew;
		auto section_headers_size = get_pe_header_pointer(dll_buffer)->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		auto total_size = dos_headers_size + sizeof(IMAGE_NT_HEADERS32) + section_headers_size;

		LPVOID headers = VirtualAlloc(
			m_base_memory.get(),
			total_size,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (NULL == headers) {
			TRACE_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
		}
		CopyMemory(headers, (LPVOID)(dll_buffer.data()), total_size);

	}

	void Module::allocate_and_copy_sections(const vector<byte>& dll_buffer) {
		// Reserve memory for the entire image
		auto pe_header = get_pe_header_pointer(dll_buffer);
		m_base_memory.reset(VirtualAlloc(
			NULL, // Will always relocate
			pe_header->OptionalHeader.SizeOfImage,
			MEM_RESERVE,
			PAGE_READWRITE));
		if (invalid(m_base_memory)) {
			TRACE_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
		}
		TRACE("Image Memory Reserved: Got 0x%x:%x", m_base_memory.get(), pe_header->OptionalHeader.SizeOfImage);

		// Commit and copy memory for PE Headers, since they are needed for everything, and even after we get rid of dll_buffer (for get_proc_address)
		allocate_and_copy_headers(dll_buffer);

		// Commit each section, and copy it
		auto first_section = get_first_section(pe_header);

		TRACE("Iterating %hu sections", pe_header->FileHeader.NumberOfSections);
		for (auto i = 0; i < pe_header->FileHeader.NumberOfSections; ++i) {
			auto section = first_section + i;
			auto size_to_commit = section->Misc.VirtualSize;

			// If size_to_commit is bigger than 0, commit the memory. if it isn't, don't.
			if (size_to_commit > 0) {
				auto virtual_address_for_section = (LPVOID)((const PBYTE)m_base_memory.get() + section->VirtualAddress);
				TRACE("Commiting memory for section %hs -> 0x%x:%04x...", get_section_name(section).c_str(), virtual_address_for_section, size_to_commit);
				LPVOID section_memory = VirtualAlloc(
					virtual_address_for_section,
					size_to_commit,
					MEM_COMMIT,
					PAGE_READWRITE);
				if (NULL == section_memory) {
					TRACE_AND_THROW_WINAPI(VirtualAllocFailedException, VirtualAlloc);
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
	}

	void Module::perform_base_relocations() {
		TRACE("Starting address base relocations...")

		auto pe_header = get_pe_header_pointer(m_base_memory);
		auto image_base = (PBYTE)m_base_memory.get();
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
			auto block_end = (PBYTE)(block)+block->SizeOfBlock;
			auto block_data = (PBYTE)(block)+sizeof(IMAGE_BASE_RELOCATION);

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
					TRACE_AND_THROW(RelocationTypeUnkownException, "Cannot handle base relocation type %u", type);
				}
			}
			// Advance to next block
			block = (PIMAGE_BASE_RELOCATION)((PBYTE)block + block->SizeOfBlock);
		}

		TRACE("Base relocations Done\n");
	}

	void Module::resolve_imports() {
		TRACE("Starting to resolve imports...");

		auto pe_header = get_pe_header_pointer(m_base_memory);
		auto image_base = (PBYTE)m_base_memory.get();
		auto import_table_data_directory = (PIMAGE_DATA_DIRECTORY)(&(pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
		auto table_start = (PBYTE)image_base + import_table_data_directory->VirtualAddress;
		auto table_end = table_start + import_table_data_directory->Size;
		TRACE("Found import table 0x%x<->0x%x (0x%x)", table_start, table_end, import_table_data_directory->Size);

		size_t descriptor_count = import_table_data_directory->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		// -1, because last descriptor is nullified Descriptor
		for (size_t i = 0; i < descriptor_count - 1; i++) {
			auto import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(table_start)+i;
			if (!import_descriptor->Name) {
				TRACE_AND_THROW(ImportDescriptorInvalidException, "Import descriptor %d's Name's RVA is NULL!", i);
			}

			auto module_name = string((const char *)(image_base + import_descriptor->Name));
			TRACE("Found import descriptor for %hs", module_name.c_str());
			if (import_descriptor->ForwarderChain != -1) {
				// Currently will do absolutely nothing about it... mainly because I don't know what I should do.
				// TRACE("ForwarderChain=%lu", import_descriptor->ForwarderChain);
			}

			if (import_descriptor->TimeDateStamp != 0) {
				if (import_descriptor->TimeDateStamp == -1) {
					TRACE("Dll was previously bound (new bind?)");
				}
				else {
					TRACE("Dll was previously bound (%hs)", format_timestamp(import_descriptor->TimeDateStamp).c_str());
				}
			}

			// Do actual importing

			// TODO: In the final version, we shouldn't use LoadLibrary, GetProcAddress, etc., but use the pirateloader recursively to load the dependencies
			//       Also, need to refcount the dll's and stuff

			auto module = LoadLibraryA(module_name.c_str());
			if (NULL == module) {
				TRACE_AND_THROW_WINAPI(LoadLibraryFailedException, LoadLibraryA);
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
					TRACE_AND_THROW_WINAPI(GetProcAddressFailedException, GetProcAddress);
				}
				*import_address_list = (DWORD)(function_address);
			}

			// TODO: We didn't free the DLL! In the final version, this should be a part of the cleanup routine
		}

		TRACE("Done resolving imports\n");
	}

	void Module::fixup_sections() {
		TRACE("Starting to fix sections protection...");

		auto pe_header = get_pe_header_pointer(m_base_memory);
		auto image_base = (PBYTE)m_base_memory.get();
		auto first_section = get_first_section(pe_header);

		TRACE("Iterating %hu sections", pe_header->FileHeader.NumberOfSections);
		for (auto i = 0; i < pe_header->FileHeader.NumberOfSections; ++i) {
			auto section = first_section + i;
			auto section_address = (LPVOID)(image_base + section->VirtualAddress);
			auto section_size = section->Misc.VirtualSize;

			// If the section is a discard section, discard it by decommiting the memory
			if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
				SecureZeroMemory(section_address, section_size);
				VirtualFree(section_address, section_size, MEM_DECOMMIT);
				continue;
			}

			auto new_protection = get_new_section_protection(section);
			TRACE("%hs -> Setting section protection. 0x%08x:%04x (new_protection=0x%08x)", get_section_name(section).c_str(), section_address, section_size, new_protection);
			DWORD previous_protection = 0;
			if (!VirtualProtect(
				section_address,
				section_size,
				new_protection,
				&previous_protection)) {
				TRACE_AND_THROW_WINAPI(VirtualProtectFailedException, VirtualProtect);
			}
		}
		TRACE("All Sections Done.\n");
	}

	void Module::call_dllmain(DWORD reason) {
		TRACE("Starting DllMain Call...");

		auto pe_header = get_pe_header_pointer(m_base_memory);
		auto image_base = (PBYTE)m_base_memory.get();

		DllEntryProc entry = (DllEntryProc)(image_base + pe_header->OptionalHeader.AddressOfEntryPoint);
		TRACE("Calling DllMain on 0x%08x (dwReason=%lu)", entry, reason);
		(*entry)((HINSTANCE)image_base, reason, 0);

		TRACE("DllMain call completed");
	}

	// TODO: This function gets function by NAME. if we want to get the function by ordinal,
	//		 we will need to write a separate function to iterate over address_of_name_ordinals only???
	// TODO: Getting functions by ordinal isn't complex. I think:
	//	"auto index_to_function_table = ordinal - export_table->Base;"
	//       should work...

	string Module::get_module_name() {
		if (!m_name.empty()) {
			return m_name;
		}

		TRACE("Getting module name...")

		auto pe_header = get_pe_header_pointer(m_base_memory);
		auto image_base = (PBYTE)m_base_memory.get();
		auto export_table_data_directory = (PIMAGE_DATA_DIRECTORY)(&(pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
		auto export_table = (PIMAGE_EXPORT_DIRECTORY)(image_base + export_table_data_directory->VirtualAddress);

		m_name = string((const char *)(image_base + export_table->Name));
		TRACE("Got module name %hs", m_name.c_str());
		return m_name;
	}

	DllExportedFunction Module::get_proc_address(const string& export_name) {
		TRACE("Starting to resolve exports...");
		
		auto pe_header = get_pe_header_pointer(m_base_memory);
		auto image_base = (PBYTE)m_base_memory.get();
		auto export_table_data_directory = (PIMAGE_DATA_DIRECTORY)(&(pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
		auto table_start = (PBYTE)image_base + export_table_data_directory->VirtualAddress;
		auto export_table = (PIMAGE_EXPORT_DIRECTORY)table_start;
		TRACE("Found export table 0x%x:%04x", export_table, export_table_data_directory->Size);
		TRACE("Export table timestamp: %hs", format_timestamp(export_table->TimeDateStamp).c_str());

		auto address_of_names = (PDWORD)((PBYTE)image_base + export_table->AddressOfNames);
		auto address_of_name_ordinals = (PWORD)((PBYTE)image_base + export_table->AddressOfNameOrdinals);
		auto address_of_functions = (PDWORD)((PBYTE)image_base + export_table->AddressOfFunctions);

		for (size_t i = 0; i < export_table->NumberOfNames; ++i) {
			auto name = string((const char *)(image_base + address_of_names[i]));
			if (0 == name.compare(export_name)) {
				auto index = address_of_name_ordinals[i];
				auto exported_function = (DllExportedFunction)(image_base + address_of_functions[index]);
				TRACE("Found exported function (%hs): 0x%08x", export_name.c_str(), exported_function);
				return exported_function;
			}
		}

		TRACE_AND_THROW(ExportedFunctionNotFound, "Could not find exported function %hs", export_name.c_str());
	}

	Module::Module(const vector<byte>& dll_buffer) {
		// Step 1 - Check DOSHeader, PEHeader

		// Step 2 - Try to allocate a memory block of PEHeader.OptionalHeader.SizeOfImage bytes (We are always randoming the position instead of using PEHeader.OptionalHeader.ImageBase)
		// Step 3 - Parse section headers and copy sections to their addresses.
		//    The destination address for each section, relative to the base of the allocated memory block, is stored in the VirtualAddress attribute of the IMAGE_SECTION_HEADER structure.
		allocate_and_copy_sections(dll_buffer);

		// Step 4 - If the allocated memory block differs from ImageBase, various references in the code and/or data sections must be adjusted. This is called Base relocation.
		perform_base_relocations();

		// Step 5 - The required imports for the library must be resolved by loading the corresponding libraries.
		resolve_imports();

		// Step 6 - The memory regions of the different sections must be protected depending on the section’s characteristics.
		//    Some sections are marked as discardable and therefore can be safely freed at this point.
		//    These sections normally contain temporary data that is only needed during the import, like the informations for the base relocation.
		fixup_sections();

		// Step 7 - Now the library is loaded completely. It must be notified about this by calling the entry point using the flag DLL_PROCESS_ATTACH.
		call_dllmain(DLL_PROCESS_ATTACH);

		// This will statically cache m_name
		(void)get_module_name();

		TRACE("Done loading dll %hs", m_name.c_str());
	}

	Module::~Module() {
		try {
			TRACE("Freeing dll %hs", m_name.c_str());

			call_dllmain(DLL_PROCESS_DETACH);
		}
		catch (...) {

		}
	}

}
}


