#include <algorithm>
#include <windows.h>
#include <shlwapi.h>
#include "dllloader.h"
#include "common/common.h"
#include "peutils.h"
#include "module.h"

using namespace pirateloader::peutils;

namespace pirateloader {
namespace dllloader {
	DllLoader DllLoader::sm_loader;

	DllLoader::DllLoader() {

	}

	DllLoader::~DllLoader() {

	}

	DllLoader& DllLoader::get() {
		return sm_loader;
	}

	string DllLoader::search_dll_path(string name) {
		// !TODO: Try to imitate dll searching:
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx#standard_search_order_for_desktop_applications
		//	[ ] - The directory from which the application loaded.
		//	[V] - The current directory.
		//	[V] - The system directory.Use the GetSystemDirectory function to get the path of this directory.
		//	[ ] - The 16 - bit system directory.There is no function that obtains the path of this directory, but it is searched.
		//	[V] - The Windows directory.Use the GetWindowsDirectory function to get the path of this directory.
		//	[?] - The directories that are listed in the PATH environment variable.Note that this does not include the per - application path specified by the App Paths registry key.The App Paths key is not used when computing the DLL search path.

		// Build other directories to search (Current Directory, System directory, Windows Directory)

		vector<byte> current_dir(MAX_PATH, 0);
		auto current_dir_path_length = GetCurrentDirectory(current_dir.size(), (LPSTR)current_dir.data());
		current_dir.resize(current_dir_path_length + 1); // +1 for null termination

		vector<byte> system_directory(MAX_PATH, 0);
		auto system_directory_path_length = GetSystemDirectory((LPSTR)system_directory.data(), system_directory.size());
		system_directory.resize(system_directory_path_length + 1); // +1 for null termination

		vector<byte> windows_directory(MAX_PATH, 0);
		auto windows_directory_path_length = GetWindowsDirectory((LPSTR)windows_directory.data(), windows_directory.size());
		windows_directory.resize(windows_directory_path_length + 1); // +1 for null termination

		// We are operating on a copy of the original name, and resize is guaranteed to keep the existing data, so this statement is cool
		name.resize(MAX_PATH);

		vector<LPSTR> other_dirs = { (LPSTR)current_dir.data(), (LPSTR)system_directory.data(), (LPSTR)windows_directory.data(), NULL };
		if (!PathFindOnPath((LPSTR)(name.data()), (PZPCSTR)other_dirs.data())) {
			TRACE_AND_THROW_WINAPI(PathFindOnPathFailedException, PathFindOnPath);
		}

		// Rebuild the string, since we don't want all the extra zeros, and finding the last one is a drag.
		return string((const char *)(name.data()));
	}

	string DllLoader::get_uniform_dll_name(string name) {
		transform(name.begin(), name.end() - string(".dll").size(), name.begin(), toupper);

		return name;
	}

	shared_ptr<Module> DllLoader::load(string name) {
		auto full_path = search_dll_path(name);
		auto dll_buffer = get_dll_buffer(full_path);

		shared_ptr<Module> module(new Module(dll_buffer));
		m_loaded_modules[get_uniform_dll_name(name)] = module;

		return module;
	}

	shared_ptr<Module> DllLoader::load(vector<byte> dll_buffer, string name) {
		// If we have the name of the dll, we can search it out!
		if (!name.empty()) {
			auto uniform_name = get_uniform_dll_name(name);
			auto search = m_loaded_modules.find(uniform_name);
			if (m_loaded_modules.end() != search) {
				// Dll was already loaded. return a copy of shared_ptr to the module to the user to increase its refcount
				TRACE("Dll %hs was already loaded before (under the name %hs)", name.c_str(), uniform_name.c_str());
				return search->second;
			}
		}

		// Load the module
		shared_ptr<Module> module(new Module(dll_buffer));

		// If the user did not give us the name of the dll, we will figure it our ourselves
		auto module_name = name.empty() ? module->get_module_name() : name;

		// TODO: If we still did not find name (module_name.empty()) we should random one.

		m_loaded_modules[get_uniform_dll_name(module_name)] = module;
		return module;
	}

	void DllLoader::free(string name) {
		// TODO
	}

	void DllLoader::free(shared_ptr<Module> module) {
		// TODO
	}

}
}
