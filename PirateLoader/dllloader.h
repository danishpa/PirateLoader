#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <Windows.h>
#include "common/common.h"
#include "module.h"

using std::shared_ptr;
using std::string;
using std::map;
using std::vector;

namespace pirateloader {
namespace dllloader {

	class DllLoader {
	public:
		virtual ~DllLoader();

		static DllLoader& get();

		shared_ptr<Module> load(string name);
		shared_ptr<Module> load(vector<byte> dll_buffer, string name = "");
		
		void free(string name);
		void free(shared_ptr<Module> module);

		DllLoader(const DllLoader& other) = delete;
		DllLoader& operator=(const DllLoader& other) = delete;

	private:
		// private ctor -> Singleton
		DllLoader();

		string search_dll_path(string name);
		string get_uniform_dll_name(string name);

		map<string, shared_ptr<Module>> m_loaded_modules;
		static DllLoader sm_loader;
	};

}
}
