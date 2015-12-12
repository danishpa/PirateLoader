#include <memory>
#include <functional>
#include <ctime>
#include <Windows.h>
#include "common\common.h"
#include "module.h"
#include "dllloader.h"
#include "peutils.h"

using namespace pirateloader::peutils;
using namespace pirateloader::dllloader;

typedef int(*FuncType)();
int main(int argc, char *argv[]) {
	try {
		// Load by buffer
		auto dll_buffer = get_dll_buffer(argv[1]);
		display_pe_header_statistics(get_pe_header_pointer(dll_buffer));

		auto m = DllLoader::get().load(dll_buffer);

		auto Func = m->get_proc_address("Func");
		((FuncType)(Func))();
		auto Func3 = m->get_proc_address("Func3");
		((FuncType)(Func3))();


		// Load by name
		auto module_by_name = DllLoader::get().load("kernel32.dll");

		auto e1 = module_by_name->get_proc_address("GetErrorMode");
		//((FuncType)(e1))();
		auto e2 = module_by_name->get_proc_address("SetErrorMode");
		//((FuncType)(e2))();






	}
	catch (const CommonException&) {
		TRACE("Caught Exception");
	}

	return 0;
}
