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
		auto dll_buffer = get_dll_buffer(argv[1]);
		display_pe_header_statistics(get_pe_header_pointer(dll_buffer));

		Module m("MyDll", dll_buffer);

		// Now dll is loaded, lets find exports
		auto exported_function = m.get_proc_address("Func");
		((FuncType)(exported_function))();
		exported_function = m.get_proc_address("Func3");
		((FuncType)(exported_function))();

	}
	catch (const CommonException&) {
		TRACE("Caught Exception");
	}

	return 0;
}
