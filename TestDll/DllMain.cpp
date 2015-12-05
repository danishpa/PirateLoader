#include <Windows.h>
#include <cstdio>

HINSTANCE g_instance = NULL;

int DllExport() {
	int a = 123;
	printf("DllExport %d\n", a);

	return a;
}

int DllExport2() {
	int a = 456;
	printf("DllExport2 %d\n", a);

	return a;
}

int DllExport3() {
	int a = 789;
	printf("DllExport3 %d\n", a);

	return a;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		g_instance = hinstDLL;
		break;

	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		break;
	}
	
	return TRUE;
}