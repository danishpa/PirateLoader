#include <Windows.h>
#include <cstdio>

HINSTANCE g_instance = NULL;

static const int HARTA = 100;
static int shit = 1;

int DllExport() {
	int a = 123;
	shit++;
	
	printf("DllExport %d %d %d\n", a, shit, HARTA);
	return a;
}

int DllExport2() {
	int a = 456;
	shit++;

	printf("DllExport %d %d %d\n", a, shit, HARTA);
	return a;
}

int DllExport3() {
	int a = 789;
	shit++;

	printf("DllExport %d %d %d\n", a, shit, HARTA);
	return a;
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved) {

	shit++;

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