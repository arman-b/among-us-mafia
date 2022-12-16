#include "pch.h"
#include <Windows.h>
#include <shellapi.h>

void hookFunc(void* src, void* dst, unsigned int bytes)
{
	if (bytes >= 5) {
		DWORD currProtection;
		VirtualProtect(src, bytes, PAGE_EXECUTE_READWRITE, &currProtection);
		memset(src, 0x90, bytes); // Sets bytes after original function call address to nop
		uintptr_t relativeAddress = (uintptr_t)dst - (uintptr_t)src - 5;
		*(BYTE*)src = 0xE9; // Sets assembly instruction to jump to relative address of hooked function when the point in memory of the original function call is reached
		*(uintptr_t*)((BYTE*)src + 1) = relativeAddress;
		VirtualProtect(src, bytes, currProtection, &currProtection);
	}
}

BYTE* trampoline(void* src, void* dst, unsigned int bytes)
{
	if (bytes >= 5) {
		// Create the gateway; the point of this is to allocate memory to keep the call to the original function intact somewhere else in case we need to call it after hooking the function and replacing it with our own implementation
		BYTE* gateway = (BYTE*)VirtualAlloc(0, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		// Write the stolen bytes
		memcpy_s(gateway, bytes, src, bytes);

		// Get the gateway to destination address
		uintptr_t gatewayRelativeAddr = (BYTE*)src - gateway - 5;
		*(gateway + bytes) = 0xE9;

		// Write address of gateway to jmp
		*(uintptr_t*)((uintptr_t)gateway + bytes + 1) = gatewayRelativeAddr;

		// Hooks the original function
		hookFunc(src, dst, bytes);
		return gateway;
	}
	return 0;
}

typedef void (*tBuyStars)(void* StoreMenu);
tBuyStars oBuyStars = (tBuyStars)(GetModuleHandleW(L"GameAssembly.dll") + (0x6BEFE0 / 4));
void hBuyStars(void* StoreMenu) {
	ShellExecuteW(NULL, L"open", L"https://forms.gle/q8NckTEoVbGi7MnRA", NULL, NULL, SW_SHOWNORMAL);
}

DWORD WINAPI newThread(HMODULE hModule)
{
	//(Address to hook, New Function, number of bytes greater than 5 that the function start is[You can check this in ollydbg or cheat engine, just attach to the process, go to memory view, and go to the address GameAssembly.dll + RVA, then check how many bytes greater than 5 it has])
	oBuyStars = (tBuyStars)trampoline(oBuyStars, hBuyStars, 6);
	while (true) {

	}
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

// Defines the entry point for the DLL application, exported
extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)newThread, hModule, NULL, nullptr));
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;

}

// Exporting function that follows SetWindowsHookEx call in the injector, passes along hook chain
extern "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(NULL, code, wParam, lParam);
}