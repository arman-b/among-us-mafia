#include <Windows.h>

int main(int argc, char* argv[]) {
	ShellExecute(NULL, L"open", L"steam://rungameid/945360/", NULL, NULL, SW_HIDE); // Open Among Us.exe process
	Sleep(3000);

	const wchar_t* dllPath = L"./among-us-mafia-vs-town-mod.dll";
	HWND hwnd = FindWindowW(L"UnityWndClass", NULL);
	DWORD pid = NULL;
	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
	HMODULE dll = LoadLibraryExW(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES); // Load the dll from the dllPath variable
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "NextHook"); // Our dll has only one exported function, StartHooking; used to hook all the relevant functions once entry point is hit
	HHOOK handle = SetWindowsHookExW(WH_GETMESSAGE, addr, dll, tid);

	while (true) { // Keep dll injected until target process ends

	}
}

#ifdef _WIN32
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	return main(__argc, __argv);
}
#endif