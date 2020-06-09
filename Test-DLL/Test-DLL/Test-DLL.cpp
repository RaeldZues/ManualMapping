#include <Windows.h>

DWORD WINAPI DisplayMessageBox(LPVOID parameter)
{
	MessageBoxA(nullptr, "DLL Successfully Loaded\nPress Insert to Eject DLL", "Test DLL", 0);
	DWORD count = 0;
	while (count < 50)
	{
		if (GetAsyncKeyState(VK_INSERT) & 1)
		{
			FreeLibraryAndExitThread(HMODULE(parameter), NULL);
			return 0;
		}
		Sleep(30);
		count++;
	}
	return 0;
}

extern "C" __declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		{
			CreateThread(nullptr, 0, DisplayMessageBox, moduleHandle, 0, nullptr);
			DisableThreadLibraryCalls(moduleHandle);
			break;
		}
	case DLL_THREAD_ATTACH:
		{
			break;
		}
	case DLL_PROCESS_DETACH:
		{
			break;
		}
	case DLL_THREAD_DETACH:
		{
			break;
		}
	default: ;
	}
	return true;
}
