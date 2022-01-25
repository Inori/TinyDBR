#include <Windows.h>
#include <string>
#include <filesystem>
#include <memory>

#include "../tinydbr.h"

// For detours inject
__declspec(dllexport) void WINAPI Dummy()
{
}

std::string GetExeName()
{
	std::string name;
	do 
	{
		char szFileName[MAX_PATH] = { 0 };
		if (GetModuleFileNameA(NULL, szFileName, MAX_PATH) == 0)
		{
			break;
		}

		std::string fullpath(szFileName);
		name = std::filesystem::path(fullpath).filename().string();

	} while (false);
	return name;
}

void ReWriteModule()
{
	do 
	{
		auto module_name = GetExeName();
		if (module_name.empty())
		{
			break;
		}

		void* exe_base    = reinterpret_cast<void*>(GetModuleHandleA(NULL));
		void* entry_point = GetModuleEntrypoint(exe_base);
		if (!entry_point)
		{
			break;
		}

		auto tinydbr = TinyDBR::GetInstance();

		tinydbr->Init({module_name});

		// tinydbr->Run(entry_point);

	} while (false);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		ReWriteModule();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}