#include "tinydbr.h"
#include "arch/x86/x86_memory_monitor.h"

#include <Windows.h>
#include <filesystem>
#include <memory>
#include <string>
#include <map>

/*
* TinyDBR DLL translator, you need to inject this compiled dll into to target process
* before the execution of main module entry point.
*/

std::unique_ptr<Executor> instrumenter;


class MyMonitor : public MemoryCallback
{
public:
	MyMonitor()
	{
		m_map.insert(std::make_pair<uint64_t, uint64_t>((uint64_t)&instrumenter, (uint64_t)&instrumenter));
		m_map.insert(std::make_pair<uint64_t, uint64_t>(1, 2));
		m_map.insert(std::make_pair<uint64_t, uint64_t>(0x00400000, 0x00400000));
		m_map.insert(std::make_pair<uint64_t, uint64_t>((uint64_t)this, (uint64_t)this));
	}
	virtual ~MyMonitor(){};

	void OnMemoryRead(void* address, size_t size) override
	{
		//auto iter = m_map.lower_bound((uint64_t)address);
	}

	void OnMemoryWrite(void* address, size_t size) override
	{
		//auto iter = m_map.upper_bound((uint64_t)address);
	}

private:
	std::map<uint64_t, uint64_t> m_map;
};



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

void InitRewrite()
{
	do
	{
		auto module_name = GetExeName();
		if (module_name.empty())
		{
			break;
		}

		static MyMonitor monitor;

		MonitorFlags flags = IgnoreCode | IgnoreStack | IgnoreRipRelative;
		instrumenter       = std::make_unique<X86MemoryMonitor>(flags, &monitor);
		//instrumenter = std::make_unique<TinyDBR>();

		TargetModule main_module = {};
		main_module.name         = module_name;
		main_module.is_main      = true;

		Options options          = {};
		instrumenter->Init({ main_module }, options);

	} while (false);
}

void UnitRewrite()
{
	if (instrumenter)
	{
		instrumenter->Unit();
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
					  DWORD   ul_reason_for_call,
					  LPVOID  lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InitRewrite();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		UnitRewrite();
		break;
	}
	return TRUE;
}