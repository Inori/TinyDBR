#include "executor.h"

#include <Windows.h>

Executor::Executor()
{
}

Executor::~Executor()
{
}

void Executor::Init()
{
	veh_handle = InstallVEHHandler();
}

void Executor::Unit()
{
	if (veh_handle)
	{
		UninstallVEHHandler(veh_handle);
		veh_handle = nullptr;
	}
}

//bool Executor::AddMoudle(const CodeModule& mod)
//{
//	modules.emplace_back(mod);
//
//	return SetModuleCodeNX(mod);
//}

void Executor::OnEntrypoint()
{

}

void Executor::OnProcessCreated()
{

}

void Executor::OnProcessExit()
{

}

void Executor::OnModuleLoaded(void* module, char* module_name)
{

}

void Executor::OnModuleUnloaded(void* module)
{

}

bool Executor::OnException(Exception* exception_record)
{

}

void Executor::OnCrashed(Exception* exception_record)
{

}

size_t Executor::GetTranslatedAddress(size_t address)
{

}

void Executor::ExtractCodeRanges(
	void* module_base, 
	size_t min_address, size_t max_address, 
	std::list<AddressRange>* executable_ranges,
	size_t* code_size)
{

}

//bool Executor::SetModuleCodeNX(const CodeModule& mod)
//{
//	bool ret = false;
//	do
//	{
//		if (mod.code_ranges.empty())
//		{
//			break;
//		}
//
//		bool has_error = false;
//		for (const auto& range : mod.code_ranges)
//		{
//			if (!range.address || !range.size)
//			{
//				has_error = true;
//				break;
//			}
//
//			// TODO:
//			// To support multiple platform, this protect function should be abstracted.
//
//			// Since we need to read the original code and rewrite it, 
//			// we just need to remove the EXEC property and keep it readable.
//			DWORD old_protect = 0;
//			BOOL bRet = VirtualProtect(range.address, range.size, PAGE_READONLY, &old_protect);
//			if (!bRet)
//			{
//				has_error = true;
//				break;
//			}
//		}
//
//		if (has_error)
//		{
//			break;
//		}
//
//		ret  = true;
//	}while(false);
//	return ret;
//}

void* Executor::InstallVEHHandler()
{
	void* handle = AddVectoredExceptionHandler(TRUE, &Executor::VectoredExceptionHandler);
	return handle;
}

void Executor::UninstallVEHHandler(void* handle)
{
	do 
	{
		if (!handle)
		{
			break;
		}

		RemoveVectoredExceptionHandler(handle);

	} while (false);
}

LONG Executor::VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo)
{
	LONG action = EXCEPTION_CONTINUE_SEARCH;

	do 
	{
		if (!ExceptionInfo)
		{
			break;
		}


	} while (false);

	return action;
}
