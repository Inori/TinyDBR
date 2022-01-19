#include "executor.h"

#include <Windows.h>

Executor::Executor()
{
}

Executor::~Executor()
{
}

bool Executor::AddMoudle(const ModuleInfo& mod)
{
	modules.emplace_back(mod);

	return SetModuleCodeNX(mod);
}

bool Executor::SetModuleCodeNX(const ModuleInfo& mod)
{
	bool ret = false;
	do
	{
		if (mod.code_ranges.empty())
		{
			break;
		}

		bool has_error = false;
		for (const auto& range : mod.code_ranges)
		{
			if (!range.address || !range.size)
			{
				has_error = true;
				break;
			}

			// TODO:
			// To support multiple platform, this protect function should be abstracted.

			// Since we need to read the original code, we just need to remove the EXEC property.
			DWORD old_protect = 0;
			BOOL bRet = VirtualProtect(range.address, range.size, PAGE_READONLY, &old_protect);
			if (!bRet)
			{
				has_error = true;
				break;
			}
		}

		if (has_error)
		{
			break;
		}

		ret  = true;
	}while(false);
	return ret;
}
