#pragma once

#include <vector>
#include <string>

struct CodeRange
{
	void* address;
	size_t size;
};


struct ModuleInfo
{
	std::string module_name;
	std::vector<CodeRange> code_ranges;
};


class Executor
{
public:
	Executor();
	virtual ~Executor();

	template <typename FuncTy, typename... ArgTys>
	bool Run(void* code, ArgTys... args)
	{
		FuncTy func = reinterpret_cast<FuncTy>(code);
		func(args...);
	}

	bool AddMoudle(const ModuleInfo& mod);

private:
	bool SetModuleCodeNX(const ModuleInfo& mod);

private:
	std::vector<ModuleInfo> modules;
};

