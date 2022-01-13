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

	bool Run(void* code);

	bool AddMoudle(const ModuleInfo& mod);

private:
	bool SetModuleCodeNX(const ModuleInfo& mod);

private:
	std::vector<ModuleInfo> modules;
};

