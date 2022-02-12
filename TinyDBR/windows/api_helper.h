#pragma once

#include "common.h"
#include <unordered_set>
#include <list>

class ApiHelper
{
public:
	virtual ~ApiHelper();

	virtual void ExtractAndProtectCodeRanges(
		void*                    module_base,
		size_t                   min_address,
		size_t                   max_address,
		std::list<AddressRange>* executable_ranges,
		size_t*                  code_size) = 0;

	virtual void ProtectCodeRanges(
		std::list<AddressRange>* executable_ranges) = 0;

	virtual uint32_t GetImageSize(void* base_address) = 0;

	virtual uint32_t GetProcOffset(void* module, const char* name) = 0;

	virtual void GetExceptionHandlers(
		size_t module_header, std::unordered_set<size_t>& handlers) = 0;
};

///////////////////////////////////////////////////////////////////

class ModuleHelper : public ApiHelper
{
public:
	ModuleHelper();
	virtual ~ModuleHelper();

	virtual void ExtractAndProtectCodeRanges(
		void*                    module_base,
		size_t                   min_address,
		size_t                   max_address,
		std::list<AddressRange>* executable_ranges,
		size_t*                  code_size) override;

	virtual void ProtectCodeRanges(
		std::list<AddressRange>* executable_ranges) override;

	virtual uint32_t GetImageSize(void* base_address) override;

	virtual uint32_t GetProcOffset(void* module, const char* name) override;

	virtual void GetExceptionHandlers(
		size_t module_header, std::unordered_set<size_t>& handlers) override;

private:
};

///////////////////////////////////////////////////////////////////

class ShellcodeHelper : public ApiHelper
{
public:
	ShellcodeHelper();
	virtual ~ShellcodeHelper();

	virtual void ExtractAndProtectCodeRanges(
		void*                    module_base,
		size_t                   min_address,
		size_t                   max_address,
		std::list<AddressRange>* executable_ranges,
		size_t*                  code_size) override;

	virtual void ProtectCodeRanges(
		std::list<AddressRange>* executable_ranges) override;

	virtual uint32_t GetImageSize(void* base_address) override;

	virtual uint32_t GetProcOffset(void* module, const char* name) override;

	virtual void GetExceptionHandlers(
		size_t module_header, std::unordered_set<size_t>& handlers) override;

private:
};

