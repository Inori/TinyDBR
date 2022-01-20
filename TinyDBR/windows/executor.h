#pragma once

#include <vector>
#include <string>
#include <list>
#include "../singleton.h"
#include "../common.h"

struct _EXCEPTION_POINTERS;



class Executor : public Singleton<Executor>
{
	friend class Singleton<Executor>;
public:
	Executor();
	virtual ~Executor();

	virtual void Init();

	virtual void Unit();

	// The caller should make sure
	// code is within added modules.
	template <typename... ArgTys>
	bool Run(void* code, ArgTys... args)
	{
		typedef int (*FuncTy)(ArgTys... args);

		bool ret = false;
		do
		{
			// TODO:
			// Check if the code is within added modules.
			if (!code)
			{
				break;
			}

			FuncTy func = reinterpret_cast<FuncTy>(code);
			int ret_val = func(args...);

			ret  = true;
		}while(false);
		return ret;

	}

	bool AddMoudle(const CodeModule& mod);

protected:

	enum ExceptionType {
		BREAKPOINT,
		ACCESS_VIOLATION,
		ILLEGAL_INSTRUCTION,
		STACK_OVERFLOW,
		OTHER
	};

	struct Exception {
		ExceptionType type;
		void* ip;
		bool maybe_write_violation;
		bool maybe_execute_violation;
		void* access_address;
	};

	virtual void OnEntrypoint();
	virtual void OnProcessCreated();
	virtual void OnProcessExit();
	virtual void OnModuleLoaded(void* module, char* module_name);
	virtual void OnModuleUnloaded(void* module);
	virtual bool OnException(Exception* exception_record);
	virtual void OnCrashed(Exception* exception_record);

	virtual size_t GetTranslatedAddress(size_t address);

protected:
	void ExtractCodeRanges(void* module_base,
		size_t min_address,
		size_t max_address,
		std::list<AddressRange>* executable_ranges,
		size_t* code_size);

private:
	// bool SetModuleCodeNX(const CodeModule& mod);

	void* InstallVEHHandler();

	void UninstallVEHHandler(void* handle);

	static long VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo);

private:
	void* veh_handle = nullptr;
};

