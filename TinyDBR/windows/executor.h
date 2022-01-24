#pragma once

#include <vector>
#include <string>
#include <list>
#include <unordered_set>
#include <unordered_map>
#include "../singleton.h"
#include "../common.h"
#include "../arch/x86/reg.h"

struct _EXCEPTION_POINTERS;

struct SavedRegisters
{
	CONTEXT saved_context;
};

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

	// bool AddMoudle(const CodeModule& mod);

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
	enum MemoryProtection
	{
		READONLY,
		READWRITE,
		READEXECUTE,
		READWRITEEXECUTE
	};

protected:
	void ExtractCodeRanges(void* module_base,
		size_t min_address,
		size_t max_address,
		std::list<AddressRange>* executable_ranges,
		size_t* code_size);

	void ProtectCodeRanges(
		std::list<AddressRange>* executable_ranges);

	DWORD GetImageSize(void* base_address);
	void  GetImageSize(
		 void*   base_address,
		 size_t* min_address,
		 size_t* max_address);


	void GetExceptionHandlers(size_t module_haeder, std::unordered_set<size_t>& handlers);

	void PatchPointersRemote(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);
	template <typename T>
	void PatchPointersRemoteT(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace);
	

	void* RemoteAllocateNear(uint64_t         region_min,
							 uint64_t         region_max,
							 size_t           size,
							 MemoryProtection protection,
							 bool             use_shared_memory = false);
	void  RemoteFree(void* address, size_t size);
	void  RemoteWrite(void* address, void* buffer, size_t size);
	void  RemoteRead(void* address, void* buffer, size_t size);
	void  RemoteProtect(void* address, size_t size, MemoryProtection protect);

	size_t GetRegister(Register r);
	void   SetRegister(Register r, size_t value);

	void SaveRegisters(SavedRegisters* registers);
	void RestoreRegisters(SavedRegisters* registers);

	DWORD GetProcOffset(HMODULE module, const char* name);

protected:
	int32_t child_ptr_size = sizeof(void*);
	bool    child_entrypoint_reached = false;

private:
	// bool SetModuleCodeNX(const CodeModule& mod);

	void* InstallVEHHandler();

	void UninstallVEHHandler(void* handle);

	static long VectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo);

	void* RemoteAllocateBefore(uint64_t         min_address,
							   uint64_t         max_address,
							   size_t           size,
							   MemoryProtection protection);

	void* RemoteAllocateAfter(uint64_t         min_address,
							  uint64_t         max_address,
							  size_t           size,
							  MemoryProtection protection);

	DWORD WindowsProtectionFlags(MemoryProtection protection);

private:
	void*  veh_handle             = nullptr;
	size_t allocation_granularity = 0;
	HANDLE self_handle            = NULL;
	bool   have_thread_context    = false;
};


