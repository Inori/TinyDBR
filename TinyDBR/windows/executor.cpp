#include "executor.h"
#include "dllnotify.h"
#include "../tinydbr.h"


#include <Windows.h>
#include <Psapi.h>

Executor::Executor()
{
}

Executor::~Executor()
{
}

void Executor::Init(const std::vector<std::string>& instrument_module_names)
{
	veh_handle = InstallVEHHandler();
	dll_notify_cookie = InstallDllNotification(&Executor::DllNotificationHandler, this);

	DWORD dwPid = GetCurrentProcessId();
	self_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!self_handle)
	{
		FATAL("open self process failed.");
	}

	// get allocation granularity
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	allocation_granularity = system_info.dwAllocationGranularity;
}

void Executor::Unit()
{
	if (veh_handle)
	{
		UninstallVEHHandler(veh_handle);
		veh_handle = nullptr;
	}

	if (dll_notify_cookie)
	{
		UninstallDllNotification(dll_notify_cookie);
		dll_notify_cookie = nullptr;
	}
}

long Executor::OnVEHException(EXCEPTION_POINTERS* ExceptionInfo)
{
	LONG action = EXCEPTION_CONTINUE_SEARCH;
	do
	{
		Exception exception = {};
		ConvertException(ExceptionInfo->ExceptionRecord, &exception);

		bool handled = OnException(&exception, ExceptionInfo->ContextRecord);

		if (handled)
		{
			action = EXCEPTION_CONTINUE_EXECUTION;
		}

	} while (false);

	return action;
}

void Executor::OnEntrypoint()
{
	HMODULE* module_handles = NULL;
	DWORD    num_modules    = GetLoadedModules(&module_handles);
	for (DWORD i = 0; i < num_modules; i++)
	{
		char base_name[MAX_PATH];
		GetModuleBaseNameA(self_handle, module_handles[i], (LPSTR)(&base_name), sizeof(base_name));
		if (trace_debug_events)
			printf("Debugger: Loaded module %s at %p\n", base_name, (void*)module_handles[i]);
		OnModuleLoaded((void*)module_handles[i], base_name);
	}
	if (module_handles)
		free(module_handles);

	child_entrypoint_reached = true;

	if (trace_debug_events)
		printf("Debugger: Process entrypoint reached\n");
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

// should return true if the exception has been handled
bool Executor::OnException(Exception* exception_record, Context* context_record)
{
	if ((exception_record->type == ACCESS_VIOLATION) &&
		(exception_record->maybe_execute_violation))
	{

	}
	return false;
}

void Executor::OnCrashed(Exception* exception_record)
{
}

size_t Executor::GetTranslatedAddress(size_t address)
{
	return 0;
}

// detects executable memory regions in the module
// makes them non-executable
// and copies code out
void Executor::ExtractAndProtectCodeRanges(
	void*                    module_base,
	size_t                   min_address,
	size_t                   max_address,
	std::list<AddressRange>* executable_ranges,
	size_t*                  code_size)
{
	LPCVOID                  end_address = (char*)max_address;
	LPCVOID                  cur_address = module_base;
	MEMORY_BASIC_INFORMATION meminfobuf;

	AddressRange newRange;

	for (auto iter = executable_ranges->begin();
		 iter != executable_ranges->end(); iter++)
	{
		free(iter->data);
	}
	executable_ranges->clear();
	*code_size = 0;

	while (cur_address < end_address)
	{
		size_t ret = VirtualQuery(cur_address,
								  &meminfobuf,
								  sizeof(MEMORY_BASIC_INFORMATION));

		if (!ret)
			break;

		if (meminfobuf.Protect & 0xF0)
		{
			// printf("%p, %llx, %lx\n", meminfobuf.BaseAddress, meminfobuf.RegionSize, meminfobuf.Protect);

			newRange.data = (char*)malloc(meminfobuf.RegionSize);

			std::memcpy(newRange.data, meminfobuf.BaseAddress, meminfobuf.RegionSize);

			uint8_t low      = meminfobuf.Protect & 0xFF;
			low              = low >> 4;
			DWORD newProtect = (meminfobuf.Protect & 0xFFFFFF00) + low;
			DWORD oldProtect;
			if (!VirtualProtect(meminfobuf.BaseAddress,
								meminfobuf.RegionSize,
								newProtect,
								&oldProtect))
			{
				FATAL("Error in VirtualProtectEx");
			}

			newRange.from = (size_t)meminfobuf.BaseAddress;
			newRange.to   = (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize;
			executable_ranges->push_back(newRange);

			*code_size += newRange.to - newRange.from;
		}

		cur_address = (char*)meminfobuf.BaseAddress + meminfobuf.RegionSize;
	}
}

// sets all pages containing (previously detected)
// code to non-executable
void Executor::ProtectCodeRanges(std::list<AddressRange>* executable_ranges)
{
	MEMORY_BASIC_INFORMATION meminfobuf;

	for (auto iter = executable_ranges->begin();
		 iter != executable_ranges->end(); iter++)
	{
		size_t ret = VirtualQuery((void*)iter->from,
								  &meminfobuf,
								  sizeof(MEMORY_BASIC_INFORMATION));

		// if the module was already instrumented, everything must be the same as before
		if (!ret)
		{
			FATAL("Error in ProtectCodeRanges."
				  "Target incompatible with persist_instrumentation_data");
		}
		if (iter->from != (size_t)meminfobuf.BaseAddress)
		{
			FATAL("Error in ProtectCodeRanges."
				  "Target incompatible with persist_instrumentation_data");
		}
		if (iter->to != (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize)
		{
			FATAL("Error in ProtectCodeRanges."
				  "Target incompatible with persist_instrumentation_data");
		}
		if (!(meminfobuf.Protect & 0xF0))
		{
			FATAL("Error in ProtectCodeRanges."
				  "Target incompatible with persist_instrumentation_data");
		}

		uint8_t low      = meminfobuf.Protect & 0xFF;
		low              = low >> 4;
		DWORD newProtect = (meminfobuf.Protect & 0xFFFFFF00) + low;
		DWORD oldProtect;
		if (!VirtualProtect(meminfobuf.BaseAddress,
							meminfobuf.RegionSize,
							newProtect,
							&oldProtect))
		{
			FATAL("Error in VirtualProtectEx");
		}
	}
}

DWORD Executor::GetImageSize(void* base_address)
{
	unsigned char headers[4096];
	std::memcpy(headers, base_address, 4096);

	DWORD pe_offset;
	pe_offset                = *((DWORD*)(headers + 0x3C));
	unsigned char* pe        = headers + pe_offset;
	DWORD          signature = *((DWORD*)pe);
	if (signature != 0x00004550)
	{
		FATAL("PE signature error\n");
	}
	pe         = pe + 0x18;
	WORD magic = *((WORD*)pe);
	if ((magic != 0x10b) && (magic != 0x20b))
	{
		FATAL("Unknown PE magic value\n");
	}
	DWORD SizeOfImage = *((DWORD*)(pe + 56));
	return SizeOfImage;
}

void Executor::GetImageSize(void* base_address, size_t* min_address, size_t* max_address)
{
	*min_address      = (size_t)base_address;
	DWORD SizeOfImage = GetImageSize(base_address);
	*max_address      = *min_address + SizeOfImage;
}

// allocates memory in process as close as possible
// to max_address, but at address larger than min_address
void* Executor::RemoteAllocateBefore(
	uint64_t         min_address,
	uint64_t         max_address,
	size_t           size,
	MemoryProtection protection)
{
	DWORD protection_flags = WindowsProtectionFlags(protection);

	MEMORY_BASIC_INFORMATION meminfobuf;
	void*                    ret_address = NULL;

	uint64_t cur_code = max_address;
	while (cur_code > min_address)
	{
		// Don't attempt allocating on the null page
		if (cur_code < 0x1000)
			break;

		size_t step = size;

		size_t query_ret = VirtualQuery((LPCVOID)cur_code,
										&meminfobuf,
										sizeof(MEMORY_BASIC_INFORMATION));
		if (!query_ret)
			break;

		if (meminfobuf.State == MEM_FREE)
		{
			if (meminfobuf.RegionSize >= size)
			{
				size_t address = (size_t)meminfobuf.BaseAddress +
								 (meminfobuf.RegionSize - size);
				ret_address = VirtualAlloc((LPVOID)address,
										   size,
										   MEM_COMMIT | MEM_RESERVE,
										   protection_flags);
				if (ret_address)
				{
					if (((size_t)ret_address >= min_address) &&
						((size_t)ret_address <= max_address))
					{
						return ret_address;
					}
					else
					{
						return NULL;
					}
				}
			}
			else
			{
				step = size - meminfobuf.RegionSize;
			}
		}

		cur_code = (size_t)meminfobuf.BaseAddress;
		if (cur_code < step)
			break;
		else
			cur_code -= step;
	}

	return ret_address;
}

// allocates memory in target process as close as possible
// to min_address, but not higher than max_address
void* Executor::RemoteAllocateAfter(
	uint64_t         min_address,
	uint64_t         max_address,
	size_t           size,
	MemoryProtection protection)
{
	DWORD protection_flags = WindowsProtectionFlags(protection);

	MEMORY_BASIC_INFORMATION meminfobuf;
	void*                    ret_address = NULL;

	uint64_t cur_code = min_address;
	while (cur_code < max_address)
	{
		size_t query_ret = VirtualQuery((LPCVOID)cur_code,
										&meminfobuf,
										sizeof(MEMORY_BASIC_INFORMATION));
		if (!query_ret)
			break;

		if (meminfobuf.State == MEM_FREE)
		{
			size_t region_address = (size_t)meminfobuf.BaseAddress;
			size_t region_size    = meminfobuf.RegionSize;
			// make sure we are allocating on an address that
			// is aligned according to allocation_granularity
			size_t alignment = region_address & (allocation_granularity - 1);
			if (alignment)
			{
				size_t offset = (allocation_granularity - alignment);
				region_address += offset;
				if (region_size > offset)
				{
					region_size -= offset;
				}
				else
				{
					region_size = 0;
				}
			}
			if (region_size >= size)
			{
				ret_address = VirtualAlloc((LPVOID)region_address,
										   size,
										   MEM_COMMIT | MEM_RESERVE,
										   protection_flags);
				if (ret_address)
				{
					if (((size_t)ret_address >= min_address) &&
						((size_t)ret_address <= max_address))
					{
						return ret_address;
					}
					else
					{
						return NULL;
					}
				}
			}
		}

		cur_code = (size_t)meminfobuf.BaseAddress + meminfobuf.RegionSize;
	}

	return ret_address;
}

DWORD Executor::WindowsProtectionFlags(MemoryProtection protection)
{
	switch (protection)
	{
	case READONLY:
		return PAGE_READONLY;
	case READWRITE:
		return PAGE_READWRITE;
	case READEXECUTE:
		return PAGE_EXECUTE_READ;
	case READWRITEEXECUTE:
		return PAGE_EXECUTE_READWRITE;
	default:
		FATAL("Unumplemented memory protection");
	}
}

DWORD Executor::GetLoadedModules(HMODULE** modules)
{
	DWORD    module_handle_storage_size = 1024 * sizeof(HMODULE);
	HMODULE* module_handles             = (HMODULE*)malloc(module_handle_storage_size);
	DWORD    hmodules_size;
	while (true)
	{
		if (!EnumProcessModulesEx(self_handle,
								  module_handles,
								  module_handle_storage_size,
								  &hmodules_size,
								  LIST_MODULES_ALL))
		{
			FATAL("EnumProcessModules failed, %x\n", GetLastError());
		}
		if (hmodules_size <= module_handle_storage_size)
			break;
		module_handle_storage_size *= 2;
		module_handles = (HMODULE*)realloc(module_handles, module_handle_storage_size);
	}
	*modules = module_handles;
	return hmodules_size / sizeof(HMODULE);
}

void Executor::ConvertException(
	EXCEPTION_RECORD* win_exception_record,
	Exception*        exception)
{
	switch (win_exception_record->ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
	case 0x4000001f:
		exception->type = BREAKPOINT;
		break;
	case EXCEPTION_ACCESS_VIOLATION:
		exception->type = ACCESS_VIOLATION;
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		exception->type = ILLEGAL_INSTRUCTION;
		break;
	case EXCEPTION_STACK_OVERFLOW:
		exception->type = STACK_OVERFLOW;
		break;
	default:
		exception->type = OTHER;
		break;
	}

	exception->ip = win_exception_record->ExceptionAddress;

	exception->maybe_execute_violation = false;
	exception->maybe_write_violation   = false;
	exception->access_address          = 0;
	if (win_exception_record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		if (win_exception_record->ExceptionInformation[0] == 8)
		{
			exception->maybe_execute_violation = true;
		}
		if (win_exception_record->ExceptionInformation[0] == 1)
		{
			exception->maybe_write_violation = true;
		}

		exception->access_address = (void*)(win_exception_record->ExceptionInformation[1]);
	}

	if (win_exception_record->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		uint8_t* ip = reinterpret_cast<uint8_t*>(win_exception_record->ExceptionAddress);
		// treat hlt as breakpoint instruction.
		// see comments of BREAKPOINT.
		const uint8_t hlt_code = 0xF4;
		if (ip[0] == hlt_code)
		{
			exception->type = BREAKPOINT;
		}
	}
}

void* Executor::RemoteAllocateNear(
	uint64_t         region_min,
	uint64_t         region_max,
	size_t           size,
	MemoryProtection protection,
	bool             use_shared_memory /*= false*/)
{
	void* ret = NULL;

	// try before first
	uint64_t min_address = region_max;
	if (min_address < 0x80000000)
		min_address = 0;
	else
		min_address -= 0x80000000;
	uint64_t max_address = region_min;
	if (max_address < size)
		max_address = 0;
	else
		max_address -= size;

	ret = RemoteAllocateBefore(min_address,
							   max_address,
							   size,
							   protection);

	if (ret)
		return ret;

	min_address                = region_max;
	uint64_t address_range_max = 0xFFFFFFFFFFFFFFFFULL;
	if (child_ptr_size == 4)
	{
		address_range_max = 0xFFFFFFFFULL;
	}
	if ((address_range_max - 0x80000000) < region_min)
	{
		max_address = address_range_max - size;
	}
	else
	{
		max_address = region_min + 0x80000000 - size;
	}

	ret = RemoteAllocateAfter(min_address,
							  max_address,
							  size,
							  protection);

	return ret;
}

void Executor::RemoteFree(void* address, size_t size)
{
	VirtualFree(address, 0, MEM_RELEASE);
}

void Executor::RemoteWrite(void* address, void* buffer, size_t size)
{
	SIZE_T size_written;
	if (WriteProcessMemory(
			self_handle,
			address,
			buffer,
			size,
			&size_written))
	{
		return;
	}

	// we need to
	// (a) read page permissions
	// (b) make it writable, and
	// (c) restore permissions
	DWORD oldProtect;
	if (!VirtualProtectEx(self_handle,
						  address,
						  size,
						  PAGE_READWRITE,
						  &oldProtect))
	{
		FATAL("Error in VirtualProtectEx");
	}

	if (!WriteProcessMemory(
			self_handle,
			address,
			buffer,
			size,
			&size_written))
	{
		FATAL("Error writing target memory\n");
	}

	DWORD ignore;
	if (!VirtualProtectEx(self_handle,
						  address,
						  size,
						  oldProtect,
						  &ignore))
	{
		FATAL("Error in VirtualProtectEx");
	}
}

void Executor::RemoteRead(void* address, void* buffer, size_t size)
{
	SIZE_T size_read;
	if (!ReadProcessMemory(
			self_handle,
			address,
			buffer,
			size,
			&size_read))
	{
		FATAL("Error reading target memory\n");
	}
}

void Executor::RemoteProtect(void* address, size_t size, MemoryProtection protect)
{
	DWORD protection_flags = WindowsProtectionFlags(protect);
	DWORD old_protect;

	if (!VirtualProtect(address,
						size,
						protection_flags,
						&old_protect))
	{
		FATAL("Could not apply memory protection");
	}
}

size_t Executor::GetRegister(Context* context, Register r)
{
	CONTEXT& lcContext = *context;

#ifdef _WIN64

	switch (r)
	{
	case RAX:
		return lcContext.Rax;
	case RCX:
		return lcContext.Rcx;
	case RDX:
		return lcContext.Rdx;
	case RBX:
		return lcContext.Rbx;
	case RSP:
		return lcContext.Rsp;
	case RBP:
		return lcContext.Rbp;
	case RSI:
		return lcContext.Rsi;
	case RDI:
		return lcContext.Rdi;
	case R8:
		return lcContext.R8;
	case R9:
		return lcContext.R9;
	case R10:
		return lcContext.R10;
	case R11:
		return lcContext.R11;
	case R12:
		return lcContext.R12;
	case R13:
		return lcContext.R13;
	case R14:
		return lcContext.R14;
	case R15:
		return lcContext.R15;
	case RIP:
		return lcContext.Rip;
	default:
		FATAL("Unimplemented");
	}

#else

	switch (r)
	{
	case RAX:
		return lcContext.Eax;
	case RCX:
		return lcContext.Ecx;
	case RDX:
		return lcContext.Edx;
	case RBX:
		return lcContext.Ebx;
	case RSP:
		return lcContext.Esp;
	case RBP:
		return lcContext.Ebp;
	case RSI:
		return lcContext.Esi;
	case RDI:
		return lcContext.Edi;
	case RIP:
		return lcContext.Eip;
	default:
		FATAL("Unimplemented");
	}

#endif
}

void Executor::SetRegister(Context* context, Register r, size_t value)
{
	CONTEXT& lcContext = *context;

#ifdef _WIN64

	switch (r)
	{
	case RAX:
		lcContext.Rax = value;
		break;
	case RCX:
		lcContext.Rcx = value;
		break;
	case RDX:
		lcContext.Rdx = value;
		break;
	case RBX:
		lcContext.Rbx = value;
		break;
	case RSP:
		lcContext.Rsp = value;
		break;
	case RBP:
		lcContext.Rbp = value;
		break;
	case RSI:
		lcContext.Rsi = value;
		break;
	case RDI:
		lcContext.Rdi = value;
		break;
	case R8:
		lcContext.R8 = value;
		break;
	case R9:
		lcContext.R9 = value;
		break;
	case R10:
		lcContext.R10 = value;
		break;
	case R11:
		lcContext.R11 = value;
		break;
	case R12:
		lcContext.R12 = value;
		break;
	case R13:
		lcContext.R13 = value;
		break;
	case R14:
		lcContext.R14 = value;
		break;
	case R15:
		lcContext.R15 = value;
		break;
	case RIP:
		lcContext.Rip = value;
		break;
	default:
		FATAL("Unimplemented");
	}

#else

	switch (r)
	{
	case RAX:
		lcContext.Eax = value;
		break;
	case RCX:
		lcContext.Ecx = value;
		break;
	case RDX:
		lcContext.Edx = value;
		break;
	case RBX:
		lcContext.Ebx = value;
		break;
	case RSP:
		lcContext.Esp = value;
		break;
	case RBP:
		lcContext.Ebp = value;
		break;
	case RSI:
		lcContext.Esi = value;
		break;
	case RDI:
		lcContext.Edi = value;
		break;
	case RIP:
		lcContext.Eip = value;
		break;
	default:
		FATAL("Unimplemented");
	}

#endif
}

void Executor::SaveRegisters(Context* context, SavedRegisters* registers)
{
	CONTEXT lcContext = {};
	GetThreadContext(GetCurrentThread(), &lcContext);
	memcpy(&registers->saved_context, &lcContext, sizeof(registers->saved_context));
}

void Executor::RestoreRegisters(Context* context, SavedRegisters* registers)
{
	if (!SetThreadContext(GetCurrentThread(), &registers->saved_context))
	{
		FATAL("Error restoring registers");
	}
}

DWORD Executor::GetProcOffset(HMODULE module, const char* name)
{
	void* proc_address = GetProcAddress(module, name);
	DWORD offset =
		static_cast<DWORD>(
			reinterpret_cast<uintptr_t>(proc_address) - reinterpret_cast<uintptr_t>(module));
	return offset;
}

// Gets the registered safe exception handlers for the module
void Executor::GetExceptionHandlers(size_t module_header, std::unordered_set<size_t>& handlers)
{
	// only present on x86
	if (child_ptr_size != 4)
		return;

	DWORD size_of_image = GetImageSize((void*)module_header);

	char* modulebuf = (char*)malloc(size_of_image);
	std::memcpy(modulebuf, (void*)module_header, size_of_image);

	DWORD pe_offset;
	pe_offset       = *((DWORD*)(modulebuf + 0x3C));
	char* pe        = modulebuf + pe_offset;
	DWORD signature = *((DWORD*)pe);
	if (signature != 0x00004550)
	{
		free(modulebuf);
		return;
	}
	pe          = pe + 0x18;
	WORD  magic = *((WORD*)pe);
	DWORD lc_offset;
	DWORD lc_size;
	if (magic == 0x10b)
	{
		lc_offset = *(DWORD*)(pe + 176);
		lc_size   = *(DWORD*)(pe + 180);
	}
	else if (magic == 0x20b)
	{
		lc_offset = *(DWORD*)(pe + 192);
		lc_size   = *(DWORD*)(pe + 196);
	}
	else
	{
		free(modulebuf);
		return;
	}

	if (!lc_offset || (lc_size != 64))
	{
		free(modulebuf);
		return;
	}

	char* lc = modulebuf + lc_offset;

	size_t seh_table_address;
	DWORD  seh_count;
	if (magic == 0x10b)
	{
		seh_table_address = *(DWORD*)(lc + 64);
		seh_count         = *(DWORD*)(lc + 68);
	}
	else if (magic == 0x20b)
	{
		seh_table_address = *(uint64_t*)(lc + 96);
		seh_count         = *(DWORD*)(lc + 104);
	}
	else
	{
		free(modulebuf);
		return;
	}

	size_t seh_table_offset = seh_table_address - module_header;

	DWORD* seh_table = (DWORD*)(modulebuf + seh_table_offset);
	for (DWORD i = 0; i < seh_count; i++)
	{
		handlers.insert(module_header + seh_table[i]);
	}

	free(modulebuf);
}

template <typename T>
void Executor::PatchPointersRemoteT(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace)
{
	size_t module_size = max_address - min_address;
	char*  buf         = (char*)malloc(module_size);
	RemoteRead((void*)min_address, buf, module_size);

	size_t remote_address = min_address;
	for (size_t i = 0; i < (module_size - child_ptr_size + 1); i++)
	{
		T    ptr  = *(T*)(buf + i);
		auto iter = search_replace.find(ptr);
		if (iter != search_replace.end())
		{
			// printf("patching entry %zx at address %zx\n", (size_t)ptr, remote_address);
			T fixed_ptr = (T)iter->second;
			RemoteWrite((void*)remote_address, &fixed_ptr, child_ptr_size);
		}
		remote_address += 1;
	}

	free(buf);
}

void Executor::PatchPointersRemote(size_t min_address, size_t max_address, std::unordered_map<size_t, size_t>& search_replace)
{
	if (child_ptr_size == 4)
	{
		PatchPointersRemoteT<uint32_t>(min_address, max_address, search_replace);
	}
	else
	{
		PatchPointersRemoteT<uint64_t>(min_address, max_address, search_replace);
	}
}

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


LONG WINAPI Executor::VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	LONG action = EXCEPTION_CONTINUE_SEARCH;
	do
	{
		auto executor = TinyDBR::GetInstance();
		if (!executor)
		{
			break;
		}

		action = executor->OnVEHException(ExceptionInfo);

	} while (false);

	return action;
}

void __stdcall Executor::DllNotificationHandler(
	unsigned long                    notification_reason,
	const LDR_DLL_NOTIFICATION_DATA* notification_data,
	void*                            context)
{
	Executor* executor = reinterpret_cast<Executor*>(context);
	if (notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		auto& loaded = notification_data->Loaded;
		std::string dll_name = UnicodeToAnsi(loaded.BaseDllName->Buffer, CP_ACP);
		executor->OnModuleLoaded(loaded.DllBase, const_cast<char*>(dll_name.c_str()));
	}
	else if (notification_reason == LDR_DLL_NOTIFICATION_REASON_UNLOADED)
	{
		auto& unloaded = notification_data->Unloaded;
		executor->OnModuleUnloaded(unloaded.DllBase);
	}
}
