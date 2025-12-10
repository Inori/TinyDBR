#include "tinydbr.h"
#include "arch/x86/x86_memory_monitor.h"
#include <Windows.h>
#include <memory>
#include <string>
#include <map>

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
	virtual ~MyMonitor() {};

	DISABLE_SIMD_INSTRUCTION
	void OnMemoryRead(void* address, size_t size) override
	{
		auto iter = m_map.lower_bound((uint64_t)address);
	}

	DISABLE_SIMD_INSTRUCTION
	void OnMemoryWrite(void* address, size_t size) override
	{
		auto iter = m_map.upper_bound((uint64_t)address);
	}

private:
	std::map<uint64_t, uint64_t> m_map;
};


void QuickSort(int number[25], int first, int last)
{
	int i, j, pivot, temp;

	if (first < last)
	{
		pivot = first;
		i     = first;
		j     = last;

		while (i < j)
		{
			while (number[i] <= number[pivot] && i < last)
				i++;
			while (number[j] > number[pivot])
				j--;
			if (i < j)
			{
				temp      = number[i];
				number[i] = number[j];
				number[j] = temp;
			}
		}

		temp          = number[pivot];
		number[pivot] = number[j];
		number[j]     = temp;
		QuickSort(number, first, j - 1);
		QuickSort(number, j + 1, last);
	}
}



void TestShellcode()
{
	void*        code      = nullptr;
	const size_t code_size = 0x1000;

	do 
	{
		code = VirtualAlloc(NULL, code_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!code)
		{
			break;
		}

		int i = 0, count = 25, number[25];

		for (i = 0; i < count; i++)
		{
			number[i] = rand();
		}

		printf("Order before Sort: ");
		for (i = 0; i < count; i++)
		{
			printf(" %d", number[i]);
		}

		//QuickSort(number, 0, count - 1);

		// Copy function code.
		memcpy(code, &QuickSort, 0x256);
		typedef void (*FnQuickSort)(int number[25], int first, int last);
		FnQuickSort pfnQuickSort = (FnQuickSort)code;

		// Initialize TinyDBR

		// Give it a dummy module name.
		char shellcode_name[64] = { 0 };
		sprintf_s(shellcode_name, "shellcode_0x%X", code);

		// Init module info.
		TargetModule virtual_module = {};
		virtual_module.name         = shellcode_name;
		virtual_module.is_main      = true;
		virtual_module.is_shellcode = true;
		virtual_module.code_sections.push_back({ code, code_size });

		// Set shellcode mode to true.
		Options options        = {};
		options.shellcode_mode = true;


		static MyMonitor monitor;

		MonitorFlags flags = IgnoreCode | IgnoreStack | IgnoreRipRelative;
		instrumenter       = std::make_unique<X86MemoryMonitor>(flags, &monitor);
		// instrumenter = std::make_unique<TinyDBR>();

		instrumenter->Init({ virtual_module }, options);

		// After TinyDBR initialization, this call should
		// be rewrite once it get called.
		pfnQuickSort(number, 0, count - 1);

		printf("\n\n");
		printf("Order after Sorted: ");
		for (i = 0; i < count; i++)
		{
			printf(" %d", number[i]);
		}
			
		
	} while (false);	

	if (code)
	{
		VirtualFree(code, code_size, MEM_RELEASE);
	}
}

int main(int argc, char* argv[])
{
	TestShellcode();
	return 0;
}