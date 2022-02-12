#include "tinydbr.h"
#include <Windows.h>

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

		memcpy(code, &QuickSort, 0x256);
		typedef void (*FnQuickSort)(int number[25], int first, int last);
		FnQuickSort pfnQuickSort = (FnQuickSort)code;
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