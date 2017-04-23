#include "xigncode_callback.hpp"
#include "xigncode_manager.hpp"

#include <list>
#include <algorithm>

namespace xigncode
{
	CRITICAL_SECTION critical_section;

	void __stdcall detection_callback(void* arg0, void* arg4)
	{

	}
	
	bool __stdcall set_detection_callback(void** function_pointer)
	{
		static std::list<void**> function_pointer_list;

		EnterCriticalSection(&critical_section);

		if (std::find(function_pointer_list.begin(), function_pointer_list.end(), function_pointer) == function_pointer_list.end())
		{
			function_pointer_list.push_back(function_pointer);

			unsigned int function_address = reinterpret_cast<unsigned int>(*function_pointer);

			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
			
			if (!VirtualQuery(function_pointer, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
				return false;
			
			/* see if the detection-callback requested is within xkaga */
			std::pair<unsigned int, unsigned int> xkaga_xem = xigncode_manager::get_instance().get_memory_image(L"xkaga.xem");

			if (xkaga_xem.first != 0 && xkaga_xem.second != 0)
			{
				if (xkaga_xem.first < function_address && function_address < (xkaga_xem.first + xkaga_xem.second))
				{
					// 0x0000AC8A initialization
					// 0x00009FE8 Create a structure?
					// 0x00009AC9 What is the prefetch 
					// 0x0000658A ds b
					// 0x0000E665 unknown 1
					// 0x0000F8E8 vms b
					// 0x00011E96 unknown 2
					// 0x00007E8A detection process

					//printf("xkaga hook: %08X (%08X, %08X)\n", function_address - xkaga_xem.first, xkaga_xem.first, xkaga_xem.second);

					if (function_address - xkaga_xem.first != 0x0000AC8A)
						xigncode_manager::get_instance().set_callback(mbi, function_pointer, detection_callback);
				}
			}		
			
			/* see if the detection-callback requested is within xdl */
			std::pair<unsigned int, unsigned int> xdl_xem = xigncode_manager::get_instance().get_memory_image(L"xdl.xem");
			
			if (xdl_xem.first != 0 && xdl_xem.second != 0)
			{
				if (xdl_xem.first < function_address && function_address < (xdl_xem.first + xdl_xem.second))
				{
					// 0x000141E0 running driver verifier

					//printf("xdl hook: %08X (%08X, %08X)\n", function_address - xdl_xem.first, xdl_xem.first, xdl_xem.second);
					
					if ((function_address - xdl_xem.first) == 0x000141E0)
						xigncode_manager::get_instance().set_callback(mbi, function_pointer, detection_callback);
				}
			}
		}

		LeaveCriticalSection(&critical_section);
		return true;
	}
	
	unsigned char* set_detection_callback_hook_address = nullptr;

	void __declspec(naked) set_detection_callback_hook()
	{
		__asm
		{
			pushad
			mov eax,[eax+0x08]
			mov eax,[eax]
			push eax
			call set_detection_callback
			popad
			jmp dword ptr[set_detection_callback_hook_address]
		}
	}

	bool Hook_EnterCriticalSection()
	{
		static decltype(&EnterCriticalSection) _EnterCriticalSection = &EnterCriticalSection;

		decltype(&EnterCriticalSection) EnterCriticalSection_hook = [](LPCRITICAL_SECTION lpCriticalSection) -> void
		{
			static bool is_done = false;

			if (!is_done)
			{
				unsigned int* return_address = reinterpret_cast<unsigned int*>(_ReturnAddress());

				if (*return_address == 0x78246483)
				{
					InitializeCriticalSection(&critical_section);

					set_detection_callback_hook_address = reinterpret_cast<unsigned char*>(return_address) + 0xD3; // 50 E8 ? ? ? ? FF 74 24 ? 8D 44 24 ? FF (xst)
				
					MEMORY_BASIC_INFORMATION mbi;
					memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
					
					if (VirtualQuery(set_detection_callback_hook_address, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
					{
						xigncode_manager::get_instance().set_hook(mbi, reinterpret_cast<void**>(&set_detection_callback_hook_address), set_detection_callback_hook);
					}
					
					is_done = true;
				}
			}

			return _EnterCriticalSection(lpCriticalSection);
		};

		return function::redirect(true, reinterpret_cast<void**>(&_EnterCriticalSection), EnterCriticalSection_hook);
	}
}