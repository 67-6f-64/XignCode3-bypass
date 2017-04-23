#include "maplestory.hpp"
#include "memory.hpp"

namespace maplestory
{
	unsigned char* image_base = nullptr;
	unsigned char* image_end = nullptr;
	unsigned char* image_copy = nullptr;
	
	//void __thiscall CClientSocket::SendPacket(CClientSocket *this, COutPacket *oPacket)
	const unsigned int send_packet = 0x005C5CC0; // Reference: 8B 0D ? ? ? ? 8D 44 24 ? 50 E8 ? ? ? 00 83 BE ? 00 00 00 00 75
	
	const unsigned int dr_check = 0x005BE630; // BD A1 DE 19 (1st call below)
	const unsigned int logo_skipper = 0x008F17C9; // 74 ? 2B F8 81 FF ? ? 00 00 0F

	/* MapleStory CRCs */
	const unsigned int mscrc_address_1 = 0x01437F49; // 3B 8D 70 FF FF FF 0F 85
	const unsigned int mscrc_return_1 = 0x01438169 + 5; // 8A 11 80 C2 01
	const unsigned int mscrc_skip_1 = 0x01C89377;

	const unsigned int mscrc_address_2 = 0x02104717;
	const unsigned int mscrc_return_2 = mscrc_address_2 + 5;
	
	const unsigned int mscrc_address_3 = 0x01FFAE30;
	const unsigned int mscrc_return_3 = 0x02007F0A;

	const unsigned int mscrc_check_1 = mscrc_address_1 - 6;
	const unsigned int mscrc_check_2 = mscrc_address_1 + 6;
	const unsigned int mscrc_check_3 = mscrc_address_2 - 6;
	const unsigned int mscrc_check_4 = mscrc_address_2 + 6;
	const unsigned int mscrc_check_5 = send_packet - 20;
	const unsigned int mscrc_check_6 = send_packet + 40;

	void __declspec(naked) mscrc_hook_1()
	{
		_asm
		{
			cmp ecx,[ebp-0x00000090]
			je Skip

			xor eax,eax
			add eax,edx
			mov edx,[ebp+0x18]
			sub eax,0x08
			mov eax,[edx]
			shr eax,0x08
			xor ecx,ecx
			mov ecx,eax
			shl ecx,0x08
			mov ecx,[ebp+0x08]
			add ecx,[ebp-0x38]
			xor edx,edx
			mov ebx,[ebp+0x08]

			cmp ecx,image_base
			jl nobypass
			cmp ecx,image_end
			jg nobypass

			sub ecx,image_base
			add ecx,[image_copy]

			nobypass:
			mov dl,[ecx]
			add dl,0x01
			jmp [mscrc_return_1]

			Skip:
			push 0x00
			jmp [mscrc_skip_1]
		}
	}
	
	void __declspec(naked) mscrc_hook_2()
	{
		_asm
		{
			cmp ecx,image_base
			jl nobypass
			cmp ecx,image_end
			jg nobypass

			sub ecx,image_base
			add ecx,[image_copy]

			nobypass:
			add al,[ecx]
			pop ecx
			push cx
			jmp [mscrc_return_2]
		}
	}

	void __declspec(naked) mscrc_hook_3()
	{
		_asm
		{
			cmp edx,[mscrc_check_1]
			jl nobypassa
			cmp edx,[mscrc_check_2]
			jg nobypassa
			jmp bypass

			nobypassa:
			cmp edx,[mscrc_check_3]
			jl nobypassb
			cmp edx,[mscrc_check_4]
			jg nobypassb
			jmp bypass

			nobypassb:
			cmp edx,[mscrc_check_5]
			jl nobypass
			cmp edx,[mscrc_check_6]
			jg nobypass

			bypass:
			sub edx,image_base
			add edx,[image_copy]

			nobypass:
			push [edx]
			jmp [mscrc_return_3]
		}
	}
	
	void set_maplestory_crc()
	{
		static memory mscrc_1(mscrc_address_1, 6);
		mscrc_1.jump(mscrc_hook_1);

		static memory mscrc_2(mscrc_address_2, mscrc_return_2 - mscrc_address_2);
		mscrc_2.jump(mscrc_hook_2);

		static memory mscrc_3(mscrc_address_3, 7);
		mscrc_3.jump(mscrc_hook_3);
		
#ifdef PRINT_DEBUG_INFO
		printf("mscrc 1: %08X -> %08X\n", mscrc_address_1, mscrc_return_1);
		printf("mscrc 2: %08X -> %08X\n", mscrc_address_2, mscrc_return_2);
		printf("mscrc 3: %08X -> %08X\n", mscrc_address_3, mscrc_return_3);
		printf("\n");
#endif
	}

	bool set_image_base()
	{
		PEB* peb = reinterpret_cast<TEB*>(__readfsdword(PcTeb))->ProcessEnvironmentBlock;

		/* Set PEB->ImageBaseAddress to the image_copy */
		peb->Reserved3[1] = image_copy;
	
		/* Set the module's DllBase to image_copy */
		PEB_LDR_DATA* loader_data = reinterpret_cast<PEB_LDR_DATA*>(peb->Ldr);

		if (loader_data->InLoadOrderModuleList.Flink == &loader_data->InLoadOrderModuleList) 
		{
			return false;
		}

		LDR_DATA_TABLE_ENTRY* first = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(&loader_data->InLoadOrderModuleList);

		for (LDR_DATA_TABLE_ENTRY* current = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(first->InLoadOrderLinks.Flink); 
			current != first; current = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(current->InLoadOrderLinks.Flink))
		{
			try
			{
				if (current->DllBase == image_base)
				{
					unsigned long protection;
					VirtualProtect(current, sizeof(LDR_DATA_TABLE_ENTRY), PAGE_EXECUTE_READWRITE, &protection);

					current->DllBase = image_copy;
				}
			}
			catch (...)
			{
				continue;
			}
		}

		return true;
	}
	
	void set_additional_hacks()
	{
		membase::set_memory(reinterpret_cast<unsigned char*>(dr_check), "\x33\xC0\xC3", 3);
		membase::set_memory(reinterpret_cast<unsigned char*>(logo_skipper), "\x90\x90", 2);
	}
	
	void initialize_crc_multi()
	{
		function::close_handle("WvsClientMtx");

		image_base = reinterpret_cast<unsigned char*>(GetModuleHandle("MapleStory.exe"));
		IMAGE_NT_HEADERS* nt_header = PIMAGE_NT_HEADERS(image_base + PIMAGE_DOS_HEADER(image_base)->e_lfanew);

		image_copy = reinterpret_cast<unsigned char*>(malloc(nt_header->OptionalHeader.SizeOfImage));
		memcpy(image_copy, image_base, nt_header->OptionalHeader.SizeOfImage);

		image_end = image_base + nt_header->OptionalHeader.SizeOfImage;

		//set_image_base();
		//set_maplestory_crc();
		//set_additional_hacks();
	}

	bool Hook_RegisterClassExA()
	{
		static decltype(&RegisterClassExA) _RegisterClassExA = RegisterClassExA;

		decltype(&RegisterClassExA) RegisterClassExA_hook = [](const WNDCLASSEXA* lpwcx) -> ATOM
		{
			static WNDPROC _SplashWndProc = nullptr;

			static WNDPROC SplashWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT
			{
				if (msg == WM_CREATE)
				{
					char window_caption[256];
					sprintf(window_caption, "MapleStory | PID: %08X (%d)", GetCurrentProcessId(), GetCurrentProcessId());
					SetWindowText(hwnd, window_caption);
				}

				return _SplashWndProc(hwnd, msg, wParam, lParam);
			};

			if (lpwcx->lpszClassName)
			{
				if (!strcmp(lpwcx->lpszClassName, "StartUpDlgClass"))
				{
					initialize_crc_multi();
					return NULL;
				}
				else if (!strcmp(lpwcx->lpszClassName, "MapleStoryClass"))
				{
					_SplashWndProc = lpwcx->lpfnWndProc;
					const_cast<WNDCLASSEXA*>(lpwcx)->lpfnWndProc = SplashWndProc;
				}
				else if (!strcmp(lpwcx->lpszClassName, "NexonADBallon"))
				{
					return NULL;
				}
			}

			return _RegisterClassExA(lpwcx);
		};

		return function::redirect(true, reinterpret_cast<void**>(&_RegisterClassExA), RegisterClassExA_hook);
	}
	
	void initialize_bypass()
	{
		Hook_RegisterClassExA();
	}
}