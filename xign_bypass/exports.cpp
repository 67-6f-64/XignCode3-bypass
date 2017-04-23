#include "exports.hpp"

static FARPROC ijl_spoof_function[6];

void _declspec(naked) ijl15_GetLibVersion()
{
	_asm jmp dword ptr ijl_spoof_function[0]
}

void _declspec(naked) ijl15_Init()
{
	_asm jmp dword ptr ijl_spoof_function[1]
}

void _declspec(naked) ijl15_Free()
{
	_asm jmp dword ptr ijl_spoof_function[2]
}

void _declspec(naked) ijl15_Read()
{
	_asm jmp dword ptr ijl_spoof_function[3]
}

void _declspec(naked) ijl15_Write()
{
	_asm jmp dword ptr ijl_spoof_function[4]
}

void _declspec(naked) ijl15_ErrorStr()
{
	_asm jmp dword ptr ijl_spoof_function[5]
}

namespace exports
{
	bool setup()
	{
		HMODULE ijl15 = LoadLibrary("spoof\\ijl15.dll");
		
		if (!ijl15)
		{
			MessageBox(NULL, "Failed to load library \"spoof\\ijl15.dll\".", NULL, 0);
			return false;
		}
		
		ijl_spoof_function[0] = GetProcAddress(ijl15, "ijlGetLibVersion");
		ijl_spoof_function[1] = GetProcAddress(ijl15, "ijlInit");
		ijl_spoof_function[2] = GetProcAddress(ijl15, "ijlFree");
		ijl_spoof_function[3] = GetProcAddress(ijl15, "ijlRead");
		ijl_spoof_function[4] = GetProcAddress(ijl15, "ijlWrite");
		ijl_spoof_function[5] = GetProcAddress(ijl15, "ijlErrorStr");

		for (int i = 0; i < 6; i++)
		{
			if (!ijl_spoof_function[i])
			{
				MessageBox(NULL, "The ijl15 spoof failed.", NULL, 0);
				return false;
			}
		}

		return true;
	}
}