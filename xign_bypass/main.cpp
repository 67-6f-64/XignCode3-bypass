#include "generic.hpp"

#include "exports.hpp"

#include "maplestory.hpp"
#include "xigncode.hpp"

BOOL APIENTRY DllMain(HMODULE module, unsigned long reason, void* reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{	
//#ifdef PRINT_DEBUG_INFO
		AllocConsole();
		SetConsoleTitle("XignCode Bypass");
		AttachConsole(GetCurrentProcessId());
	
		FILE* pFile = nullptr;
		freopen_s(&pFile, "CON", "r", stdin);
		freopen_s(&pFile, "CON", "w", stdout);
		freopen_s(&pFile, "CON", "w", stderr);
//#endif
		
		if (exports::setup())
		{
			maplestory::initialize_bypass();
			xigncode::initialize_bypass();
		}

		DisableThreadLibraryCalls(module);
	}
	else if (reason == DLL_PROCESS_DETACH)
	{	
#ifdef PRINT_DEBUG_INFO
		FreeConsole();
#endif
	}

	return TRUE;
}