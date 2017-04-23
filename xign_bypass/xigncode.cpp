#include "xigncode.hpp"
#include "xigncode_callback.hpp"
#include "xigncode_manager.hpp"

#include <psapi.h>
#pragma comment(lib, "psapi")

#include <intrin.h>

namespace xigncode
{
	bool Hook_WideCharToMultiByte()
	{
		static decltype(&WideCharToMultiByte) _WideCharToMultiByte = &WideCharToMultiByte;

		decltype(&WideCharToMultiByte) WideCharToMultiByte_hook = [](UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) -> int
		{
			if (lpWideCharStr)
			{
				if (wcsstr(lpWideCharStr, L" => "))
					xigncode_manager::get_instance().add_image(std::wstring(lpWideCharStr));
				
				if (!xigncode_manager::get_instance().is_spider_ok())
					if (wcsstr(lpWideCharStr, L"spider ok"))
						xigncode_manager::get_instance().set_spider_ok();
			}

			HMODULE module = NULL;
			
			if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &module))
			{
				char module_file_name[1024];
				memset(module_file_name, 0, sizeof(module_file_name));

				if (GetModuleBaseName(GetCurrentProcess(), module, module_file_name, sizeof(module_file_name)) && lstrcmpi(module_file_name, "x3.xem") && !wcsstr(lpWideCharStr, L"0123456789:;<=>?"))
				{
					wchar_t log_output[1024];
					memset(log_output, 0, 1024 * sizeof(wchar_t));

					wsprintfW(log_output, L"[%08X] %ws\n", _ReturnAddress(), lpWideCharStr);
					OutputDebugStringW(log_output);
				}
			}

			return _WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
		};

		return function::redirect(true, reinterpret_cast<void**>(&_WideCharToMultiByte), WideCharToMultiByte_hook);
	}
	
	bool Hook_NtCreateSemaphore()
	{
		typedef NTSTATUS (NTAPI* NtCreateSemaphore_t)(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG InitialCount, ULONG MaximumCount);
		static NtCreateSemaphore_t _NtCreateSemaphore = reinterpret_cast<NtCreateSemaphore_t>(GetProcAddress(GetModuleHandle("ntdll"), "NtCreateSemaphore"));
		
		NtCreateSemaphore_t NtCreateSemaphore_hook = [](PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG InitialCount, ULONG MaximumCount) -> NTSTATUS
		{
			if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer && !wcscmp(ObjectAttributes->ObjectName->Buffer, L"Global\\368457d19197f4eec4a257959dfdb062"))
					return _NtCreateSemaphore(SemaphoreHandle, DesiredAccess, NULL, InitialCount, MaximumCount);
			
			return _NtCreateSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount);
		};

		return function::redirect(true, reinterpret_cast<void**>(&_NtCreateSemaphore), NtCreateSemaphore_hook);
	}

	bool Hook_NtOpenProcess()
	{
		typedef NTSTATUS (NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
		static NtOpenProcess_t _NtOpenProcess = reinterpret_cast<NtOpenProcess_t>(GetProcAddress(GetModuleHandle("ntdll"), "NtOpenProcess"));
		
		NtOpenProcess_t NtOpenProcess_hook = [](PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) -> NTSTATUS
		{
			if (ClientId->UniqueProcess != GetCurrentProcessId() || xigncode_manager::get_instance().is_spider_ok())
				return STATUS_ACCESS_DENIED;
			
			return _NtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
		};

		return function::redirect(true, reinterpret_cast<void**>(&_NtOpenProcess), NtOpenProcess_hook);
	}
	
	bool Hook_NtOpenThread()
	{
		typedef NTSTATUS (NTAPI* NtOpenThread_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
		static NtOpenThread_t _NtOpenThread = reinterpret_cast<NtOpenThread_t>(GetProcAddress(GetModuleHandle("ntdll"), "NtOpenThread"));
		
		NtOpenThread_t NtOpenThread_hook = [](PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) -> NTSTATUS
		{
			if (DesiredAccess & THREAD_QUERY_INFORMATION)
			{
				if (DesiredAccess == THREAD_ALL_ACCESS)
					DesiredAccess &= ~THREAD_QUERY_LIMITED_INFORMATION;

				DesiredAccess &= ~THREAD_QUERY_INFORMATION;
			}

			return _NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
		};

		return	function::redirect(true, reinterpret_cast<void**>(&_NtOpenThread), NtOpenThread_hook);
	}

	bool Hook_NtQuerySystemInformation()
	{
		static decltype(&NtQuerySystemInformation) _NtQuerySystemInformation = &NtQuerySystemInformation;

		decltype(&NtQuerySystemInformation) NtQuerySystemInformation_hook = [](SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) -> NTSTATUS
		{
			if (SystemInformationClass == SystemProcessInformation && SystemInformation)
			{
				HMODULE module = 0;
				
				if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(_ReturnAddress()), &module))
				{
					NTSTATUS status = _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

					if (status == STATUS_SUCCESS)
					{
						for (SYSTEM_PROCESS_INFORMATION* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(SystemInformation); spi->NextEntryOffset != 0; 
							spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<unsigned char*>(spi) + spi->NextEntryOffset))
						{
							memset(spi->ImageName.Buffer, 0, spi->ImageName.Length);
							memset(&spi->ImageName, 0, sizeof(UNICODE_STRING));
							spi->UniqueProcessId = 0;
							spi->InheritedFromUniqueProcessId = 0;
							spi->HandleCount = 0;
						}
					}

					return status;
				}
			}
			
			return _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		};
		
		return function::redirect(true, reinterpret_cast<void**>(&_NtQuerySystemInformation), NtQuerySystemInformation_hook);
	}
	
	bool Hook_CreateProcessW()
	{
		static decltype(&CreateProcessW) _CreateProcessW = &CreateProcessW;

		decltype(&CreateProcessW) CreateProcessW_hook = [](LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, 
			BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) -> BOOL
		{
			if (lpCommandLine && !_wcsicmp(lpCommandLine + wcslen(lpCommandLine) - 5, L".xem\""))
			{
				if (lpProcessInformation)
				{
					lpProcessInformation->dwProcessId = GetCurrentProcessId();
					lpProcessInformation->dwThreadId = GetCurrentThreadId();
					lpProcessInformation->hProcess = GetCurrentProcess();
					lpProcessInformation->hThread = GetCurrentThread();
				}

				return TRUE;
			}

			return _CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, 
				dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
		};

		return function::redirect(true, reinterpret_cast<void**>(&_CreateProcessW), CreateProcessW_hook);
	}
	
	bool Hook_DeviceIoControl()
	{
		static decltype(&DeviceIoControl) _DeviceIoControl = &DeviceIoControl;

		decltype(&DeviceIoControl) DeviceIoControl_hook = [](HANDLE hDevice, DWORD dwIoControlCode, void* lpInBuffer, DWORD nInBufferSize, void* lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) -> BOOL
		{
			if (dwIoControlCode == FSCTL_QUERY_USN_JOURNAL)
				return FALSE;
			
			return _DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
		};
		
		return function::redirect(true, reinterpret_cast<void**>(&_DeviceIoControl), DeviceIoControl_hook);
	}
	
	bool Hook_StartServiceW()
	{
		static decltype(&StartServiceW) _StartServiceW = &StartServiceW;

		decltype(&StartServiceW) StartServiceW_hook = [](SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) -> BOOL
		{
			return TRUE;
		};
		
		return function::redirect(true, reinterpret_cast<void**>(&_StartServiceW), StartServiceW_hook);
	}
	
	void initialize_bypass()
	{
		Hook_EnterCriticalSection();
		Hook_WideCharToMultiByte();

		Hook_NtCreateSemaphore();
		Hook_NtOpenProcess();
		Hook_NtOpenThread();
		Hook_NtQuerySystemInformation();

		Hook_CreateProcessW();
		Hook_DeviceIoControl();
		Hook_StartServiceW();
	}
}