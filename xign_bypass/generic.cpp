#include "generic.hpp"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "version")

namespace function
{
	typedef struct _SYSTEM_HANDLE 
	{
		unsigned int process_id;
		unsigned char object_type_number;
		unsigned char flags;
		unsigned short handle;
		void* object;
		ACCESS_MASK granted_access;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		unsigned int handle_count;
		SYSTEM_HANDLE handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	const int STATUS_SUCCESS = 0x00000000;
	const int STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

	const SYSTEM_INFORMATION_CLASS SystemHandleInformation = static_cast<SYSTEM_INFORMATION_CLASS>(16);
	const OBJECT_INFORMATION_CLASS ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);

	bool close_handle(std::string const& handle_name)
	{
		std::wstring wide_handle_name(handle_name.length(), L' ');
		std::copy(handle_name.begin(), handle_name.end(), wide_handle_name.begin());

		int number_of_handles = 512;
		SYSTEM_HANDLE_INFORMATION* handle_group = nullptr;

		unsigned long length = 0;
		NTSTATUS status = 0;

		do
		{
			free(handle_group);

			number_of_handles *= 2;
			handle_group = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(malloc(4 + sizeof(SYSTEM_HANDLE) * number_of_handles));
		
			status = NtQuerySystemInformation(SystemHandleInformation, handle_group, 4 + sizeof(SYSTEM_HANDLE) * number_of_handles, &length);
		}
		while (status == STATUS_INFO_LENGTH_MISMATCH);

		if (status != STATUS_SUCCESS)
		{
			free(handle_group);
			return false;
		}

		for (unsigned int i = 0; i < handle_group->handle_count; i++)
		{
			wchar_t object_name[1024];

			if (NtQueryObject(reinterpret_cast<HANDLE>(handle_group->handles[i].handle), ObjectNameInformation, &object_name, 1024, &length) != STATUS_SUCCESS)
			{
				continue;
			}

			if (wcsstr(object_name, wide_handle_name.c_str()) != NULL)
			{
				HANDLE handle;
				DuplicateHandle(GetCurrentProcess(), reinterpret_cast<HANDLE>(handle_group->handles[i].handle), 0, &handle, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
				CloseHandle(handle);
				free(handle_group);
				return true;
			}
		}
	
		free(handle_group);
		return false;
	}

	bool redirect(bool enable, void** function, void* redirection)
	{
		if (DetourTransactionBegin() != NO_ERROR)
		{
			return false;
		}

		if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
		{
			return false;
		}

		if ((enable ? DetourAttach : DetourDetach)(function, redirection) != NO_ERROR)
		{
			return false;
		}

		if (DetourTransactionCommit() == NO_ERROR)
		{
			return true;
		}

		DetourTransactionAbort();
		return false;
	}
	
	bool get_version(std::string const& file_path, version_struct& version)
	{
		std::size_t size = GetFileVersionInfoSize(file_path.c_str(), nullptr);

		if (!size)
		{
			return false;
		}

		unsigned char* data = new unsigned char[size];

		if (!GetFileVersionInfo(file_path.c_str(), NULL, size, data))
		{
			return false;
		}

		VS_FIXEDFILEINFO* version_info = nullptr;

		if (!VerQueryValueA(data, "\\", reinterpret_cast<void**>(&version_info), &size))
		{
			return false;
		}

		if (size == 0 || version_info->dwSignature != 0xfeef04bd)
		{
			return false;
		}

		version = version_struct(version_info->dwFileVersionMS, version_info->dwFileVersionLS);

		delete[] data;
		return true;
	}
}