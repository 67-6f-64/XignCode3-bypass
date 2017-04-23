#pragma once

#define PRINT_STATUS 0

#if (PRINT_STATUS == 1)
#define PRINT_DEBUG_INFO
#endif

#ifdef UNICODE
#undef UNICODE
#endif

#ifdef _UNICODE
#undef _UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _STL_SECURE_NO_WARNINGS
#define _STL_SECURE_NO_WARNINGS
#endif

#include <WinSock2.h>
#include <Windows.h>
#include <Winternl.h>

#include <detours.h>
#pragma comment(lib, "detours")

#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifndef Padding
#define Padding(x) struct { unsigned char __padding##x[(x)]; };
#endif

#ifndef WM_SOCKET
#define WM_SOCKET WM_USER + 100
#endif

/* custom version-type */
typedef struct VERSION
{
	VERSION() : _1(0), _2(0), _3(0), _4(0)
	{
		/* constructor */
	}

	VERSION(unsigned int MS, unsigned int LS)
		: MS(MS), LS(LS)
	{
		/* constructor */
	}

	VERSION(unsigned short _1, unsigned short _2, unsigned short _3, unsigned short _4)
		: _1(_1), _2(_2), _3(_3), _4(_4)
	{
		/* constructor */
	}

	union
	{
		struct
		{
			unsigned short _2;
			unsigned short _1;
		};

		unsigned int MS;
	};

	union
	{
		struct
		{
			unsigned short _4;
			unsigned short _3;
		};

		unsigned int LS;
	};

} version_struct;

namespace function
{
	bool close_handle(std::string const& handle_name);
	bool redirect(bool enable, void** function, void* redirection);
	bool get_version(std::string const& file_path, version_struct& version);
}