#pragma once

#ifdef UNICODE
#undef UNICODE
#endif

#ifdef _UNICODE
#undef _UNICODE
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <Windows.h>

#include <winternl.h>
#pragma comment(lib, "ntdll")

#include <iostream>

#define STATUS_SUCCESS			((NTSTATUS)0x00000000)
#define STATUS_ACCESS_DENIED	((NTSTATUS)0xC0000022)
	
const OBJECT_INFORMATION_CLASS ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);

typedef struct _CLIENT_ID
{
	DWORD UniqueProcess;
	DWORD UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
	WCHAR NameBuffer[1024];
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;