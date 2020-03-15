#pragma once

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <Strsafe.h>
#include <TlHelp32.h>
#include <vector>
#pragma comment(lib,"Advapi32.lib")

using namespace std;
typedef NTSTATUS (WINAPI* FN_NtQueryInformationThread)(
	IN HANDLE               ThreadHandle,
	IN THREAD_INFORMATION_CLASS ThreadInformationClass,
	OUT PVOID               ThreadInformation,
	IN ULONG                ThreadInformationLength,
	OUT PULONG              ReturnLength OPTIONAL);

typedef enum _SC_SERVICE_TAG_QUERY_TYPE
{
	ServiceNameFromTagInformation = 1,
	ServiceNamesReferencingModuleInformation,
	ServiceNameTagMappingInformation
} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;


typedef struct _SC_SERVICE_TAG_QUERY
{
	ULONG ProcessId;
	ULONG ServiceTag;
	ULONG Unknown;
	PVOID Buffer;
} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;



typedef ULONG(NTAPI* FN_I_QueryTagInformation)(
	__in PVOID Unknown,
	__in SC_SERVICE_TAG_QUERY_TYPE QueryType,
	__inout PSC_SERVICE_TAG_QUERY Query
	);

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	int						ClientId;
	KAFFINITY               AffinityMask;
	int						Priority;
	int						BasePriority;
	int						v;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


typedef void(WINAPI* FnCall)(vector<INT> &);

DWORD fn_seek_logservice_pid();

DWORD fn_enum_process_module(DWORD dwProcessId);

BOOL fn_query_thread_information(DWORD dwProcessId, HANDLE hOpenThread);

BOOL fn_get_service_name(DWORD dwProcessId, ULONG subProcessTag);

DWORD fn_threadInfo_rettid(DWORD Pid, vector<INT>& threads);

BOOL fn_GrantPriviledge(WCHAR* PriviledgeName);

void fn_Resume_Threads(vector<INT> & threads);

void fn_Suspend_threads(vector<INT> & threads);

VOID fn_GetLastError(LPCSTR lpszFunction);

void fn_TerminateThread_Threads(vector<INT>& threads);

FnCall FN = NULL;