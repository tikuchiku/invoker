// Copyright (c) 2019 Ivan Šincek

#ifndef INVOKER
#define INVOKER

#include <string>
#include <windows.h>

#define STREAM_BUFFER_SIZE 1024
#define STRING_BUFFER_SIZE   15
#define WMI_ARRAY_SIZE       10
#define SVC_START             1
#define SVC_STOP              2
#define SVC_RESTART           3

// ---------------------------------- STRINGS ----------------------------------

std::string IntToStr(int num);

int StrToInt(std::string str);

int StrToInt(BSTR str);

std::string StrToLower(std::string str);

std::string StrToUpper(std::string str);

void Output(std::string msg);

std::string Trim(std::string str);

std::string Input(std::string msg);

bool IsPositiveNumber(std::string str);

std::string StrStripFirstFront(std::string str, std::string delim, bool clear = false);

std::string StrStripFirstBack(std::string str, std::string delim, bool clear = false);

std::string GetErrorMessage(int code);

// ----------------------------------- SHELL -----------------------------------

std::string GetFileName(HMODULE hModule = NULL);

bool IsShellAccessible();

void Pause();

void Clear();

void ShellExec(std::string command = "");

void PowerShellExec(std::string command = "");

// ----------------------------------- FILES -----------------------------------

bool CreateFile(std::string out, std::string data = "");

std::string ReadFile(std::string file);

bool AppendFile(std::string file, std::string data);

bool DuplicateFile(std::string file, std::string out);

typedef int(__stdcall* MyURLDownloadToFile)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);

bool DownloadFile(std::string url, std::string out);

// -------------------------------- PERSISTENCE --------------------------------

bool EditRegistryKey(PHKEY hKey, std::string subkey, std::string name, std::string data);

bool ScheduleTask(std::string name, std::string user, std::string file, std::string args = "");

// ------------------------------------ WMI ------------------------------------

std::string GetErrorMessage(int code);

void WMIRunQuery(std::string query, std::string language = "WQL", std::string space = "ROOT\\CIMV2");

bool WMIExecuteMethod(std::string obj, std::string method, std::string space = "ROOT\\CIMV2");

bool WMIExecuteMethod(std::string obj, std::string method, std::string property, std::string value, std::string space = "ROOT\\CIMV2");

// --------------------------------- PROCESSES ---------------------------------

bool ReverseTCP(std::string addr, std::string port, std::string args = "CMD");

bool IsWoW64(int pid);

int GetProcessID();

bool TerminateProcess(int pid);

bool RunProcess(std::string file, std::string args = "", PHANDLE hToken = NULL);

typedef int(__stdcall* MyMiniDumpWriteDump)(HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);

bool DumpProcessMemory(int pid);

// --------------------------------- BYTECODES ---------------------------------

std::string GetWebContent(std::string url, std::string port, std::string method = "GET");

std::string ExtractPayload(std::string data, std::string element = "<invoker>payload</invoker>", std::string placeholder = "payload");

bool InjectBytecode(int pid, std::string bytecode);

// ------------------------------------ DLL ------------------------------------

bool InjectDLL(int pid, std::string file);

void ListProcessDLLs(int pid);

struct hook {
	std::string file;
	HANDLE hThread;
	bool active;
};

void HookJob(struct hook* info);

HANDLE CreateHookThread(struct hook* info);

void RemoveHookThread(struct hook* info);

// ----------------------------------- TOKEN -----------------------------------

void EnableAccessTokenPrivs();

HANDLE DuplicateAccessToken(int pid);

// ----------------------------------- MISCS -----------------------------------

std::string GetUnquotedServiceName();

bool ManageService(std::string name, int task);

bool ReplaceStickyKeys();

#endif

