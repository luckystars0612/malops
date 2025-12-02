## 1.What is the entry point address of the sample?

**0x45e540**

## 2.The sample is written in a two-letter programming language. Which one?
DIE return it was written in GO

**go**

## 3.When executed, the malware creates persistence using a Run key. Which Run key path is used?
```bash
v0 = golang_org_x_sys_windows_registry_OpenKey(
             2147483649LL,
             "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             45,
             2);
      result = v0._r0;
```

**Software\Microsoft\Windows\CurrentVersion\Run**

## 4.What is the registry value name used for persistence?
```bash
v4 = golang_org_x_sys_windows_registry_Key_setStringValue(
               v3._r0,
               (__int64)"CalculatorApp_AutoStart",
               23,
               1,
               r0,
               v10._r1,
               v0,
               v1,
               v2);
```

**CalculatorApp_AutoStart**

## 5.The malware decrypts a second-stage payload at runtime. Which symmetric encryption algorithm is used?
```bash
v32 = main_AesDecryptByECB("1ws12uuu11j*p5fr", 16, v0, 153184);
```

**aes**

## 6.What is the decryption key used for unpacking the second stage?

**1ws12uuu11j*p5fr**

## 7.How many bytes does the decrypted second-stage payload contain?

**153184**

## 8.Which Windows security feature does the malware patch first?
We know where the shellcode was decoded, then extract it into file
```bash
import idaapi

# Replace with actual address and size from your debug session
shellcode_addr = 0x000000C0001A6000  # v32 value
shellcode_size = 153184      # or check v30/RBX

data = idaapi.get_bytes(shellcode_addr, shellcode_size)
with open("decrypted_shellcode.bin", "wb") as f:
    f.write(data)

print(f"Dumped {shellcode_size} bytes to decrypted_shellcode.bin")
```
DIE detects it is donut shellcode then use [donut-decyptor](https://github.com/volexity/donut-decryptor) to decrypt it and get an pe file
```bash
 file mod_decrypted_shellcode.bin
mod_decrypted_shellcode.bin: PE32+ executable for MS Windows 5.02 (GUI), x86-64, 6 sections
```
Here is the main function
```bash
__int64 wmain()
{
  HWND ConsoleWindow; // rax
  DWORD CurrentThreadId; // eax

  SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  ConsoleWindow = GetConsoleWindow();
  ShowWindow(ConsoleWindow, 0);
  CurrentThreadId = GetCurrentThreadId();
  PostThreadMessageA(CurrentThreadId, 0, 0, 0);
  GetInputState();
  sub_1400073D0();
  hObject = CreateThread(0, 0, StartAddress, 0, 0, 0);
  WaitForSingleObject(hObject, 0xFFFFFFFF);
  CloseHandle(hObject);
  Sleep(0x12Cu);
  return 0;
}
```
## 9.Which second Windows security feature does the malware patch?

## 10.After security patching, another shellcode stage executes. A memory region modified via VirtualProtect (size ~0x29000 bytes) contains the C2 configuration. What is the referenced C2 domain?

**maaahao.vip**

## 11.Inside the dumped memory section, three C2 ports are referenced. List them in ascending order, comma-separated.
In `sub_1400073D0` is the main part of config parsing, check it reveals
```bash
 if ( !byte_140023508 )
  {
    byte_140023508 = 1;
    wcsrev(a0Db0Lk0Hs0Ld0L);
    memset(&Src, 0, 0x12A0u);
    sub_1400072A0(L"p1:", &Source);
    sub_1400072A0(L"o1:", &word_14002246C);
    v1 = lstrlenW(a0Db0Lk0Hs0Ld0L);
    v2 = lstrlenW(L"t1:");
```
It reverse string from `a0Db0Lk0Hs0Ld0L` and extract config from this
```bash
0:db|0:lk|0:hs|0:ld|0:ll|0:bh|0:jp|7 .11.52.2025:zb|0.1:bb|蟘:fz|1:cl|1:dd|1:t3|08:o3|maaahao.vip:p3|1:t2|8888:o2|maaahao.vip:p2|1:t1|1808:o1|maaahao.vip:p1|
```

**80,8081,8888**

## 12.The sample implements a process-dumping function. What is the referenced dump filename format string?
```bash
LibraryW = LoadLibraryW(L"DbgHelp.dll");
  v3 = LibraryW;
  if ( !LibraryW )
    return 0xFFFFFFFFLL;
  MiniDumpWriteDump = (BOOL (__stdcall *)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION))GetProcAddress(LibraryW, "MiniDumpWriteDump");
  if ( MiniDumpWriteDump )
  {
    memset(FileName, 0, 520);
    GetLocalTime(&SystemTime);
    wsprintfW(
      FileName,
      L"%s-%04d%02d%02d-%02d%02d%02d.dmp",
      L"!analyze -v",
      SystemTime.wYear,
      SystemTime.wMonth,
      SystemTime.wDay,
      SystemTime.wHour,
      SystemTime.wMinute,
      SystemTime.wSecond);
    FileW = CreateFileW(FileName, 0xC0000000, 3u, 0, 2u, 0, 0);
```

**%s-%04d%02d%02d-%02d%02d%02d.dmp**

## 13.Which DLL is used for the dumping process?

**DbgHelp.dll**