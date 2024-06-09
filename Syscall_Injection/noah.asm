.code
EXTERN UpdateGlobals: PROC
EXTERN gCurrentSyscall:QWORD
EXTERN gSSN:QWORD 
EXTERN gJMP:QWORD

NoahRead3 PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov rcx,gCurrentSyscall
	call UpdateGlobals        ; Get a syscall offset from a different api.
	mov rax,gSSN ;Move SSN into EAX
	mov r15,gJMP; WORKS WORKS WORKS
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r15                                ; Jump to -> Invoke system call.
NoahRead3 ENDP

end


;Parameters
;RCX=1
;RDX=2
;ActualSSN,Indirect JMP Location


