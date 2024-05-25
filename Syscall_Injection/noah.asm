.code


;I dont fully understand this syntax but im gonna go w it for now;
EXTERN IndirectSyscall:PROC
EXTERN RetrieveOriginalSSN: PROC

;Okay so what I'm thinking is we remake that GetRandomSyscallAddress by Hells Gating through NTDLL and saving all
;of the syscall opcodes

;Then we just pick a random one based off somekinda time based seed

;Then we return that SSN to the function and note which register the return val gets save into

;Then we move our good SSN into the proper register, we just jmp to the new syscall location prior 

;I think that since we're doing all this work to get ALL the SSN's i want this function to be universal for any syscall. ideally.
NoahAssembly PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0F8D7E269h        ; Load function hash into ECX.
	call IndirectSyscall        ; Get a syscall offset from a different api.
	mov r11, rax                           ; Save the address of the syscall
	mov ecx, 0F8D7E269h        ; Re-Load function hash into ECX (optional).
	call RetrieveOriginalSSN              ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp+8]                      ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                ; Jump to -> Invoke system call.
NoahAssembly ENDP

end