.code

DoIndirectVP PROC
    mov [rsp+8h], rcx
    mov [rsp+10h], rdx
    mov eax, [rsp+28h]
    mov r11, [rsp+30h]
    mov [rsp+28h], r9
    mov r9d, r8d
    xor rcx, rcx
    dec rcx
    lea rdx, [rsp+8h]
    lea r8, [rsp+10h]
    push rcx
    pop r10
    jmp r11
DoIndirectVP ENDP

END
