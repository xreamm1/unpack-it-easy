; Owned analysis fixture. Changes only its own stack and returns a character.
.code
decode_fixture PROC FRAME
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    mov dword ptr [rsp+20h], 7b7b727fh
    mov word ptr [rsp+24h], 3778h
    xor eax, eax
decode_loop:
    xor byte ptr [rsp+rax+20h], 37h
    inc eax
    cmp eax, 6
    jb decode_loop
    movzx eax, byte ptr [rsp+20h]
    add rsp, 40h
    ret
decode_fixture ENDP
END
