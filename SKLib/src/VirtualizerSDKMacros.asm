; ****************************************************************************
; Module: VirtualizerSDKBasicVmMacros.asm
; Description: Another way to link with the SecureEngine SDK via an ASM module
;
; Author/s: Oreans Technologies 
; (c) 2019 Oreans Technologies
; ****************************************************************************

IFDEF RAX

ELSE

.586
.model flat,stdcall
option casemap:none

ENDIF


; ****************************************************************************
;                                 Constants
; ****************************************************************************

.CONST


; ****************************************************************************
;                               Data Segment
; ****************************************************************************

.DATA


; ****************************************************************************
;                               Code Segment
; ****************************************************************************

.CODE

IFDEF RAX

; ****************************************************************************
; VIRTUALIZER definition
; ****************************************************************************

VIRTUALIZER_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 1
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_START_ASM64 ENDP

VIRTUALIZER_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 2
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_END_ASM64 ENDP

; ****************************************************************************
; STR_ENCRYPT definition
; ****************************************************************************

VIRTUALIZER_STR_ENCRYPT_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 23
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_STR_ENCRYPT_START_ASM64 ENDP

VIRTUALIZER_STR_ENCRYPT_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 24
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_STR_ENCRYPT_END_ASM64 ENDP

; ****************************************************************************
; STR_ENCRYPTW definition
; ****************************************************************************

VIRTUALIZER_STR_ENCRYPTW_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 27
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_STR_ENCRYPTW_START_ASM64 ENDP

VIRTUALIZER_STR_ENCRYPTW_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 28
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_STR_ENCRYPTW_END_ASM64 ENDP

; ****************************************************************************
; VIRTUALIZER_UNPROTECTED definition
; ****************************************************************************

VIRTUALIZER_UNPROTECTED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 18
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_UNPROTECTED_START_ASM64 ENDP

VIRTUALIZER_UNPROTECTED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 19
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_UNPROTECTED_END_ASM64 ENDP

ELSE

; ****************************************************************************
; VIRTUALIZER definition
; ****************************************************************************

VIRTUALIZER_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 1
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_START_ASM32 ENDP

VIRTUALIZER_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 2
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_END_ASM32 ENDP

; ****************************************************************************
; VIRTUALIZER_STR_ENCRYPT definition
; ****************************************************************************

VIRTUALIZER_STR_ENCRYPT_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 23
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_STR_ENCRYPT_START_ASM32 ENDP

VIRTUALIZER_STR_ENCRYPT_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 24
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_STR_ENCRYPT_END_ASM32 ENDP

; ****************************************************************************
; VIRTUALIZER_STR_ENCRYPTW definition
; ****************************************************************************

VIRTUALIZER_STR_ENCRYPTW_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 27
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_STR_ENCRYPTW_START_ASM32 ENDP

VIRTUALIZER_STR_ENCRYPTW_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 28
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_STR_ENCRYPTW_END_ASM32 ENDP

; ****************************************************************************
; VIRTUALIZER_UNPROTECTED definition
; ****************************************************************************

VIRTUALIZER_UNPROTECTED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 18
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_UNPROTECTED_START_ASM32 ENDP

VIRTUALIZER_UNPROTECTED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 19
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_UNPROTECTED_END_ASM32 ENDP

ENDIF

END
