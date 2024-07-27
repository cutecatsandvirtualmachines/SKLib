; ****************************************************************************
; Module: VirtualizerSDKCustomVmMacros.asm
; Description: Another way to link with the SecureEngine SDK via an ASM module
;
; Author/s: Oreans Technologies 
; (c) 2021 Oreans Technologies
;
; --- File generated automatically from Oreans VM Generator (14/5/2021) ---
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
; VIRTUALIZER_TIGER_WHITE definition
; ****************************************************************************

VIRTUALIZER_TIGER_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 103
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_TIGER_WHITE_START_ASM64 ENDP

VIRTUALIZER_TIGER_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 503
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_TIGER_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_TIGER_RED definition
; ****************************************************************************

VIRTUALIZER_TIGER_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 104
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_TIGER_RED_START_ASM64 ENDP

VIRTUALIZER_TIGER_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 504
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_TIGER_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_TIGER_BLACK definition
; ****************************************************************************

VIRTUALIZER_TIGER_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 105
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_TIGER_BLACK_START_ASM64 ENDP

VIRTUALIZER_TIGER_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 505
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_TIGER_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_FISH_WHITE definition
; ****************************************************************************

VIRTUALIZER_FISH_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 107
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_FISH_WHITE_START_ASM64 ENDP

VIRTUALIZER_FISH_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 507
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_FISH_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_FISH_RED definition
; ****************************************************************************

VIRTUALIZER_FISH_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 109
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_FISH_RED_START_ASM64 ENDP

VIRTUALIZER_FISH_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 509
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_FISH_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_FISH_BLACK definition
; ****************************************************************************

VIRTUALIZER_FISH_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 111
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_FISH_BLACK_START_ASM64 ENDP

VIRTUALIZER_FISH_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 511
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_FISH_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_PUMA_WHITE definition
; ****************************************************************************

VIRTUALIZER_PUMA_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 113
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_PUMA_WHITE_START_ASM64 ENDP

VIRTUALIZER_PUMA_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 513
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_PUMA_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_PUMA_RED definition
; ****************************************************************************

VIRTUALIZER_PUMA_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 115
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_PUMA_RED_START_ASM64 ENDP

VIRTUALIZER_PUMA_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 515
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_PUMA_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_PUMA_BLACK definition
; ****************************************************************************

VIRTUALIZER_PUMA_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 117
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_PUMA_BLACK_START_ASM64 ENDP

VIRTUALIZER_PUMA_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 517
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_PUMA_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_SHARK_WHITE definition
; ****************************************************************************

VIRTUALIZER_SHARK_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 119
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_SHARK_WHITE_START_ASM64 ENDP

VIRTUALIZER_SHARK_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 519
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_SHARK_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_SHARK_RED definition
; ****************************************************************************

VIRTUALIZER_SHARK_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 121
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_SHARK_RED_START_ASM64 ENDP

VIRTUALIZER_SHARK_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 521
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_SHARK_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_SHARK_BLACK definition
; ****************************************************************************

VIRTUALIZER_SHARK_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 123
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_SHARK_BLACK_START_ASM64 ENDP

VIRTUALIZER_SHARK_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 523
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_SHARK_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_DOLPHIN_WHITE definition
; ****************************************************************************

VIRTUALIZER_DOLPHIN_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 135
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_DOLPHIN_WHITE_START_ASM64 ENDP

VIRTUALIZER_DOLPHIN_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 535
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_DOLPHIN_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_DOLPHIN_RED definition
; ****************************************************************************

VIRTUALIZER_DOLPHIN_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 137
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_DOLPHIN_RED_START_ASM64 ENDP

VIRTUALIZER_DOLPHIN_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 537
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_DOLPHIN_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_DOLPHIN_BLACK definition
; ****************************************************************************

VIRTUALIZER_DOLPHIN_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 139
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_DOLPHIN_BLACK_START_ASM64 ENDP

VIRTUALIZER_DOLPHIN_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 539
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_DOLPHIN_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_EAGLE_WHITE definition
; ****************************************************************************

VIRTUALIZER_EAGLE_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 147
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_EAGLE_WHITE_START_ASM64 ENDP

VIRTUALIZER_EAGLE_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 547
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_EAGLE_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_EAGLE_RED definition
; ****************************************************************************

VIRTUALIZER_EAGLE_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 149
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_EAGLE_RED_START_ASM64 ENDP

VIRTUALIZER_EAGLE_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 549
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_EAGLE_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_EAGLE_BLACK definition
; ****************************************************************************

VIRTUALIZER_EAGLE_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 151
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_EAGLE_BLACK_START_ASM64 ENDP

VIRTUALIZER_EAGLE_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 551
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_EAGLE_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_LION_WHITE definition
; ****************************************************************************

VIRTUALIZER_LION_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 161
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_LION_WHITE_START_ASM64 ENDP

VIRTUALIZER_LION_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 561
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_LION_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_LION_RED definition
; ****************************************************************************

VIRTUALIZER_LION_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 163
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_LION_RED_START_ASM64 ENDP

VIRTUALIZER_LION_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 563
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_LION_RED_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_LION_BLACK definition
; ****************************************************************************

VIRTUALIZER_LION_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 165
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_LION_BLACK_START_ASM64 ENDP

VIRTUALIZER_LION_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 565
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_LION_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VIRTUALIZER_MUTATE_ONLY definition
; ****************************************************************************

VIRTUALIZER_MUTATE_ONLY_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 16
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_MUTATE_ONLY_START_ASM64 ENDP

VIRTUALIZER_MUTATE_ONLY_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'CV'
    mov     ebx, 17
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VIRTUALIZER_MUTATE_ONLY_END_ASM64 ENDP

ELSE

; ****************************************************************************
; VIRTUALIZER_TIGER_WHITE definition
; ****************************************************************************

VIRTUALIZER_TIGER_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 100
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_TIGER_WHITE_START_ASM32 ENDP

VIRTUALIZER_TIGER_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 500
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_TIGER_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_TIGER_RED definition
; ****************************************************************************

VIRTUALIZER_TIGER_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 101
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_TIGER_RED_START_ASM32 ENDP

VIRTUALIZER_TIGER_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 501
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_TIGER_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_TIGER_BLACK definition
; ****************************************************************************

VIRTUALIZER_TIGER_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 102
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_TIGER_BLACK_START_ASM32 ENDP

VIRTUALIZER_TIGER_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 502
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_TIGER_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_FISH_WHITE definition
; ****************************************************************************

VIRTUALIZER_FISH_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 106
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_FISH_WHITE_START_ASM32 ENDP

VIRTUALIZER_FISH_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 506
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_FISH_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_FISH_RED definition
; ****************************************************************************

VIRTUALIZER_FISH_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 108
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_FISH_RED_START_ASM32 ENDP

VIRTUALIZER_FISH_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 508
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_FISH_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_FISH_BLACK definition
; ****************************************************************************

VIRTUALIZER_FISH_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 110
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_FISH_BLACK_START_ASM32 ENDP

VIRTUALIZER_FISH_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 510
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_FISH_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_PUMA_WHITE definition
; ****************************************************************************

VIRTUALIZER_PUMA_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 112
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_PUMA_WHITE_START_ASM32 ENDP

VIRTUALIZER_PUMA_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 512
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_PUMA_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_PUMA_RED definition
; ****************************************************************************

VIRTUALIZER_PUMA_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 114
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_PUMA_RED_START_ASM32 ENDP

VIRTUALIZER_PUMA_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 514
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_PUMA_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_PUMA_BLACK definition
; ****************************************************************************

VIRTUALIZER_PUMA_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 116
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_PUMA_BLACK_START_ASM32 ENDP

VIRTUALIZER_PUMA_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 516
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_PUMA_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_SHARK_WHITE definition
; ****************************************************************************

VIRTUALIZER_SHARK_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 118
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_SHARK_WHITE_START_ASM32 ENDP

VIRTUALIZER_SHARK_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 518
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_SHARK_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_SHARK_RED definition
; ****************************************************************************

VIRTUALIZER_SHARK_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 120
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_SHARK_RED_START_ASM32 ENDP

VIRTUALIZER_SHARK_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 520
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_SHARK_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_SHARK_BLACK definition
; ****************************************************************************

VIRTUALIZER_SHARK_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 122
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_SHARK_BLACK_START_ASM32 ENDP

VIRTUALIZER_SHARK_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 522
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_SHARK_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_DOLPHIN_WHITE definition
; ****************************************************************************

VIRTUALIZER_DOLPHIN_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 134
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_DOLPHIN_WHITE_START_ASM32 ENDP

VIRTUALIZER_DOLPHIN_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 534
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_DOLPHIN_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_DOLPHIN_RED definition
; ****************************************************************************

VIRTUALIZER_DOLPHIN_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 136
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_DOLPHIN_RED_START_ASM32 ENDP

VIRTUALIZER_DOLPHIN_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 536
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_DOLPHIN_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_DOLPHIN_BLACK definition
; ****************************************************************************

VIRTUALIZER_DOLPHIN_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 138
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_DOLPHIN_BLACK_START_ASM32 ENDP

VIRTUALIZER_DOLPHIN_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 538
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_DOLPHIN_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_EAGLE_WHITE definition
; ****************************************************************************

VIRTUALIZER_EAGLE_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 146
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_EAGLE_WHITE_START_ASM32 ENDP

VIRTUALIZER_EAGLE_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 546
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_EAGLE_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_EAGLE_RED definition
; ****************************************************************************

VIRTUALIZER_EAGLE_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 148
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_EAGLE_RED_START_ASM32 ENDP

VIRTUALIZER_EAGLE_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 548
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_EAGLE_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_EAGLE_BLACK definition
; ****************************************************************************

VIRTUALIZER_EAGLE_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 150
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_EAGLE_BLACK_START_ASM32 ENDP

VIRTUALIZER_EAGLE_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 550
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_EAGLE_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_LION_WHITE definition
; ****************************************************************************

VIRTUALIZER_LION_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 160
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_LION_WHITE_START_ASM32 ENDP

VIRTUALIZER_LION_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 560
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_LION_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_LION_RED definition
; ****************************************************************************

VIRTUALIZER_LION_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 162
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_LION_RED_START_ASM32 ENDP

VIRTUALIZER_LION_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 562
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_LION_RED_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_LION_BLACK definition
; ****************************************************************************

VIRTUALIZER_LION_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 164
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_LION_BLACK_START_ASM32 ENDP

VIRTUALIZER_LION_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 564
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_LION_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VIRTUALIZER_MUTATE_ONLY definition
; ****************************************************************************

VIRTUALIZER_MUTATE_ONLY_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 16
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_MUTATE_ONLY_START_ASM32 ENDP

VIRTUALIZER_MUTATE_ONLY_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'CV'
    mov     ebx, 17
    mov     ecx, 'CV'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VIRTUALIZER_MUTATE_ONLY_END_ASM32 ENDP

ENDIF

END
