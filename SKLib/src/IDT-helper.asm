
.code _text

EXTERN seh_handler : proc
EXTERN seh_handler_ecode : proc

; #DE has no error code...
generic_interrupt_handler PROC
__de_handler proc
	iretq
__de_handler endp
generic_interrupt_handler ENDP

; PF and GP have error code...
generic_interrupt_handler_ecode PROC
__pf_handler proc
__gp_handler proc
	add rsp, 8	; remove error code on the stack...

	iretq
__gp_handler endp
__pf_handler endp
generic_interrupt_handler_ecode ENDP

__db_handler proc
	push rax
	pushfq
	pop rax

	btr rax, 8
	
	push rax
	popfq
	pop rax
	iretq
__db_handler endp

END