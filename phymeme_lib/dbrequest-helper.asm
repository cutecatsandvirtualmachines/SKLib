
.code _text

;DWORD64 DbRequest(DWORD64 code, PDB_INFO pDbInfo)
DbRequest proc
	int 3
	ret
DbRequest endp

END