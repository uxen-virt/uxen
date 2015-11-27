	;;
	;; Copyright 2015-2016, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

    .code
    public bus_config_read8
    public bus_config_read_buffer

bus_config_read8        proc
    xor         rax, rax
    mov         al, BYTE PTR [rcx]
    ret
bus_config_read8        endp
    
bus_config_read_buffer  proc
    xor         rax, rax
    test        r8, r8
    jz          L2 
    push        rsi
    mov         rsi, rcx
    add         rsi, r8
L1:
    mov         al, BYTE PTR [rcx]
    inc         rcx
    mov         BYTE PTR [rdx], al
    inc         rdx
    cmp         rsi, rcx
    ja          L1
    pop         rsi
    mov         rax, r8
L2:
    ret
bus_config_read_buffer  endp

    end
