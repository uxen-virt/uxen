	;;
	;; Copyright 2015-2016, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

    .686p
    .model flat, stdcall
    .code
    public bus_config_read8

bus_config_read8        proc NEAR
    push        ebp
    mov         ebp, esp
    mov         esi, [ebp+8]
    xor         eax, eax
    mov         al, BYTE PTR [esi]
    pop         ebp
    ret
bus_config_read8        endp

bus_config_read_buffer  proc NEAR
    push        ebp
    mov         ebp, esp
    mov         esi, [ebp+8]
    mov         edi, [ebp+12]
    mov         edx, [ebp+16]
    xor         eax, eax
    test        edx, edx
    jz          L2
    add         edx, esi
L1:
    mov         al, BYTE PTR [esi]
    inc         esi
    mov         BYTE PTR [edi], al
    inc         edi
    cmp         edx, esi
    ja          L1
    mov         eax, [ebp+16]
L2:
    pop         ebp
    ret
bus_config_read_buffer  endp

    end
