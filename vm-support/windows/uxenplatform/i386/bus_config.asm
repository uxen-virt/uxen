	;;
	;; Copyright 2015-2016, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

    .686p
    .model flat, stdcall
    .code
    public bus_config_read8
    public bus_config_read_buffer

bus_config_read8        proc NEAR STDCALL, addr1:DWORD
    mov         edx, addr1
    xor         eax, eax
    mov         al, BYTE PTR [edx]
    ret
bus_config_read8        endp

bus_config_read_buffer  proc NEAR STDCALL USES edi esi,
                        src:DWORD, dst:DWORD, len:DWORD
    mov         esi, src
    mov         edi, dst
    mov         edx, len
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
    mov         eax, len
L2:
    ret
bus_config_read_buffer  endp

    end
