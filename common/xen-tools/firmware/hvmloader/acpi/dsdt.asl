/******************************************************************************
 * DSDT for Xen with Qemu device model
 *
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

DefinitionBlock ("DSDT.aml", "DSDT", 2, "Xen", "HVM", 0)
{
    Name (\PMBS, 0x0C00)
    Name (\PMLN, 0x08)
    Name (\IOB1, 0x00)
    Name (\IOL1, 0x00)
    Name (\APCB, 0xFEC00000)
    Name (\APCL, 0x00010000)
    Name (\PUID, 0x00)

    /* _S3 and _S4 are in separate SSDTs */
    Name (\_S5, Package (0x04)
    {
        0x00,  /* PM1a_CNT.SLP_TYP */
        0x00,  /* PM1b_CNT.SLP_TYP */
        0x00,  /* reserved */
        0x00   /* reserved */
    })

    Name(PICD, 0)
    Method(_PIC, 1)
    {
        Store(Arg0, PICD) 
    }

    Scope (\_SB)
    {
       /* ACPI_INFO_PHYSICAL_ADDRESS == 0xFC000000 */
       OperationRegion(BIOS, SystemMemory, 0xFC000000, 24)
       Field(BIOS, ByteAcc, NoLock, Preserve) {
           UAR1, 1,
           UAR2, 1,
           LTP1, 1,
           HPET, 1,
           SMC, 1,
           Offset(4),
           PMIN, 32,
           PLEN, 32,
           MSUA, 32, /* MADT checksum address */
           MAPA, 32  /* MADT LAPIC0 address */
       }

        /* Fix HCT test for 0x400 pci memory:
         * - need to report low 640 MB mem as motherboard resource
         */
       Device(MEM0)
       {
           Name(_HID, EISAID("PNP0C02"))
           Name(_CRS, ResourceTemplate() {
               QWordMemory(
                    ResourceConsumer, PosDecode, MinFixed,
                    MaxFixed, Cacheable, ReadWrite,
                    0x00000000,
                    0x00000000,
                    0x0009ffff,
                    0x00000000,
                    0x000a0000)
           })
       }

       Device (PCI0)
       {
           Name (_HID, EisaId ("PNP0A03"))
           Name (_UID, 0x00)
           Name (_ADR, 0x00)
           Name (_BBN, 0x00)

           /* Make cirrues VGA S3 suspend/resume work in Windows XP/2003 */
           Device (VGA)
           {
               Name (_ADR, 0x00020000)

               Method (_S1D, 0, NotSerialized)
               {
                   Return (0x00)
               }
               Method (_S2D, 0, NotSerialized)
               {
                   Return (0x00)
               }
               Method (_S3D, 0, NotSerialized)
               {
                   Return (0x00)
               }
           }

           Method (_CRS, 0, NotSerialized)
           {
               Name (PRT0, ResourceTemplate ()
               {
                   /* bus number is from 0 - 255*/
                   WordBusNumber(
                        ResourceProducer, MinFixed, MaxFixed, SubDecode,
                        0x0000,
                        0x0000,
                        0x00FF,
                        0x0000,
                        0x0100)
                    IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08)
                    WordIO(
                        ResourceProducer, MinFixed, MaxFixed, PosDecode,
                        EntireRange,
                        0x0000,
                        0x0000,
                        0x0CF7,
                        0x0000,
                        0x0CF8)
                    WordIO(
                        ResourceProducer, MinFixed, MaxFixed, PosDecode,
                        EntireRange,
                        0x0000,
                        0x0D00,
                        0xFFFF,
                        0x0000,
                        0xF300)

                    /* reserve memory for pci devices */
                    DWordMemory(
                        ResourceProducer, PosDecode, MinFixed, MaxFixed,
                        Cacheable, ReadWrite,
                        0x00000000,
                        0x000A0000,
                        0x000BFFFF,
                        0x00000000,
                        0x00020000)

                    DWordMemory(
                        ResourceProducer, PosDecode, MinFixed, MaxFixed,
                        Cacheable, ReadWrite,
                        0x00000000,
                        0xF0000000,
                        0xF4FFFFFF,
                        0x00000000,
                        0x05000000,
                        ,, _Y01)
                })

                CreateDWordField(PRT0, \_SB.PCI0._CRS._Y01._MIN, MMIN)
                CreateDWordField(PRT0, \_SB.PCI0._CRS._Y01._MAX, MMAX)
                CreateDWordField(PRT0, \_SB.PCI0._CRS._Y01._LEN, MLEN)

                Store(\_SB.PMIN, MMIN)
                Store(\_SB.PLEN, MLEN)
                Add(MMIN, MLEN, MMAX)
                Subtract(MMAX, One, MMAX)

                Return (PRT0)
            }

            Device(HPET) {
                Name(_HID,  EISAID("PNP0103"))
                Name(_UID, 0)
                Method (_STA, 0, NotSerialized) {
                    If(LEqual(\_SB.HPET, 0)) {
                        Return(0x00)
                    } Else {
                        Return(0x0F)
                    }
                }
                Name(_CRS, ResourceTemplate() {
                    DWordMemory(
                        ResourceConsumer, PosDecode, MinFixed, MaxFixed,
                        NonCacheable, ReadWrite,
                        0x00000000,
                        0xFED00000,
                        0xFED003FF,
                        0x00000000,
                        0x00000400 /* 1K memory: FED00000 - FED003FF */
                    )
                })
            }
	
	    Device(VFV) { 
                Name(_HID, EISAID("UXV0100"))
                Name(_CID, "uxenv4v")

		/* Status method bits 0 - present, 1 - enabled and decoding, 2 - show in device manager, 3 - passed self test */
                Method (_STA, 0, NotSerialized) {
                        return(0x0F)
                }

                Name(_CRS, ResourceTemplate() {
                    /* IO (Decode16, 0x0330, 0x0330, 0x01, 0x08) */
                    IRQNoFlags () {7}
                })
	    }



            OperationRegion(UXSO, SystemIO, 0x330, 0x10)
            Field(UXSO,ByteAcc,NoLock,Preserve) {
                USP0,1,
                USP1,1,
                USP2,1,
                USP3,1,
                USP4,1,
                USP5,1,
                USP6,1,
                USP7,1
            }
            
	    Device(UXSE) {  /*Uxen stor enumerator */
                Name(_HID, EISAID("UXS0FFF"))
                Name(_CID, "uxsenum")


                Method (_STA, 0, NotSerialized) {
			return(0xB) /* Hide in device manager*/
		}
		
                Name(_CRS, ResourceTemplate() {
                    IO (Decode16, 0x0330, 0x0330, 0x01, 0x10)
		})

            }

	    Device(UXS0) {  
                Name(_HID, EISAID("UXS0000"))
                Name(_CID, "uxs0000")
	        Method (_STA, 0, NotSerialized) {
                    If(LEqual(USP0, 0)) {
                        return(0x0F)
                    } Else {
                        Return(0x00)
                    }
                }
            }

	    Device(UXS1) { 
                Name(_HID, EISAID("UXS0001"))
                Name(_CID, "uxs0001")
	        Method (_STA, 0, NotSerialized) {
                    If(LEqual(USP1, 0)) {
                        return(0x0F)
                    } Else {
                        Return(0x00)
                    }
                }
            }


	    Device(UXS2) {
                Name(_HID, EISAID("UXS0002"))
                Name(_CID, "uxs0002")
	        Method (_STA, 0, NotSerialized) {
                    If(LEqual(USP2, 0)) {
                        return(0x0F)
                    } Else {
                        Return(0x00)
                    }
                }
            }

	    Device(UXS3) {
                Name(_HID, EISAID("UXS0003"))
                Name(_CID, "uxs0003")
	        Method (_STA, 0, NotSerialized) {
                    If(LEqual(USP3, 0)) {
                        return(0x0F)
                    } Else {
                        Return(0x00)
                    }
                }
            }


	    Device(UXN) { 
                Name(_HID, EISAID("UXN0100"))
                Name(_CID, "uxennet")

       		OperationRegion(UXNO, SystemIO, 0x320, 0x10)
		Field(UXNO,ByteAcc,NoLock,Preserve) {
			UXNS,8,
			UXN0,8,
			UXN1,8,
			UXN2,8,
			UXN3,8,
			UXN4,8,
			UXN5,8,
			UXND,8,
			UXNM,16,
		}

		/* Status method bits 0 - present, 1 - enabled and decoding, 2 - show in device manager, 3 - passed self test */
                Method (_STA, 0, NotSerialized) {
                    If(LEqual(UXNS, 0x81)) {
                        return(0x0F)
                    } Else {
                        return(0x0D)
                    }
                }

                Method (_DIS, 0, NotSerialized) {
                    Store(UXNS, Local0)
                    And(Local0, 0xFE, UXNS)
                }

                Method (_SRS, 1, NotSerialized) {
                    Store(UXNS, Local0)
                    Or(Local0, 0x01, UXNS)
                }

                Name(_CRS, ResourceTemplate() {
                    IO (Decode16, 0x0320, 0x0320, 0x01, 0x10)
                })

		Method(VMAC,0) {
			Name(NBUF,Buffer() { 0x00,0x00,0x00,0x00,0x00,0x00 })

			CreateByteField(NBUF,0x00,NB0)
			CreateByteField(NBUF,0x01,NB1)
			CreateByteField(NBUF,0x02,NB2)
			CreateByteField(NBUF,0x03,NB3)
			CreateByteField(NBUF,0x04,NB4)
			CreateByteField(NBUF,0x05,NB5)

			Store(UXN0,NB0)
			Store(UXN1,NB1)
			Store(UXN2,NB2)
			Store(UXN3,NB3)
			Store(UXN4,NB4)
			Store(UXN5,NB5)

			Return(NBUF)
		}

		Method(VMTU,0) {
			Return (UXNM)
		}
	    }

            Device(UXH) {
                Name(_HID, EISAID("UXH0000"))
                Name(_CID, "uxenhid")

                /* Status method bits 0 - present, 1 - enabled and decoding, 2 - show in device manager, 3 - passed self test */
                Method (_STA, 0, NotSerialized) {
                    return(0x0F)
                }
            }

            Device(SMC) {
                Name(_HID, EISAID("APP0001"))
                Name(_CID, "smc-napa")
                Method (_STA, 0, NotSerialized) {
                    If(LEqual(\_SB.SMC, 0)) {
                        Return(0x00)
                    } Else {
                        return(0x0B)
                    }
                }
                Name(_CRS, ResourceTemplate() {
                    IO (Decode16, 0x0300, 0x0300, 0x01, 0x20)
                    IRQNoFlags () {6}
                })
            }

            Device (ISA)
            {
                Name (_ADR, 0x00010000) /* device 1, fn 0 */

                OperationRegion(PIRQ, PCI_Config, 0x60, 0x4)
                Scope(\) {
                    Field (\_SB.PCI0.ISA.PIRQ, ByteAcc, NoLock, Preserve) {
                        PIRA, 8,
                        PIRB, 8,
                        PIRC, 8,
                        PIRD, 8
                    }
                }
                Device (SYSR)
                {
                    Name (_HID, EisaId ("PNP0C02"))
                    Name (_UID, 0x01)
                    Name (CRS, ResourceTemplate ()
                    {
                        /* TODO: list hidden resources */
                        IO (Decode16, 0x0010, 0x0010, 0x00, 0x10)
                        IO (Decode16, 0x0022, 0x0022, 0x00, 0x0C)
                        IO (Decode16, 0x0030, 0x0030, 0x00, 0x10)
                        IO (Decode16, 0x0044, 0x0044, 0x00, 0x1C)
                        IO (Decode16, 0x0062, 0x0062, 0x00, 0x02)
                        IO (Decode16, 0x0065, 0x0065, 0x00, 0x0B)
                        IO (Decode16, 0x0072, 0x0072, 0x00, 0x0E)
                        IO (Decode16, 0x0080, 0x0080, 0x00, 0x01)
                        IO (Decode16, 0x0084, 0x0084, 0x00, 0x03)
                        IO (Decode16, 0x0088, 0x0088, 0x00, 0x01)
                        IO (Decode16, 0x008C, 0x008C, 0x00, 0x03)
                        IO (Decode16, 0x0090, 0x0090, 0x00, 0x10)
                        IO (Decode16, 0x00A2, 0x00A2, 0x00, 0x1C)
                        IO (Decode16, 0x00E0, 0x00E0, 0x00, 0x10)
                        IO (Decode16, 0x08A0, 0x08A0, 0x00, 0x04)
                        IO (Decode16, 0x0CC0, 0x0CC0, 0x00, 0x10)
                        IO (Decode16, 0x04D0, 0x04D0, 0x00, 0x02)
                    })
                    Method (_CRS, 0, NotSerialized)
                    {
                        Return (CRS)
                    }
                }

                Device (PIC)
                {
                    Name (_HID, EisaId ("PNP0000"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0020, 0x0020, 0x01, 0x02)
                        IO (Decode16, 0x00A0, 0x00A0, 0x01, 0x02)
                        IRQNoFlags () {2}
                    })
                }

                /* Device (DMA0) */
                /* { */
                /*     Name (_HID, EisaId ("PNP0200")) */
                /*     Name (_CRS, ResourceTemplate () */
                /*     { */
                /*         DMA (Compatibility, BusMaster, Transfer8) {4} */
                /*         IO (Decode16, 0x0000, 0x0000, 0x00, 0x10) */
                /*         IO (Decode16, 0x0081, 0x0081, 0x00, 0x03) */
                /*         IO (Decode16, 0x0087, 0x0087, 0x00, 0x01) */
                /*         IO (Decode16, 0x0089, 0x0089, 0x00, 0x03) */
                /*         IO (Decode16, 0x008F, 0x008F, 0x00, 0x01) */
                /*         IO (Decode16, 0x00C0, 0x00C0, 0x00, 0x20) */
                /*         IO (Decode16, 0x0480, 0x0480, 0x00, 0x10) */
                /*     }) */
                /* } */

                Device (TMR)
                {
                    Name (_HID, EisaId ("PNP0100"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0040, 0x0040, 0x00, 0x04)
                        IRQNoFlags () {0}
                    })
                }

                Device (RTC)
                {
                    Name (_HID, EisaId ("PNP0B00"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0070, 0x0070, 0x00, 0x02)
                        IRQNoFlags () {8}
                    })
                }

                Device (SPKR)
                {
                    Name (_HID, EisaId ("PNP0800"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0061, 0x0061, 0x00, 0x01)
                    })
                }

                Device (PS2M)
                {
                    Name (_HID, EisaId ("PNP0F13"))
                    Name (_CID, 0x130FD041)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IRQNoFlags () {12}
                    })
                }

                Device (PS2K)
                {
                    Name (_HID, EisaId ("PNP0303"))
                    Name (_CID, 0x0B03D041)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0060, 0x0060, 0x00, 0x01)
                        IO (Decode16, 0x0064, 0x0064, 0x00, 0x01)
                        IRQNoFlags () {1}
                    })
                }

                /* Device (FDC0) */
                /* { */
                /*     Name (_HID, EisaId ("PNP0700")) */
                /*     Method (_STA, 0, NotSerialized) */
                /*     { */
                /*           Return (0x0F) */
                /*     } */

                /*     Name (_CRS, ResourceTemplate () */
                /*     { */
                /*         IO (Decode16, 0x03F0, 0x03F0, 0x01, 0x06) */
                /*         IO (Decode16, 0x03F7, 0x03F7, 0x01, 0x01) */
                /*         IRQNoFlags () {6} */
                /*         DMA (Compatibility, NotBusMaster, Transfer8) {2} */
                /*     }) */
                /* } */

                Device (UAR1)
                {
                    Name (_HID, EisaId ("PNP0501"))
                    Name (_UID, 0x01)
                    Method (_STA, 0, NotSerialized)
                    {
                        If(LEqual(\_SB.UAR1, 0)) {
                            Return(0x00)
                        } Else {
                            Return(0x0F)
                        }
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x03F8, 0x03F8, 8, 8)
                        IRQNoFlags () {4}
                    })
                }

                Device (UAR2)
                {
                    Name (_HID, EisaId ("PNP0501"))
                    Name (_UID, 0x02)
                    Method (_STA, 0, NotSerialized)
                    {
                        If(LEqual(\_SB.UAR2, 0)) {
                            Return(0x00)
                        } Else {
                            Return(0x0F)
                        }
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x02F8, 0x02F8, 8, 8)
                        IRQNoFlags () {3}
                    })
                }

                Device (LTP1)
                {
                    Name (_HID, EisaId ("PNP0400"))
                    Name (_UID, 0x02)
                    Method (_STA, 0, NotSerialized)
                    {
                        If(LEqual(\_SB.LTP1, 0)) {
                            Return(0x00)
                        } Else {
                            Return(0x0F)
                        }
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x0378, 0x0378, 0x08, 0x08)
                        IRQNoFlags () {7}
                    })
                } 
            }
        }
    }
}
