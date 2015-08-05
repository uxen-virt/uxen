/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _FILE_H_
#define _FILE_H_

typedef int (QEMUFilePutBufferFunc)(void *opaque, const uint8_t *buf,
                                    int64_t pos, int size);
typedef int (QEMUFileGetBufferFunc)(void *opaque, uint8_t *buf,
                                    int64_t pos, int size);
typedef int (QEMUFileCloseFunc)(void *opaque);

int qemu_get_byte(QEMUFile *f);
void qemu_put_byte(QEMUFile *f, int v);
#define qemu_get_sbyte qemu_get_byte
#define qemu_put_sbyte qemu_put_byte
#define qemu_get_s8s(f, pv) ({ *(int8_t *)(pv) = qemu_get_byte(f); })
#define qemu_put_s8s(f, pv) ({ qemu_put_byte((f), *(int8_t *)(pv)); })
#define qemu_get_8s(f, pv) ({ *(uint8_t *)(pv) = qemu_get_byte(f); })
#define qemu_put_8s(f, pv) ({ qemu_put_byte((f), *(uint8_t *)(pv)); })

unsigned int qemu_get_be16(QEMUFile *f);
void qemu_put_be16(QEMUFile *f, unsigned int v);
#define qemu_get_sbe16(f) (int)qemu_get_be16(f)
#define qemu_put_sbe16(f, v) qemu_put_be16((f), (unsigned int)(v))
#define qemu_get_sbe16s(f, pv) ({ *(int16_t *)(pv) = qemu_get_be16(f); })
#define qemu_put_sbe16s(f, pv) ({ qemu_put_be16((f), *(int16_t *)(pv)); })
#define qemu_get_be16s(f, pv) ({ *(uint16_t *)(pv) = qemu_get_be16(f); })
#define qemu_put_be16s(f, pv) ({ qemu_put_be16((f), *(uint16_t *)(pv)); })

unsigned int qemu_get_be32(QEMUFile *f);
void qemu_put_be32(QEMUFile *f, unsigned int v);
#define qemu_get_sbe32(f) (int)qemu_get_be32(f)
#define qemu_put_sbe32(f, v) qemu_put_be32((f), (unsigned int)(v))
#define qemu_get_sbe32s(f, pv) ({ *(int32_t *)(pv) = qemu_get_be32(f); })
#define qemu_put_sbe32s(f, pv) ({ qemu_put_be32((f), *(int32_t *)(pv)); })
#define qemu_get_be32s(f, pv) ({ *(uint32_t *)(pv) = qemu_get_be32(f); })
#define qemu_put_be32s(f, pv) ({ qemu_put_be32((f), *(uint32_t *)(pv)); })

uint64_t qemu_get_be64(QEMUFile *f);
void qemu_put_be64(QEMUFile *f, uint64_t v);
#define qemu_get_sbe64s(f, pv) ({ *(int64_t *)(pv) = qemu_get_be64(f); })
#define qemu_put_sbe64s(f, pv) ({ qemu_put_be64((f), *(int64_t *)(pv)); })
#define qemu_get_be64s(f, pv) ({ *(uint64_t *)(pv) = qemu_get_be64(f); })
#define qemu_put_be64s(f, pv) ({ qemu_put_be64((f), *(uint64_t *)(pv)); })

int qemu_get_buffer(QEMUFile *f, uint8_t *buf, int size);
void qemu_put_buffer(QEMUFile *f, const uint8_t *buf, int size);

void qemu_file_skip(QEMUFile *f, int size);
void qemu_file_error(QEMUFile *f);

#endif	/* _FILE_H_ */
