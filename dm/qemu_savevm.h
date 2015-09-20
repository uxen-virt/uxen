
#ifndef _QEMU_SAVEVM_H_
#define _QEMU_SAVEVM_H_

#include "file.h"

int qemu_loadvm_state(QEMUFile *f);
int qemu_savevm_state(Monitor *mon, QEMUFile *f);

QEMUFile *qemu_fopen(const char *filename, const char *mode);
int qemu_fclose(QEMUFile *f);
void qemu_fflush(QEMUFile *f);
void qemu_put_buffer(QEMUFile *f, const uint8_t *buf, int size);
int qemu_file_get_error(QEMUFile *f);
int qemu_get_buffer(QEMUFile *f, uint8_t *buf, int size1);
int64_t qemu_fseek(QEMUFile *f, int64_t pos, int whence);
int64_t qemu_ftell(QEMUFile *f);

QEMUFile *qemu_memopen(uint8_t *buffer, int bufsize, const char *mode);
uint8_t *qemu_meminfo(QEMUFile *f, int *used);

void qemu_savevm_resume(void);

#endif  /* _QEMU_SAVEVM_H_ */
