/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "abstractfile.h"
#include "common.h"

#define MALLOC_CHK_FAIL(_p, _size, _fail_label) \
do { \
  if (NULL == ((_p) = malloc(_size))) { \
    fprintf(stderr, "%s alloc %llu failed.\n", __FUNCTION__, (unsigned long long)(_size)); \
    goto _fail_label; \
  } \
} while(0)

#define MALLOC_CHK_ABORT(_p, _size) \
do { \
  if (NULL == ((_p) = malloc(_size))) { \
    fprintf(stderr, "%s alloc %llu failed; aborting\n", __FUNCTION__, (unsigned long long)(_size)); \
    abort(); \
  } \
} while(0)

#define REALLOC_CHK_ABORT(_p, _size) \
do { \
  void *_bigger_buffer = realloc((_p), (_size)); \
  if (NULL == _bigger_buffer) { \
    fprintf(stderr, "%s realloc %llu failed; aborting\n", __FUNCTION__, (unsigned long long)(_size)); \
    free(_p); /* in case the next line is ever something else */\
    abort(); \
  } \
  (_p) = _bigger_buffer; \
} while(0)

// Round up to closest upper power of 2 (if v==0, r=0).
// Fails if v > 4G.
// On success returns 0. On failure returns some non-zero error code.
static int roundup2(size_t v, size_t *r) {
    if (v > (1ULL<<32)) {
        return ERANGE;
    }
    if (v==0) {
        *r = 0;
        return 0;
    }

    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    *r = v;
    return 0;
}

static size_t freadWrapper(AbstractFile* file, void* data, size_t len) {
  return fread(data, 1, len, (FILE*) (file->data));
}

static size_t fwriteWrapper(AbstractFile* file, const void* data, size_t len) {
  return fwrite(data, 1, len, (FILE*) (file->data));
}

static int fseekWrapper(AbstractFile* file, off_t offset) {
  return fseeko((FILE*) (file->data), offset, SEEK_SET);
}

static off_t ftellWrapper(AbstractFile* file) {
  return ftello((FILE*) (file->data));
}

static void fcloseWrapper(AbstractFile* file) {
  fclose((FILE*) (file->data));
  free(file);
}

static off_t fileGetLength(AbstractFile* file) {
	off_t length;
	off_t pos;

	pos = ftello((FILE*) (file->data));

	fseeko((FILE*) (file->data), 0, SEEK_END);
	length = ftello((FILE*) (file->data));

	fseeko((FILE*) (file->data), pos, SEEK_SET);

	return length;
}

AbstractFile* createAbstractFileFromFile(FILE* file) {
	AbstractFile* toReturn;

	if(file == NULL) {
		return NULL;
	}

	MALLOC_CHK_ABORT(toReturn, sizeof(AbstractFile));
	toReturn->data = file;
	toReturn->read = freadWrapper;
	toReturn->write = fwriteWrapper;
	toReturn->seek = fseekWrapper;
	toReturn->tell = ftellWrapper;
	toReturn->getLength = fileGetLength;
	toReturn->close = fcloseWrapper;
	toReturn->type = AbstractFileTypeFile;
	return toReturn;
}

static size_t dummyRead(AbstractFile* file, void* data, size_t len) {
  return 0;
}

static size_t dummyWrite(AbstractFile* file, const void* data, size_t len) {
  *((off_t*) (file->data)) += len;
  return len;
}

static int dummySeek(AbstractFile* file, off_t offset) {
  *((off_t*) (file->data)) = offset;
  return 0;
}

static off_t dummyTell(AbstractFile* file) {
  return *((off_t*) (file->data));
}

static void dummyClose(AbstractFile* file) {
  free(file);
}

AbstractFile* createAbstractFileFromDummy(void) {
	AbstractFile* toReturn;
	MALLOC_CHK_ABORT(toReturn, sizeof(AbstractFile));
	toReturn->data = NULL;
	toReturn->read = dummyRead;
	toReturn->write = dummyWrite;
	toReturn->seek = dummySeek;
	toReturn->tell = dummyTell;
	toReturn->getLength = NULL;
	toReturn->close = dummyClose;
	toReturn->type = AbstractFileTypeDummy;
	return toReturn;
}

static size_t memRead(AbstractFile* file, void* data, size_t len) {
  MemWrapperInfo* info = (MemWrapperInfo*) (file->data); 
  size_t req_buf_size = info->offset + len;
  if (req_buf_size < len) {
    fprintf(stderr, "memRead req_buf_size overflow\n");
    abort();
  }
  if(info->bufferSize < req_buf_size) {
    len = info->bufferSize - info->offset;
  }
  memcpy(data, (void*)((uint8_t*)(*(info->buffer)) + (uint32_t)info->offset), len);
  info->offset += (size_t)len;
  return len;
}

static size_t memWrite(AbstractFile* file, const void* data, size_t len) {
  MemWrapperInfo* info = (MemWrapperInfo*) (file->data);
  size_t req_buf_size = info->offset + len;
  if (req_buf_size < len) {
      fprintf(stderr, "memWrite req_buf_size overflow\n");
      abort();
  }

  size_t req_up;
  if (roundup2(req_buf_size, &req_up)) {
    fprintf(stderr, "memWrite failed to roundup %zu\n", req_buf_size);
    abort();
  }
  info->bufferSize = (req_up > info->bufferSize) ? req_up : info->bufferSize;
  REALLOC_CHK_ABORT(*(info->buffer), info->bufferSize);

  memcpy((void*)((uint8_t*)(*(info->buffer)) + (uint32_t)info->offset), data, len);
  info->offset += (size_t)len;
  return len;
}

static int memSeek(AbstractFile* file, off_t offset) {
  MemWrapperInfo* info = (MemWrapperInfo*) (file->data);
  info->offset = (size_t)offset;
  return 0;
}

static off_t memTell(AbstractFile* file) {
  MemWrapperInfo* info = (MemWrapperInfo*) (file->data);
  return (off_t)info->offset;
}

static off_t memGetLength(AbstractFile* file) {
  MemWrapperInfo* info = (MemWrapperInfo*) (file->data);
  return info->bufferSize;
}

static void memClose(AbstractFile* file) {
  free(file->data);
  free(file);
}

AbstractFile* createAbstractFileFromMemory(void** buffer, size_t size) {
	MemWrapperInfo* info;
	AbstractFile* toReturn;
	MALLOC_CHK_FAIL(toReturn, sizeof(AbstractFile), err0);

	MALLOC_CHK_FAIL(info, sizeof(MemWrapperInfo), err1);
	info->offset = 0;
	info->buffer = buffer;
	info->bufferSize = size;

	toReturn->data = info;
	toReturn->read = memRead;
	toReturn->write = memWrite;
	toReturn->seek = memSeek;
	toReturn->tell = memTell;
	toReturn->getLength = memGetLength;
	toReturn->close = memClose;
	toReturn->type = AbstractFileTypeMem;
	return toReturn;
err1:
	free(toReturn);
err0:
	abort();
	return NULL;
}

void abstractFilePrint(AbstractFile* file, const char* format, ...) {
	va_list args;
	char buffer[1024];
	size_t length;

	buffer[0] = '\0';
	va_start(args, format);
	length = vsnprintf(buffer, 1024, format, args);
        if (length > 1024) {
            fprintf(stderr, "abstractFilePrint buffer exceeded expected max length.\n");
            abort();
        }
	va_end(args);
	ASSERT(file->write(file, buffer, length) == length, "fwrite");
}

static int absFileRead(io_func* io, off_t location, size_t size, void *buffer) {
	AbstractFile* file;
	file = (AbstractFile*) io->data;
	file->seek(file, location);
	if(file->read(file, buffer, size) == size) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static int absFileWrite(io_func* io, off_t location, size_t size, void *buffer) {
	AbstractFile* file;
	file = (AbstractFile*) io->data;
	file->seek(file, location);
	if(file->write(file, buffer, size) == size) {
		return TRUE;
	} else {
		return FALSE;
	}
}

static void closeAbsFile(io_func* io) {
	AbstractFile* file;
	file = (AbstractFile*) io->data;
	file->close(file);
	free(io);
}


io_func* IOFuncFromAbstractFile(AbstractFile* file) {
	io_func* io;

	MALLOC_CHK_ABORT(io, sizeof(io_func));
	io->data = file;
	io->read = &absFileRead;
	io->write = &absFileWrite;
	io->close = &closeAbsFile;

	return io;
}

static size_t memFileRead(AbstractFile* file, void* data, size_t len) {
  MemFileWrapperInfo* info = (MemFileWrapperInfo*) (file->data); 
  memcpy(data, (void*)((uint8_t*)(*(info->buffer)) + (uint32_t)info->offset), len);
  info->offset += (size_t)len;
  if (info->offset < (size_t)len) {
      fprintf(stderr, "memFileRead info->offset overflow\n");
      abort();
  }
  return len;
}

static size_t memFileWrite(AbstractFile* file, const void* data, size_t len) {
  MemFileWrapperInfo* info = (MemFileWrapperInfo*) (file->data);
  size_t req_buf_size = info->offset + len;
  if (req_buf_size < len) {
      fprintf(stderr, "memFileWrite req_buf_size overflow\n");
      abort();
  }

  size_t req_up;
  if (roundup2(req_buf_size, &req_up)) {
      fprintf(stderr, "memFileWrite failed to roundup %zu\n", req_buf_size);
      abort();
  }
  info->actualBufferSize = (req_up > info->actualBufferSize) ? req_up : info->actualBufferSize;
  REALLOC_CHK_ABORT(*(info->buffer), info->actualBufferSize);

  if((info->offset + (size_t)len) > (*(info->bufferSize))) {
		*(info->bufferSize) = info->offset + (size_t)len;
	}
      
  memcpy((void*)((uint8_t*)(*(info->buffer)) + (uint32_t)info->offset), data, len);
  info->offset += (size_t)len;
  return len;
}

static int memFileSeek(AbstractFile* file, off_t offset) {
  MemFileWrapperInfo* info = (MemFileWrapperInfo*) (file->data);
  info->offset = (size_t)offset;
  return 0;
}

static off_t memFileTell(AbstractFile* file) {
  MemFileWrapperInfo* info = (MemFileWrapperInfo*) (file->data);
  return (off_t)info->offset;
}

static off_t memFileGetLength(AbstractFile* file) {
  MemFileWrapperInfo* info = (MemFileWrapperInfo*) (file->data);
  return *(info->bufferSize);
}

static void memFileClose(AbstractFile* file) {
  free(file->data);
  free(file);
}

AbstractFile* createAbstractFileFromMemoryFile(void** buffer, size_t* size) {
	MemFileWrapperInfo* info;
	AbstractFile* toReturn;
	MALLOC_CHK_FAIL(toReturn, sizeof(AbstractFile), err0);

	MALLOC_CHK_FAIL(info, sizeof(MemFileWrapperInfo), err1);
	info->offset = 0;
	info->buffer = buffer;
	info->bufferSize = size;
	info->actualBufferSize = (1024 < (*size)) ? (*size) : 1024;
	if(info->actualBufferSize != *(info->bufferSize)) {
		REALLOC_CHK_ABORT(*(info->buffer), info->actualBufferSize);
	}

	toReturn->data = info;
	toReturn->read = memFileRead;
	toReturn->write = memFileWrite;
	toReturn->seek = memFileSeek;
	toReturn->tell = memFileTell;
	toReturn->getLength = memFileGetLength;
	toReturn->close = memFileClose;
	toReturn->type = AbstractFileTypeMemFile;
	return toReturn;
err1:
	free(toReturn);
err0:
	abort();
	return NULL;
}

AbstractFile* createAbstractFileFromMemoryFileBuffer(void** buffer, size_t* size, size_t actualBufferSize) {
	MemFileWrapperInfo* info;
	AbstractFile* toReturn;
	MALLOC_CHK_FAIL(toReturn, sizeof(AbstractFile), err0);

	MALLOC_CHK_FAIL(info, sizeof(MemFileWrapperInfo), err1);
	info->offset = 0;
	info->buffer = buffer;
	info->bufferSize = size;
	info->actualBufferSize = actualBufferSize;

	toReturn->data = info;
	toReturn->read = memFileRead;
	toReturn->write = memFileWrite;
	toReturn->seek = memFileSeek;
	toReturn->tell = memFileTell;
	toReturn->getLength = memFileGetLength;
	toReturn->close = memFileClose;
	toReturn->type = AbstractFileTypeMemFile;
	return toReturn;
err1:
	free(toReturn);
err0:
	abort();
	return NULL;
}

