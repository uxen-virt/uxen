/* 
 	Copyright (c) 2010 ,
 		Cloud Wu . All rights reserved.
 
 		http://www.codingnow.com
 
 	Use, modification and distribution are subject to the "New BSD License"
 	as listed at <url: http://www.opensource.org/licenses/bsd-license.php >.
 
   filename: backtrace.c

   compiler: gcc 3.4.5 (mingw-win32)

   build command: gcc -O2 -shared -Wall -o backtrace.dll backtrace.c -lbfd -liberty -limagehlp 

   how to use: Call LoadLibraryA("backtrace.dll"); at beginning of your program .

  */

#include <windows.h>
#include <excpt.h>
#include <imagehlp.h>
#define PACKAGE "uxen-backtrace"
#include <bfd.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

#include "pecoff-internal.h"
#include "monitor.h"

#define BUFFER_MAX (16*1024)

#if defined(_WIN64)
#define ADDR_T DWORD64
#else
#define ADDR_T DWORD
#endif

struct bfd_ctx {
	bfd * handle;
	asymbol ** symbol;
    char *imagebase;
};

struct bfd_set {
	char * name;
	struct bfd_ctx * bc;
	struct bfd_set *next;
};

struct find_info {
	asymbol **symbol;
	bfd_vma counter;
	const char *file;
	const char *func;
	unsigned line;
};

struct output_buffer {
	char * buf;
	size_t sz;
	size_t ptr;
};

static void
output_init(struct output_buffer *ob, char * buf, size_t sz)
{
	ob->buf = buf;
	ob->sz = sz;
	ob->ptr = 0;
	ob->buf[0] = '\0';
}

static void
output_print(struct output_buffer *ob, const char * format, ...)
{
	if (ob->sz == ob->ptr)
		return;
	ob->buf[ob->ptr] = '\0';
	va_list ap;
	va_start(ap,format);
	vsnprintf(ob->buf + ob->ptr , ob->sz - ob->ptr , format, ap);
	va_end(ap);

	ob->ptr = strlen(ob->buf + ob->ptr) + ob->ptr;
}

static void 
lookup_section(bfd *abfd, asection *sec, void *opaque_data)
{
	struct find_info *data = opaque_data;

	if (data->func)
		return;

	if (!(bfd_get_section_flags(abfd, sec) & SEC_ALLOC)) 
		return;

	bfd_vma offset = bfd_get_section_vma(abfd, sec) -
                abfd->tdata.pe_obj_data->pe_opthdr.ImageBase;
	if (data->counter < offset ||
            offset + bfd_get_section_size(sec) <= data->counter) 
		return;

	bfd_find_nearest_line(abfd, sec, data->symbol, data->counter - offset,
                              &(data->file), &(data->func), &(data->line));
}

static void
find(struct bfd_ctx * b, ADDR_T offset, const char **file, const char **func, unsigned *line)
{
	struct find_info data;
	data.func = NULL;
	data.symbol = b->symbol;
	data.counter = offset;
	data.file = NULL;
	data.func = NULL;
	data.line = 0;

	bfd_map_over_sections(b->handle, &lookup_section, &data);
	if (file) {
		*file = data.file;
	}
	if (func) {
		*func = data.func;
	}
	if (line) {
		*line = data.line;
	}
}

static int
init_bfd_ctx(struct bfd_ctx *bc, const char * procname, struct output_buffer *ob)
{
	bc->handle = NULL;
	bc->symbol = NULL;

	bfd *b = bfd_openr(procname, 0);
	if (!b) {
		output_print(ob,"Failed to open bfd from (%s)\n" , procname);
		return 1;
	}

        int ret;
        char **matching;
        ret = bfd_check_format_matches(b, bfd_object, &matching);
        if (!ret) {
            if (bfd_get_error () != bfd_error_file_ambiguously_recognized) {
              bfd_out:
                bfd_close(b);
                return 1;
            }
            bfd_close(b);
            b = bfd_openr(procname, matching[0]);
            if (!b)
                return 1;
            ret = bfd_check_format(b, bfd_object);
            if (!ret)
                goto bfd_out;
        }

	ret = bfd_get_file_flags(b) & HAS_SYMS;
	if (!ret) {
		bfd_close(b);
		/* output_print(ob,"Failed to init bfd from (%s)\n", procname); */
		return 1;
	}

	void *symbol_table;

	unsigned dummy = 0;
	if (bfd_read_minisymbols(b, FALSE, &symbol_table, &dummy) == 0) {
		if (bfd_read_minisymbols(b, TRUE, &symbol_table, &dummy) < 0) {
			free(symbol_table);
			bfd_close(b);
			output_print(ob,"Failed to read symbols from (%s)\n", procname);
			return 1;
		}
	}

	bc->handle = b;
	bc->symbol = symbol_table;

	return 0;
}

static void
close_bfd_ctx(struct bfd_ctx *bc)
{
	if (bc) {
		if (bc->symbol) {
			free(bc->symbol);
		}
		if (bc->handle) {
			bfd_close(bc->handle);
		}
                if (bc->imagebase)
                    free(bc->imagebase);
	}
}

static struct bfd_ctx *
get_bc(struct output_buffer *ob , struct bfd_set *set , const char *procname)
{
	while(set->name) {
		if (strcmp(set->name , procname) == 0) {
			return set->bc;
		}
		set = set->next;
	}
	struct bfd_ctx bc;
	if (init_bfd_ctx(&bc, procname , ob)) {
		return NULL;
	}
	set->next = calloc(1, sizeof(*set));
	set->bc = malloc(sizeof(struct bfd_ctx));
	memcpy(set->bc, &bc, sizeof(bc));
	set->name = strdup(procname);

        set->bc->imagebase = calloc(1, 20);
        if (set->bc->imagebase)
            snprintf(set->bc->imagebase, 19, "0x%lx", (long)
                     set->bc->handle->tdata.pe_obj_data->pe_opthdr.ImageBase);

	return set->bc;
}

static void
release_set(struct bfd_set *set)
{
	while(set) {
		struct bfd_set * temp = set->next;
		free(set->name);
		close_bfd_ctx(set->bc);
		free(set);
		set = temp;
	}
}

static void
_backtrace(struct output_buffer *ob, struct bfd_set *set, int depth , LPCONTEXT context)
{
	char procname[MAX_PATH];
	GetModuleFileNameA(NULL, procname, sizeof procname);

	struct bfd_ctx *bc = NULL;

	STACKFRAME frame;
	memset(&frame,0,sizeof(frame));

#if defined(_WIN64)
	frame.AddrPC.Offset = context->Rip;
	frame.AddrStack.Offset = context->Rsp;
	frame.AddrFrame.Offset = context->Rbp;
#else
	frame.AddrPC.Offset = context->Eip;
	frame.AddrStack.Offset = context->Esp;
	frame.AddrFrame.Offset = context->Ebp;
#endif
	frame.AddrPC.Mode = AddrModeFlat;
	frame.AddrStack.Mode = AddrModeFlat;
	frame.AddrFrame.Mode = AddrModeFlat;

	HANDLE process = GetCurrentProcess();
	HANDLE thread = GetCurrentThread();

	char symbol_buffer[sizeof(IMAGEHLP_SYMBOL) + 255];
	char module_name_raw[MAX_PATH];

        output_print(ob, "Backtrace:\n");

	while(StackWalk(
#if defined(_WIN64)
		IMAGE_FILE_MACHINE_AMD64,
#else
		IMAGE_FILE_MACHINE_I386,
#endif
		process, 
		thread, 
		&frame, 
		context, 
		0, 
		SymFunctionTableAccess, 
		SymGetModuleBase, 0)) {

		--depth;
		if (depth < 0)
			break;

		IMAGEHLP_SYMBOL *symbol = (IMAGEHLP_SYMBOL *)symbol_buffer;
		symbol->SizeOfStruct = (sizeof *symbol) + 255;
		symbol->MaxNameLength = 254;

		ADDR_T module_base = SymGetModuleBase(process, frame.AddrPC.Offset);

		const char * module_name = "[unknown module]";
		if (module_base && 
                    GetModuleFileNameA((HINSTANCE)(uintptr_t)module_base, module_name_raw, MAX_PATH)) {
			module_name = module_name_raw;
			bc = get_bc(ob, set, module_name);
		}

		const char * file = NULL;
		const char * func = NULL;
		unsigned line = 0;
                unsigned int displacement = 0;

		if (bc && frame.AddrPC.Offset >= module_base) {
			find(bc,frame.AddrPC.Offset - module_base,&file,&func,&line);
		}

                ADDR_T _displacement = 0;
                if (SymGetSymFromAddr(process, frame.AddrPC.Offset,
                                      &_displacement, symbol)) {
                    if (!func && !file)
                        func = symbol->Name;
                    if (!displacement && func && !strcmp(func, symbol->Name))
                        displacement = _displacement;
                }
		if (!func) {
                    if (bc && bc->imagebase)
                        func = bc->imagebase;
                    if (!func) {
                        func = strrchr(module_name, '\\');
                        if (!func)
                            func = strrchr(module_name, '/');
                        if (func) {
                            func++;
                            if (!*func)
                                func = NULL;
                        }
                    }
                    if (!func)
                        func = "[unknown file]";
                    displacement = frame.AddrPC.Offset - module_base;
                }
		if (file == NULL) {
			output_print(ob,"    0x%x: %s@0x%x: %s+0x%x\n",
                                     frame.AddrPC.Offset,
                                     module_name, module_base,
                                     func, displacement);
		} else {
                    if (displacement)
			output_print(ob,"    0x%x: %s@0x%x: %s+0x%x: %s:%d\n",
                                     frame.AddrPC.Offset,
                                     module_name, module_base,
                                     func, displacement,
                                     file, line);
                    else
			output_print(ob,"    0x%x: %s@0x%x: %s: %s:%d\n",
                                     frame.AddrPC.Offset,
                                     module_name, module_base,
                                     func,
                                     file, line);
		}
	}
}

static char * g_output = NULL;
static LPTOP_LEVEL_EXCEPTION_FILTER g_prev = NULL;

static volatile struct except_info *except_info = NULL;
static HANDLE except_client_mutex;
static HANDLE except_monitor_mutex;
static HANDLE except_notify_event;
static HANDLE except_cont_event;

static void
dump_exception_info(struct output_buffer *ob, PEXCEPTION_RECORD record)
{
    DWORD i;

    output_print(ob, "Exception caught !\n");
    output_print(ob, "    Code=%08x, Flags=%08x, Address=%p, Parameters(%d): ",
                 record->ExceptionCode, record->ExceptionFlags,
                 record->ExceptionAddress, record->NumberParameters);
    for (i = 0; i < (record->NumberParameters - 1); i++)
        output_print(ob, "%p, ", record->ExceptionInformation[i]);
    if (record->NumberParameters)
        output_print(ob, "%p\n", record->ExceptionInformation[i]);
}

static void
dump_regs(struct output_buffer *ob, LPCONTEXT context)
{
    output_print(ob, "Register dump:\n");

#if defined(_WIN64)
    output_print(ob, "    RIP=0x%016x\n", context->Rip);
    output_print(ob, "    RAX=0x%016x, RCX=0x%016x, RDX=0x%016x, RBX=0x%016x\n",
                 context->Rax, context->Rcx, context->Rdx, context->Rbx);
    output_print(ob, "    RSP=0x%016x, RBP=0x%016x, RSI=0x%016x, RDI=0x%016x\n",
                 context->Rsp, context->Rbp, context->Rsi, context->Rdi);
    output_print(ob, "    R8 =0x%016x, R9 =0x%016x, R10=0x%016x, R11=0x%016x\n",
                 context->R8, context->R9, context->R10, context->R11);
    output_print(ob, "    R12=0x%016x, R13=0x%016x, R14=0x%016x, R15=0x%016x\n",
                 context->Rsp, context->Rbp, context->Rsi, context->Rdi);
#else
    output_print(ob, "    EIP=0x%08x\n", context->Eip);
    output_print(ob, "    EAX=0x%08x, ECX=0x%08x, EDX=0x%08x, EBX=0x%08x\n",
                 context->Eax, context->Ecx, context->Edx, context->Ebx);
    output_print(ob, "    ESP=0x%08x, EBP=0x%08x, ESI=0x%08x, EDI=0x%08x\n",
                 context->Esp, context->Ebp, context->Esi, context->Edi);
#endif
    output_print(ob, "    EFLAGS=0x%08x\n", context->EFlags);
    output_print(ob, "    CS=0x%08x DS=0x%08x ES=0x%08x\n",
                 context->SegCs, context->SegDs, context->SegEs);
    output_print(ob, "    FS=0x%08x GS=0x%08x SS=0x%08x\n",
                 context->SegFs, context->SegGs, context->SegSs);
}

static LONG WINAPI
exception_filter(LPEXCEPTION_POINTERS info)
{
	struct output_buffer ob;
	output_init(&ob, g_output, BUFFER_MAX);
        DWORD rc;

        dump_exception_info(&ob, info->ExceptionRecord);
        dump_regs(&ob, info->ContextRecord);

	if (!SymInitialize(GetCurrentProcess(), 0, TRUE)) {
		output_print(&ob,"Failed to init symbol context\n");
	}
	else {
		bfd_init();
		struct bfd_set *set = calloc(1,sizeof(*set));
		_backtrace(&ob , set , 128 , info->ContextRecord);
		release_set(set);

		SymCleanup(GetCurrentProcess());
	}

	fputs(g_output , stderr);
	fflush(stderr);

        if (!except_info)
            return 0;

        rc = WaitForSingleObject(except_client_mutex, INFINITE);
        if (rc == WAIT_OBJECT_0) {
            HANDLE events[2] = {except_cont_event, except_monitor_mutex};

            except_info->process_id = GetCurrentProcessId();
            except_info->thread_id = GetCurrentThreadId();
            except_info->exception_pointers = info;

            SetEvent(except_notify_event);

            /*
             * Wake up after one of the 3 condition occurs:
             *  - monitor signals continue event (Most likely)
             *  - we acquire the monitor mutex (monitor is not running)
             *  - 2 minute timeout occurs
             */
            rc = WaitForMultipleObjects(2, events, FALSE, 120 * 1000);
            if (rc == (WAIT_OBJECT_0 + 1)) {
                ResetEvent(except_notify_event);
                ReleaseMutex(except_monitor_mutex);
            }

            ReleaseMutex(except_client_mutex);
        }

	return 0;
}

UINT WINAPI GetErrorMode(void);
static UINT errmode;
HANDLE except_shm_handle;

static void
backtrace_register(void)
{
	errmode = GetErrorMode();
	SetErrorMode(errmode | SEM_NOGPFAULTERRORBOX);

	if (g_output == NULL) {
		g_output = malloc(BUFFER_MAX);
		g_prev = SetUnhandledExceptionFilter(exception_filter);
	}

        except_shm_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                              PAGE_READWRITE | SEC_COMMIT, 0,
                                              sizeof (*except_info),
                                              EXCEPTION_SHM_FILE_NAME);
        except_info = MapViewOfFile(except_shm_handle, FILE_MAP_WRITE, 0, 0,
                                    sizeof (*except_info));
        except_client_mutex = CreateMutex(NULL, FALSE,
                                          EXCEPTION_CLIENT_MUTEX_NAME);
        except_monitor_mutex = CreateMutex(NULL, FALSE,
                                           EXCEPTION_MONITOR_MUTEX_NAME);
        except_notify_event = CreateEvent(NULL, FALSE, FALSE,
                                          EXCEPTION_NOTIFY_EVENT_NAME);
        except_cont_event = CreateEvent(NULL, FALSE, FALSE,
                                        EXCEPTION_CONTINUE_EVENT_NAME);
}

static void
backtrace_unregister(void)
{
	if (g_output) {
		free(g_output);
		SetUnhandledExceptionFilter(g_prev);
		g_prev = NULL;
		g_output = NULL;
	}

	SetErrorMode(errmode);

        if (except_info)
            UnmapViewOfFile((void *)except_info);
        if (except_cont_event)
            CloseHandle(except_cont_event);
        if (except_notify_event)
            CloseHandle(except_notify_event);
        if (except_client_mutex)
            CloseHandle(except_client_mutex);
        if (except_monitor_mutex)
            CloseHandle(except_monitor_mutex);
        if (except_shm_handle)
            CloseHandle(except_shm_handle);
}

BOOL WINAPI
DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		backtrace_register();
		break;
	case DLL_PROCESS_DETACH:
		backtrace_unregister();
		break;
	}
	return TRUE;
}

