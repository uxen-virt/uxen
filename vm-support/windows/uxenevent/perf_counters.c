/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

/* non-ANSI unfriendly */

#include <assert.h>
#define ERR_WINDOWS
#define ERR_AUTO_CONSOLE
#include <err.h>
#include <inttypes.h>

#include <pdh.h>
#include <pdhmsg.h>

#include "uxenevent.h"
#include "perf_counters.h"

#define pc_log(fmt, ...)                       \
    debug_log("perfcnt: " fmt, ## __VA_ARGS__)

typedef struct _PERF_COUNTER_CONTEXT {
    char                        counter_class_name[MAX_PATH];
    uint32_t                    counters_number;
    uint32_t                    instances_number;
    PDH_FMT_COUNTERVALUE        *fmt_values;
    HQUERY                      query;
    PDH_COUNTER_PATH_ELEMENTS   *cpe_array;
    HCOUNTER                    *hc_array;
} PERF_COUNTER_CONTEXT;

static
int construct_paths(PERF_COUNTER_CONTEXT *pcc,
                    char *counters,
                    char *instances,
                    char *counter_paths,
                    uint32_t *counter_paths_size)
{
    int ret;
    PDH_STATUS status;
    PDH_COUNTER_PATH_ELEMENTS *cpe;
    HCOUNTER *hc;
    uint32_t i, j;
    char *counter, *instance;
    char counter_path[MAX_PATH];
    char *out_counter_path;
    uint32_t out_counter_path_size;
    uint32_t counter_path_max_len, counter_path_len;

    assert(pcc);
    assert(!pcc->cpe_array);
    assert(!pcc->hc_array);
    assert(!pcc->query);
    assert(counters);
    assert(counter_paths_size);
    assert(!counter_paths || *counter_paths_size > 0);

    out_counter_path_size = 0;
    ret = -1;

    pcc->cpe_array = malloc(sizeof(*pcc->cpe_array) *
                            pcc->counters_number * pcc->instances_number);
    if (!pcc->cpe_array) {
        pc_log("unable to allocate counter paths array");
        goto out;
    }

    pcc->hc_array = malloc(sizeof(*pcc->hc_array) *
                           pcc->counters_number * pcc->instances_number);
    if (!pcc->hc_array) {
        pc_log("unable to allocate counter handles array");
        goto out;
    }

    status = PdhOpenQueryA(NULL, 0, &pcc->query);
    if (ERROR_SUCCESS != status) {
        pc_log("PdhOpenQueryA() failed: 0x%08x", (uint32_t)status);
        goto out;
    }

    out_counter_path = counter_paths;
    cpe = pcc->cpe_array;
    hc = pcc->hc_array;
    counter = counters;
    ret = 0;

    for (i = 0; i < pcc->counters_number; i++) {
        instance = instances;

        for (j = 0; j < pcc->instances_number; j++) {
            counter_path_max_len = sizeof(counter_path);

            cpe->szMachineName = NULL;
            cpe->szObjectName = pcc->counter_class_name;
            cpe->szInstanceName = instance;
            cpe->szParentInstance = NULL;
            cpe->dwInstanceIndex = -1;
            cpe->szCounterName = counter;

            status = PdhMakeCounterPathA(cpe,
                                         counter_path,
                                         (LPDWORD)&counter_path_max_len,
                                         0);
            if (ERROR_SUCCESS != status) {
                pc_log("PdhMakeCounterPathA() failed: 0x%08x", (uint32_t)status);
                *counter_paths_size = 0;
                ret = -1;
                goto out;
            }

            status = PdhAddCounterA(pcc->query, counter_path, 0, hc);
            if (ERROR_SUCCESS != status) {
                pc_log("PdhAddCounterA() failed: 0x%08x", (uint32_t)status);
                *counter_paths_size = 0;
                ret = -1;
                goto out;
            }

            counter_path_len = strlen(counter_path) + 1;
            if (0 == ret && counter_paths) {
                if (out_counter_path + counter_path_len
                    > counter_paths + *counter_paths_size)
                    ret = -1;
                else {
                    memcpy(out_counter_path, counter_path, counter_path_len);
                    out_counter_path[counter_path_len - 1] = 0;
                    out_counter_path += counter_path_len;
                }
            }

            out_counter_path_size += counter_path_len;

            cpe++;
            hc++;
            if (!instance)
                break;
            instance += strlen(instance) + 1;
        }

        counter += strlen(counter) + 1;
    }

    out_counter_path_size += 1;
    if (out_counter_path_size > *counter_paths_size || !counter_paths)
        ret = -1;
    else
        counter_paths[out_counter_path_size - 1] = 0;

  out:
    *counter_paths_size = out_counter_path_size;
    if (0 != ret) {
        if (pcc->cpe_array) {
            free(pcc->cpe_array);
            pcc->cpe_array = NULL;
        }
        if (pcc->hc_array) {
            free(pcc->hc_array);
            pcc->hc_array = NULL;
        }
        if (pcc->query) {
            PdhCloseQuery(pcc->query);
            pcc->query = NULL;
        }
    }

    return ret;
}

static
int refresh_sys_perf_counters()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int ret = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(NULL, "lodctr /R", NULL, NULL,
                       FALSE, 0, NULL, NULL, &si, &pi))
    {
        DWORD exit_code;
        WaitForSingleObject(pi.hProcess, INFINITE);
        if (!GetExitCodeProcess(pi.hProcess, &exit_code) || 0 != exit_code) {
            pc_log("lodctr failed: %d(%d)", (int)exit_code, (int)GetLastError());
            ret = -1;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        pc_log("failed to run lodctr: %d", (int)GetLastError());
        ret = -1;
    }

    return ret;
}

int perf_counters_create(void **ctx,
                         char *counter_class_name,
                         char *counter_paths,
                         uint32_t *counter_paths_size,
                         PDH_FMT_COUNTERVALUE *fmt_values,
                         uint32_t *fmt_values_size)
{
    int ret;
    PDH_STATUS status;
    uint32_t buffer_size;
    PERF_COUNTER_CONTEXT *pcc = NULL;
    char *current;
    char *counters = NULL;
    char *instances = NULL;
    uint32_t counters_size, instances_size;

    assert(counter_class_name);
    assert(counter_paths_size);
    assert(!counter_paths || *counter_paths_size > 0);
    assert(fmt_values_size);
    assert(!fmt_values || *fmt_values_size > 0);

    ret = -1;

    /* get name buffer sizes */
    counters_size = 0;
    instances_size = 0;
    status = PdhEnumObjectItemsA(NULL, NULL, counter_class_name,
                                 NULL, (PDWORD)&counters_size,
                                 NULL, (PDWORD)&instances_size,
                                 PERF_DETAIL_WIZARD, 0);
    if (PDH_MORE_DATA != status) {
        pc_log("PdhEnumObjectItemsA(%s) failed (size query): 0x%08x",
               counter_class_name, (uint32_t)status);
        goto out;
    }

    /* get names */
    counters = malloc(counters_size);
    if (!counters) {
        pc_log("unable to allocate counter names buffer");
        goto out;
    }
    if (instances_size > 0) {
        instances = malloc(instances_size);
        if (!instances) {
            pc_log("unable to allocate instance names buffer");
            goto out;
        }
    } else
        instances = NULL;
    status = PdhEnumObjectItemsA(NULL, NULL, counter_class_name,
                                 counters, (PDWORD)&counters_size,
                                 instances, (PDWORD)&instances_size,
                                 PERF_DETAIL_WIZARD, 0);
    if (ERROR_SUCCESS != status) {
        pc_log("PdhEnumObjectItemsA() failed: 0x%08x", (uint32_t)status);
        goto out;
    }

    pcc = malloc(sizeof(*pcc));
    if (!pcc) {
        pc_log("unable to allocate context buffer");
        goto out;
    }
    memset(pcc, 0, sizeof(*pcc));
    strcpy(pcc->counter_class_name, counter_class_name);

    /* calculate number of counters and instances */
    current = counters;
    while (*current) {
        current += strlen(current) + 1;
        pcc->counters_number++;
    }
    if (instances_size > 0) {
        pcc->instances_number = 0;
        current = instances;
        while (*current) {
            current += strlen(current) + 1;
            pcc->instances_number++;
        }
    } else {
        /* some counters (eg. 'Memory') doesn't have any instances */
        assert(pcc->counters_number > 0);
        pcc->instances_number = 1;
    }

    buffer_size = sizeof(PDH_FMT_COUNTERVALUE)
                  * pcc->counters_number
                  * pcc->instances_number;
    
    ret = construct_paths(pcc,
                          counters,
                          instances,
                          counter_paths,
                          counter_paths_size);
    if (0 != ret) {
        *fmt_values_size = buffer_size;
        goto out;
    }

    /* query about buffer sizes only - bail */
    if (!ctx || !fmt_values || !counter_paths) {
        *fmt_values_size = buffer_size;
        ret = -1;
        goto out;
    }
    if (buffer_size > *fmt_values_size) {
        pc_log("formatted counters buffer is too small (%d) - %d bytes required",
               *fmt_values_size, buffer_size);
        *fmt_values_size = buffer_size;
        ret = -1;
        goto out;
    }

    *fmt_values_size = buffer_size;
    pcc->fmt_values = fmt_values;

    *ctx = pcc;

  out:
    if (0 != ret) {
        if (counters)
            free(counters);
        if (instances)
            free(instances);
        if (pcc) {
            free(pcc);
            *ctx = NULL;
        }
    }

    return ret;
}

void perf_counters_destroy(void *ctx)
{
    PERF_COUNTER_CONTEXT *pcc = (PERF_COUNTER_CONTEXT *)ctx;

    assert(pcc);

    if (pcc->cpe_array) {
        free(pcc->cpe_array);
        pcc->cpe_array = NULL;
    }
    if (pcc->hc_array) {
        free(pcc->hc_array);
        pcc->hc_array = NULL;
    }
    if (pcc->query) {
        PdhCloseQuery(pcc->query);
        pcc->query = NULL;
    }

    free(ctx);
}

int perf_counters_query(void *ctx)
{
    int ret;
    PERF_COUNTER_CONTEXT *pcc = (PERF_COUNTER_CONTEXT *)ctx;
    PDH_STATUS status;
    HCOUNTER *hc;
    uint32_t i, j;
    uint32_t counters_total_number;

    assert(pcc);

    status = PdhCollectQueryData(pcc->query);
    if (ERROR_SUCCESS != status) {
        pc_log("PdhCollectQueryData() failed: 0x%08x", (uint32_t)status);
        return -1;
    }

    ret = 0;
    hc = pcc->hc_array;
    counters_total_number = pcc->counters_number * pcc->instances_number;
    j = 0;
    for (i = 0; i < counters_total_number; i++) {
        status = PdhGetFormattedCounterValue(*hc,
                                             PDH_FMT_DOUBLE,
                                             NULL,
                                             &pcc->fmt_values[j]);
        if (ERROR_SUCCESS != status) {
            if (PDH_INVALID_DATA != status)
                pc_log("PdhGetFormattedCounterValue() failed: 0x%08x",
                       (uint32_t)status);
            pcc->fmt_values[j].doubleValue = -1;
            ret = -1;
            break;
        }
        j++;
        hc++;
    }

    return ret;
}

int perf_counters_init()
{
    uint32_t buffer_size;
    int i, ret;
    PDH_STATUS status;

    /* refresh performance objects list */
    ret = 0;
    i = 0;
    while (i++ < 2) {
        buffer_size = 0;
        status = PdhEnumObjectsA(NULL, NULL,
                                 NULL, (LPDWORD)&buffer_size,
                                 PERF_DETAIL_WIZARD, TRUE);
        if (PDH_MORE_DATA != status) {
            if (refresh_sys_perf_counters()) {
                break;
            } else {
                continue;
            }
            pc_log("PdhEnumObjects() failed: 0x%08x\n", (uint32_t)status);
            ret = -1;
            break;
        }
    }

    return ret;
}

typedef struct _DATA_COLL_THREAD_CTX {
    uint64_t counters_mask;
    uint32_t min_sampling_interval;
    uint32_t number_of_samples;
} DATA_COLL_THREAD_CTX;

static
BOOL data_collection_in_progress = FALSE;

static 
DWORD WINAPI data_collection_thread(void *param)
{
    static struct {
        char name[MAX_PATH];
        void *ctx;
        char paths[1 << 17];
        char *paths_array[512];
        PDH_FMT_COUNTERVALUE values[512];
        uint32_t values_number;
    } counters_desc[] = {
        {"Memory", NULL},
        {"Processor", NULL},
        {"PhysicalDisk", NULL},
        {"Paging File", NULL},
    };

    char *curr;
    int i, j, k;
    uint32_t paths_size, values_size;
    DATA_COLL_THREAD_CTX *thread_ctx = (DATA_COLL_THREAD_CTX *)param;

    assert(thread_ctx);

    for (j = 0; j < ARRAYSIZE(counters_desc); j++) {
        paths_size = sizeof(counters_desc[0].paths);
        values_size = sizeof(counters_desc[0].values);

        if (NULL == counters_desc[j].ctx &&
            0 == perf_counters_create(&counters_desc[j].ctx,
                                      counters_desc[j].name,
                                      counters_desc[j].paths, &paths_size,
                                      counters_desc[j].values, &values_size))
        {
            /* generate counter name array */
            curr = counters_desc[j].paths;
            i = 0;
            while (*curr) {
                counters_desc[j].paths_array[i++] = curr;
                curr += strlen(curr) + 1;
            }
            counters_desc[j].values_number = 
                values_size / sizeof(counters_desc[j].values[0]);
            perf_counters_query(counters_desc[j].ctx);
        }
    }
    
    for (k = 0; k < thread_ctx->number_of_samples; k++) {
        for (j = 0; j < ARRAYSIZE(counters_desc); j++) {
            if (counters_desc[j].ctx &&
                thread_ctx->counters_mask & (1ULL << j))
            {
                perf_counters_query(counters_desc[j].ctx);
                for (i = 0; i < counters_desc[j].values_number; i++) {
                    pc_log("%d, %s, %3.3f",
                           i, 
                           counters_desc[j].paths_array[i], 
                           counters_desc[j].values[i].doubleValue);
                }
            }
        }
        Sleep(thread_ctx->min_sampling_interval);
    }

    data_collection_in_progress = FALSE;
    free(thread_ctx);

    return 0;
}

void perf_start_sampling(uint64_t counters_mask,
                         uint32_t min_sampling_interval,
                         uint32_t number_of_samples)
{
    HANDLE thread;
    DATA_COLL_THREAD_CTX *thread_ctx;

    if (data_collection_in_progress) {
        pc_log("data collection already in progress");
        return;
    }

    thread_ctx = malloc(sizeof(DATA_COLL_THREAD_CTX));
    if (!thread_ctx) {
        pc_log("failed to allocate 0x%x bytes for thread ctx",
               (uint32_t)sizeof(DATA_COLL_THREAD_CTX));
    } else {
        data_collection_in_progress = TRUE;
        thread_ctx->counters_mask = counters_mask;
        thread_ctx->min_sampling_interval = min_sampling_interval;
        thread_ctx->number_of_samples = number_of_samples;
        thread = CreateThread(NULL, 0, data_collection_thread, thread_ctx,
                              0, NULL);
        if (thread) {
            CloseHandle(thread);
        } else {
            pc_log("failed to create data collection thread: %d",
                   (uint32_t)GetLastError());
            free(thread_ctx);
            data_collection_in_progress = FALSE;
        }
    }
}
