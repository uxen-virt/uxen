/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"

#define SYM_NAME(s) case s: return # s;

char * srb_function_name(UCHAR func)
{
    switch (func) {
        SYM_NAME(SRB_FUNCTION_EXECUTE_SCSI)
        SYM_NAME(SRB_FUNCTION_CLAIM_DEVICE)
        SYM_NAME(SRB_FUNCTION_IO_CONTROL)
        SYM_NAME(SRB_FUNCTION_RECEIVE_EVENT)
        SYM_NAME(SRB_FUNCTION_RELEASE_QUEUE)
        SYM_NAME(SRB_FUNCTION_ATTACH_DEVICE)
        SYM_NAME(SRB_FUNCTION_RELEASE_DEVICE)
        SYM_NAME(SRB_FUNCTION_SHUTDOWN)
        SYM_NAME(SRB_FUNCTION_FLUSH)
        SYM_NAME(SRB_FUNCTION_ABORT_COMMAND)
        SYM_NAME(SRB_FUNCTION_RELEASE_RECOVERY)
        SYM_NAME(SRB_FUNCTION_RESET_BUS)
        SYM_NAME(SRB_FUNCTION_RESET_DEVICE)
        SYM_NAME(SRB_FUNCTION_TERMINATE_IO)
        SYM_NAME(SRB_FUNCTION_FLUSH_QUEUE)
        SYM_NAME(SRB_FUNCTION_REMOVE_DEVICE)
        SYM_NAME(SRB_FUNCTION_WMI)
        SYM_NAME(SRB_FUNCTION_LOCK_QUEUE)
        SYM_NAME(SRB_FUNCTION_UNLOCK_QUEUE)
        SYM_NAME(SRB_FUNCTION_RESET_LOGICAL_UNIT)
        SYM_NAME(SRB_FUNCTION_SET_LINK_TIMEOUT)
        SYM_NAME(SRB_FUNCTION_LINK_TIMEOUT_OCCURRED)
        SYM_NAME(SRB_FUNCTION_LINK_TIMEOUT_COMPLETE)
        SYM_NAME(SRB_FUNCTION_POWER)
        SYM_NAME(SRB_FUNCTION_PNP)
        SYM_NAME(SRB_FUNCTION_DUMP_POINTERS)
    }
    return "unknown";
}

char * scsi_cmd_name(UCHAR cmd)
{
    switch (cmd) {
        SYM_NAME(SCSIOP_TEST_UNIT_READY)
        SYM_NAME(SCSIOP_REWIND)
        SYM_NAME(SCSIOP_REQUEST_BLOCK_ADDR)
        SYM_NAME(SCSIOP_REQUEST_SENSE)
        SYM_NAME(SCSIOP_FORMAT_UNIT)
        SYM_NAME(SCSIOP_READ_BLOCK_LIMITS)
        SYM_NAME(SCSIOP_REASSIGN_BLOCKS)
        SYM_NAME(SCSIOP_READ6)
        SYM_NAME(SCSIOP_WRITE6)
        SYM_NAME(SCSIOP_SEEK6)
        SYM_NAME(SCSIOP_SEEK_BLOCK)
        SYM_NAME(SCSIOP_PARTITION)
        SYM_NAME(SCSIOP_READ_REVERSE)
        SYM_NAME(SCSIOP_WRITE_FILEMARKS)
        SYM_NAME(SCSIOP_SPACE)
        SYM_NAME(SCSIOP_INQUIRY)
        SYM_NAME(SCSIOP_VERIFY6)
        SYM_NAME(SCSIOP_RECOVER_BUF_DATA)
        SYM_NAME(SCSIOP_MODE_SELECT)
        SYM_NAME(SCSIOP_RESERVE_UNIT)
        SYM_NAME(SCSIOP_RELEASE_UNIT)
        SYM_NAME(SCSIOP_COPY)
        SYM_NAME(SCSIOP_ERASE)
        SYM_NAME(SCSIOP_MODE_SENSE)
        SYM_NAME(SCSIOP_START_STOP_UNIT)
        SYM_NAME(SCSIOP_RECEIVE_DIAGNOSTIC)
        SYM_NAME(SCSIOP_SEND_DIAGNOSTIC)
        SYM_NAME(SCSIOP_MEDIUM_REMOVAL)
        SYM_NAME(SCSIOP_READ_FORMATTED_CAPACITY)
        SYM_NAME(SCSIOP_READ_CAPACITY)
        SYM_NAME(SCSIOP_READ)
        SYM_NAME(SCSIOP_WRITE)
        SYM_NAME(SCSIOP_SEEK)
        SYM_NAME(SCSIOP_WRITE_VERIFY)
        SYM_NAME(SCSIOP_VERIFY)
        SYM_NAME(SCSIOP_SEARCH_DATA_HIGH)
        SYM_NAME(SCSIOP_SEARCH_DATA_EQUAL)
        SYM_NAME(SCSIOP_SEARCH_DATA_LOW)
        SYM_NAME(SCSIOP_SET_LIMITS)
        SYM_NAME(SCSIOP_READ_POSITION)
        SYM_NAME(SCSIOP_SYNCHRONIZE_CACHE)
        SYM_NAME(SCSIOP_COMPARE)
        SYM_NAME(SCSIOP_COPY_COMPARE)
        SYM_NAME(SCSIOP_WRITE_DATA_BUFF)
        SYM_NAME(SCSIOP_READ_DATA_BUFF)
        SYM_NAME(SCSIOP_WRITE_LONG)
        SYM_NAME(SCSIOP_CHANGE_DEFINITION)
        SYM_NAME(SCSIOP_WRITE_SAME)
        SYM_NAME(SCSIOP_READ_SUB_CHANNEL)
        SYM_NAME(SCSIOP_READ_TOC)
        SYM_NAME(SCSIOP_READ_HEADER)
        SYM_NAME(SCSIOP_PLAY_AUDIO)
        SYM_NAME(SCSIOP_GET_CONFIGURATION)
        SYM_NAME(SCSIOP_PLAY_AUDIO_MSF)
        SYM_NAME(SCSIOP_PLAY_TRACK_INDEX)
        SYM_NAME(SCSIOP_PLAY_TRACK_RELATIVE)
        SYM_NAME(SCSIOP_GET_EVENT_STATUS)
        SYM_NAME(SCSIOP_PAUSE_RESUME)
        SYM_NAME(SCSIOP_LOG_SELECT)
        SYM_NAME(SCSIOP_LOG_SENSE)
        SYM_NAME(SCSIOP_STOP_PLAY_SCAN)
        SYM_NAME(SCSIOP_XDWRITE)
        SYM_NAME(SCSIOP_XPWRITE)
        SYM_NAME(SCSIOP_READ_TRACK_INFORMATION)
        SYM_NAME(SCSIOP_XDWRITE_READ)
        SYM_NAME(SCSIOP_SEND_OPC_INFORMATION)
        SYM_NAME(SCSIOP_MODE_SELECT10)
        SYM_NAME(SCSIOP_RESERVE_UNIT10)
        SYM_NAME(SCSIOP_RELEASE_UNIT10)
        SYM_NAME(SCSIOP_REPAIR_TRACK)
        SYM_NAME(SCSIOP_MODE_SENSE10)
        SYM_NAME(SCSIOP_CLOSE_TRACK_SESSION)
        SYM_NAME(SCSIOP_READ_BUFFER_CAPACITY)
        SYM_NAME(SCSIOP_SEND_CUE_SHEET)
        SYM_NAME(SCSIOP_PERSISTENT_RESERVE_IN)
        SYM_NAME(SCSIOP_PERSISTENT_RESERVE_OUT)
        SYM_NAME(SCSIOP_XDWRITE_EXTENDED16)
        SYM_NAME(SCSIOP_REBUILD16)
        SYM_NAME(SCSIOP_REGENERATE16)
        SYM_NAME(SCSIOP_EXTENDED_COPY)
        SYM_NAME(SCSIOP_RECEIVE_COPY_RESULTS)
        SYM_NAME(SCSIOP_ATA_PASSTHROUGH16)
        SYM_NAME(SCSIOP_ACCESS_CONTROL_IN)
        SYM_NAME(SCSIOP_ACCESS_CONTROL_OUT)
        SYM_NAME(SCSIOP_READ16)
        SYM_NAME(SCSIOP_WRITE16)
        SYM_NAME(SCSIOP_READ_ATTRIBUTES)
        SYM_NAME(SCSIOP_WRITE_ATTRIBUTES)
        SYM_NAME(SCSIOP_WRITE_VERIFY16)
        SYM_NAME(SCSIOP_VERIFY16)
        SYM_NAME(SCSIOP_PREFETCH16)
        SYM_NAME(SCSIOP_SYNCHRONIZE_CACHE16)
        SYM_NAME(SCSIOP_LOCK_UNLOCK_CACHE16)
        SYM_NAME(SCSIOP_WRITE_SAME16)
        SYM_NAME(SCSIOP_SERVICE_ACTION_IN16)
        SYM_NAME(SCSIOP_SERVICE_ACTION_OUT16)
        SYM_NAME(SCSIOP_REPORT_LUNS)
        SYM_NAME(SCSIOP_ATA_PASSTHROUGH12)
        SYM_NAME(SCSIOP_SEND_EVENT)
        SYM_NAME(SCSIOP_MAINTENANCE_IN)
        SYM_NAME(SCSIOP_MAINTENANCE_OUT)
        SYM_NAME(SCSIOP_MOVE_MEDIUM)
        SYM_NAME(SCSIOP_EXCHANGE_MEDIUM)
        SYM_NAME(SCSIOP_MOVE_MEDIUM_ATTACHED)
        SYM_NAME(SCSIOP_READ12)
        SYM_NAME(SCSIOP_SERVICE_ACTION_OUT12)
        SYM_NAME(SCSIOP_WRITE12)
        SYM_NAME(SCSIOP_SERVICE_ACTION_IN12)
        SYM_NAME(SCSIOP_GET_PERFORMANCE)
        SYM_NAME(SCSIOP_READ_DVD_STRUCTURE)
        SYM_NAME(SCSIOP_WRITE_VERIFY12)
        SYM_NAME(SCSIOP_VERIFY12)
        SYM_NAME(SCSIOP_SEARCH_DATA_HIGH12)
        SYM_NAME(SCSIOP_SEARCH_DATA_EQUAL12)
        SYM_NAME(SCSIOP_SEARCH_DATA_LOW12)
        SYM_NAME(SCSIOP_SET_LIMITS12)
        SYM_NAME(SCSIOP_READ_ELEMENT_STATUS_ATTACHED)
        SYM_NAME(SCSIOP_REQUEST_VOL_ELEMENT)
        SYM_NAME(SCSIOP_SEND_VOLUME_TAG)
        SYM_NAME(SCSIOP_READ_DEFECT_DATA)
        SYM_NAME(SCSIOP_READ_ELEMENT_STATUS)
        SYM_NAME(SCSIOP_READ_CD_MSF)
        SYM_NAME(SCSIOP_REDUNDANCY_GROUP_IN)
        SYM_NAME(SCSIOP_REDUNDANCY_GROUP_OUT)
        SYM_NAME(SCSIOP_SPARE_IN)
        SYM_NAME(SCSIOP_SPARE_OUT)
        SYM_NAME(SCSIOP_VOLUME_SET_IN)
        SYM_NAME(SCSIOP_VOLUME_SET_OUT)
        SYM_NAME(SCSIOP_INIT_ELEMENT_RANGE)
    }
    return "unknown";
}

char * ioctl_name(ULONG ioctl)
{
    switch (ioctl) {
        SYM_NAME(IOCTL_ACPI_ASYNC_EVAL_METHOD)
        SYM_NAME(IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES)
        SYM_NAME(IOCTL_STORAGE_CHECK_PRIORITY_HINT_SUPPORT)
        SYM_NAME(FT_BALANCED_READ_MODE)

        SYM_NAME(IOCTL_SCSI_PASS_THROUGH)
        SYM_NAME(IOCTL_SCSI_MINIPORT)
        SYM_NAME(IOCTL_SCSI_GET_INQUIRY_DATA)
        SYM_NAME(IOCTL_SCSI_GET_CAPABILITIES)
        SYM_NAME(IOCTL_SCSI_PASS_THROUGH_DIRECT)
        SYM_NAME(IOCTL_SCSI_GET_ADDRESS)
        SYM_NAME(IOCTL_SCSI_RESCAN_BUS)
        SYM_NAME(IOCTL_SCSI_GET_DUMP_POINTERS)
        SYM_NAME(IOCTL_SCSI_FREE_DUMP_POINTERS)
        SYM_NAME(IOCTL_IDE_PASS_THROUGH)
        SYM_NAME(IOCTL_ATA_PASS_THROUGH)
        SYM_NAME(IOCTL_ATA_PASS_THROUGH_DIRECT)
    }
    return "unknown";
}

char * stor_prop_name(int id)
{
    switch (id) {
        SYM_NAME(StorageDeviceProperty)
        SYM_NAME(StorageAdapterProperty)
        SYM_NAME(StorageDeviceIdProperty)
        SYM_NAME(StorageDeviceUniqueIdProperty)
        SYM_NAME(StorageDeviceWriteCacheProperty)
        SYM_NAME(StorageMiniportProperty)
        SYM_NAME(StorageAccessAlignmentProperty)
        SYM_NAME(StorageDeviceSeekPenaltyProperty)
        SYM_NAME(StorageDeviceTrimProperty)
    }
    return "unknown";
}

char * scsi_ioctl_name(ULONG ioctl)
{
    switch (ioctl) {
        SYM_NAME(IOCTL_SCSI_MINIPORT_SMART_VERSION)
        SYM_NAME(IOCTL_SCSI_MINIPORT_IDENTIFY)
        SYM_NAME(IOCTL_SCSI_MINIPORT_READ_SMART_ATTRIBS)
        SYM_NAME(IOCTL_SCSI_MINIPORT_READ_SMART_THRESHOLDS)
        SYM_NAME(IOCTL_SCSI_MINIPORT_ENABLE_SMART)
        SYM_NAME(IOCTL_SCSI_MINIPORT_DISABLE_SMART)
        SYM_NAME(IOCTL_SCSI_MINIPORT_RETURN_STATUS)
        SYM_NAME(IOCTL_SCSI_MINIPORT_ENABLE_DISABLE_AUTOSAVE)
        SYM_NAME(IOCTL_SCSI_MINIPORT_SAVE_ATTRIBUTE_VALUES)
        SYM_NAME(IOCTL_SCSI_MINIPORT_EXECUTE_OFFLINE_DIAGS)
        SYM_NAME(IOCTL_SCSI_MINIPORT_ENABLE_DISABLE_AUTO_OFFLINE)
        SYM_NAME(IOCTL_SCSI_MINIPORT_READ_SMART_LOG)
        SYM_NAME(IOCTL_SCSI_MINIPORT_WRITE_SMART_LOG)
    }
    return "unknown";
}

void buffer_dump(ULONG log_lvl, char *prefix, char *data, size_t data_size, size_t offset)
{
#define COLUMNS 16
    char line[128];
    char *pos = line;
    size_t i, j;

    C_ASSERT(sizeof(line) < 256);
    ASSERT_IRQL_BE(CLOCK_LEVEL - 1);
    ASSERT(data);

    data += offset;

    for (i = 0;
         i < (data_size + ((data_size % COLUMNS) ?
                           (COLUMNS - data_size % COLUMNS) : 0));
         i++)
    {
        /* Print address of current line content */
        if (i % COLUMNS == 0)
            pos += sprintf_s(pos, sizeof(line) - (pos - line),
                             "0x%p (0x%04x):  ", data + i, offset + i);

        /* Print data as hex */
        if (i < data_size) {
            if ((i % (COLUMNS / 2) == 0) && (i % COLUMNS != 0))
                pos += sprintf_s(pos, sizeof(line) - (pos - line),
                                 "- %02x ", 0xFF & data[i]);
            else
                pos += sprintf_s(pos, sizeof(line) - (pos - line),
                                 "%02x ", 0xFF & data[i]);
        } else {
            if ((i % (COLUMNS / 2) == 0) && (i % COLUMNS != 0))
                pos += sprintf_s(pos, sizeof(line) - (pos - line), "     ");
            else
                pos += sprintf_s(pos, sizeof(line) - (pos - line), "   ");
        }

        if (i % COLUMNS == (COLUMNS - 1)) {
            /* Print char representation of all bytes in the line */
            pos += sprintf_s(pos, sizeof(line) - (pos - line), " ");
            for (j = i - (COLUMNS - 1); j <= i; j++) {
                if (j < data_size) {
                    if (isprint(data[j])) {
                        pos += sprintf_s(pos, sizeof(line) - (pos - line),
                                         "%c", 0xFF & data[j]);
                    } else
                        pos += sprintf_s(pos, sizeof(line) - (pos - line), ".");
                }
            }
            uxen_printk(log_lvl, "%s%s", prefix, line);
            pos = line;
        }
    }
}
