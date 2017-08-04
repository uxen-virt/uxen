/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_SCSI_H_
#define _UXEN_SCSI_H_

#include <dm/block.h>


#define SCSIOP_TEST_UNIT_READY       0x00
#define SCSIOP_REZERO_UNIT           0x01
#define SCSIOP_REQUEST_SENSE         0x03
#define SCSIOP_FORMAT_UNIT           0x04
#define SCSIOP_READ_BLOCK_LIMITS     0x05
#define SCSIOP_REASSIGN_BLOCKS       0x07
#define SCSIOP_READ_6                0x08
#define SCSIOP_WRITE_6               0x0a
#define SCSIOP_SEEK_6                0x0b
#define SCSIOP_READ_REVERSE          0x0f
#define SCSIOP_WRITE_FILEMARKS       0x10
#define SCSIOP_SPACE                 0x11
#define SCSIOP_INQUIRY               0x12
#define SCSIOP_RECOVER_BUFFERED_DATA 0x14
#define SCSIOP_MODE_SELECT           0x15
#define SCSIOP_RESERVE               0x16
#define SCSIOP_RELEASE               0x17
#define SCSIOP_COPY                  0x18
#define SCSIOP_ERASE                 0x19
#define SCSIOP_MODE_SENSE_6          0x1a
#define SCSIOP_START_STOP_UNIT       0x1b
#define SCSIOP_RECEIVE_DIAGNOSTIC    0x1c
#define SCSIOP_SEND_DIAGNOSTIC       0x1d
#define SCSIOP_ALLOW_MEDIUM_REMOVAL  0x1e

#define SCSIOP_SET_WINDOW            0x24
#define SCSIOP_READ_CAPACITY_10      0x25
#define SCSIOP_READ_10               0x28
#define SCSIOP_WRITE_10              0x2a
#define SCSIOP_SEEK_10               0x2b
#define SCSIOP_WRITE_VERIFY          0x2e
#define SCSIOP_VERIFY                0x2f
#define SCSIOP_SEARCH_HIGH           0x30
#define SCSIOP_SEARCH_EQUAL          0x31
#define SCSIOP_SEARCH_LOW            0x32
#define SCSIOP_SET_LIMITS            0x33
#define SCSIOP_PRE_FETCH             0x34
#define SCSIOP_READ_POSITION         0x34
#define SCSIOP_SYNCHRONIZE_CACHE_10  0x35
#define SCSIOP_LOCK_UNLOCK_CACHE     0x36
#define SCSIOP_READ_DEFECT_DATA      0x37
#define SCSIOP_MEDIUM_SCAN           0x38
#define SCSIOP_COMPARE               0x39
#define SCSIOP_COPY_VERIFY           0x3a
#define SCSIOP_WRITE_BUFFER          0x3b
#define SCSIOP_READ_BUFFER           0x3c
#define SCSIOP_UPDATE_BLOCK          0x3d
#define SCSIOP_READ_LONG             0x3e
#define SCSIOP_WRITE_LONG            0x3f
#define SCSIOP_CHANGE_DEFINITION     0x40
#define SCSIOP_WRITE_SAME            0x41
#define SCSIOP_READ_TOC              0x43
#define SCSIOP_LOG_SELECT            0x4c
#define SCSIOP_LOG_SENSE             0x4d
#define SCSIOP_MODE_SELECT_10        0x55
#define SCSIOP_RESERVE_10            0x56
#define SCSIOP_RELEASE_10            0x57
#define SCSIOP_MODE_SENSE_10         0x5a
#define SCSIOP_PERSISTENT_RESERVE_IN 0x5e
#define SCSIOP_PERSISTENT_RESERVE_OUT 0x5f
#define SCSIOP_REPORT_LUNS           0xa0
#define SCSIOP_MAINTENANCE_IN        0xa3
#define SCSIOP_MOVE_MEDIUM           0xa5
#define SCSIOP_READ_16               0x88
#define SCSIOP_WRITE_16              0x8a
#define SCSIOP_SYNCHRONIZE_CACHE_16  0x91
#define SCSIOP_READ_CAPACITY_16      0x9e
#define SCSIOP_READ_12               0xa8
#define SCSIOP_WRITE_12              0xaa
#define SCSIOP_WRITE_VERIFY_12       0xae
#define SCSIOP_SEARCH_HIGH_12        0xb0
#define SCSIOP_SEARCH_EQUAL_12       0xb1
#define SCSIOP_SEARCH_LOW_12         0xb2
#define SCSIOP_READ_ELEMENT_STATUS   0xb8
#define SCSIOP_SEND_VOLUME_TAG       0xb6
#define SCSIOP_WRITE_LONG_2          0xea

/*
 * Mode pages
 */

#define SCSIMP_R_W_ERROR                   0x01
#define SCSIMP_HD_GEOMETRY                 0x04
#define SCSIMP_FLEXIBLE_DISK_GEOMETRY      0x05
#define SCSIMP_CACHING                     0x08
#define SCSIMP_AUDIO_CTL                   0x0e
#define SCSIMP_POWER                       0x1a
#define SCSIMP_FAULT_FAIL                  0x1c
#define SCSIMP_TO_PROTECT                  0x1d
#define SCSIMP_CAPABILITIES                0x2a
#define SCSIMP_ALL                         0x3f

/*
 *  Status codes
 */

#define SCSIST_GOOD                 0x00
#define SCSIST_CHECK_CONDITION      0x01
#define SCSIST_CONDITION_GOOD       0x02
#define SCSIST_BUSY                 0x04
#define SCSIST_INTERMEDIATE_GOOD    0x08
#define SCSIST_INTERMEDIATE_C_GOOD  0x0a
#define SCSIST_RESERVATION_CONFLICT 0x0c
#define SCSIST_COMMAND_TERMINATED   0x11
#define SCSIST_QUEUE_FULL           0x14

#define SCSIST_STATUS_MASK          0x3e

/*
 *  SENSE KEYS
 */

#define SCSISK_NO_SENSE            0x00
#define SCSISK_RECOVERED_ERROR     0x01
#define SCSISK_NOT_READY           0x02
#define SCSISK_MEDIUM_ERROR        0x03
#define SCSISK_HARDWARE_ERROR      0x04
#define SCSISK_ILLEGAL_REQUEST     0x05
#define SCSISK_UNIT_ATTENTION      0x06
#define SCSISK_DATA_PROTECT        0x07
#define SCSISK_BLANK_CHECK         0x08
#define SCSISK_COPY_ABORTED        0x0a
#define SCSISK_ABORTED_COMMAND     0x0b
#define SCSISK_VOLUME_OVERFLOW     0x0d
#define SCSISK_MISCOMPARE          0x0e


/*
 *  DEVICE TYPES
 */

#define SCSI_TYPE_DISK           0x00
#define SCSI_TYPE_TAPE           0x01
#define SCSI_TYPE_PROCESSOR      0x03 /* HP scanners use this */
#define SCSI_TYPE_WORM           0x04 /* Treated as ROM by our system */
#define SCSI_TYPE_ROM            0x05
#define SCSI_TYPE_SCANNER        0x06
#define SCSI_TYPE_MOD            0x07 /* Magneto-optical disk -
                                       * - treated as TYPE_DISK */
#define SCSI_TYPE_MEDIUM_CHANGER 0x08
#define SCSI_TYPE_ENCLOSURE	    0x0d /* Enclosure Services Device */
#define SCSI_TYPE_NO_LUN         0x7f



struct UXSCSI_struct;

typedef void (UXSCSI_callback) (void *, struct UXSCSI_struct *);

typedef struct UXSCSI_struct
{
  uint8_t *cdb;
  size_t cdb_len;

  uint8_t *write_ptr;
  size_t write_len;

  uint8_t *read_ptr;
  size_t read_len;

  uint8_t *sense_ptr;
  size_t sense_len;

  uint8_t scsi_status;

  UXSCSI_callback *cb;
  void *cb_arg;

  struct iovec iov;

  QEMUIOVector qiov;
  BlockDriverAIOCB *aiocb;

  BlockDriverState *bs;

} UXSCSI;


static inline uint8_t
uxscsi_status (UXSCSI * s)
{
  return s->scsi_status;
}

static inline size_t
uxscsi_red_len (UXSCSI * s)
{
  return s->read_len;
}                               /*Only valid on success */

//static inline size_t uxscsi_writ_len(UXSCSI *s) { return s->write_len; }
static inline size_t
uxscsi_sensed_len (UXSCSI * s)
{
  return s->sense_len;
}

int
uxscsi_start (UXSCSI * s, BlockDriverState * bs,
              size_t c_size, void *c_ptr,
              size_t w_size, void *w_ptr,
              size_t r_len, void *r_ptr,
              size_t s_len, void *s_ptr, UXSCSI_callback * cb, void *cb_arg);

#endif
