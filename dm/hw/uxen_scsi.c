/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/pci.h>
#include <dm/block.h>
#include <dm/hw.h>

#include "uxen_scsi.h"
#ifdef __APPLE__
#include "uxen_scsi_osx.h"
#endif

#if 1
/*GRR  - no endian.h */

#undef  __BYTE_ORDER
#define __BYTE_ORDER  1234

#undef __BIG_ENDIAN
#define __BIG_ENDIAN  4321

#undef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN  1234
#endif

#if 1
/* gcc before 4.8 doesn't provide __builtin_bswap16 */

static inline uint16_t
bswap16 (uint16_t v)
{
  __asm__ __volatile ("rorw $8,%0":"=d" (v):"0" (v));
  return v;
}
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define le_64(x) __builtin_bswap64(x)
#define le_32(x) __builtin_bswap32(x)
#define le_16(x) bswap16(x)
#define be_64(x) (x)
#define be_32(x) (x)
#define be_16(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define le_64(x) (x)
#define le_32(x) (x)
#define le_16(x) (x)
#define be_64(x) __builtin_bswap64(x)
#define be_32(x) __builtin_bswap32(x)
#define be_16(x) bswap16(x)
#else
#error __BYTE_ORDER undefined
#endif

#define SECTOR 		0x200
#define SECTOR_SHIFT	9

static inline uint64_t
uabe16_to_h (void *v)
{
  return (uint64_t) be_16 (*(uint16_t *) v);
}


static inline uint64_t
uabe32_to_h (void *v)
{
  return (uint64_t) be_32 (*(uint32_t *) v);
}


static inline uint64_t
uabe64_to_h (void *v)
{
  return (uint64_t) be_64 (*(uint64_t *) v);
}


size_t
safe_reply_8 (UXSCSI * s, size_t offset, uint8_t v)
{
  size_t n = s->read_len - offset;

  if (offset < s->read_len)
    {
      if (n > sizeof (v))
        n = sizeof (v);
      memcpy (s->read_ptr + offset, &v, n);
    }

  return sizeof (v);
}


size_t
safe_reply_be16 (UXSCSI * s, size_t offset, uint16_t v)
{
  size_t n = s->read_len - offset;

  v = be_16 (v);

  if (offset < s->read_len)
    {
      if (n > sizeof (v))
        n = sizeof (v);
      memcpy (s->read_ptr + offset, &v, n);
    }

  return sizeof (v);
}


size_t
safe_reply_be32 (UXSCSI * s, size_t offset, uint32_t v)
{
  size_t n = s->read_len - offset;

  v = be_32 (v);

  if (offset < s->read_len)
    {
      if (n > sizeof (v))
        n = sizeof (v);
      memcpy (s->read_ptr + offset, &v, n);
    }

  return sizeof (v);
}


size_t
safe_reply_be64 (UXSCSI * s, size_t offset, uint64_t v)
{
  size_t n = s->read_len - offset;

  v = be_64 (v);

  if (offset < s->read_len)
    {
      if (n > sizeof (v))
        n = sizeof (v);
      memcpy (s->read_ptr + offset, &v, n);
    }

  return sizeof (v);
}


static void
generate_sense (UXSCSI * s, uint8_t resp, uint8_t sk, uint8_t asc,
                uint8_t ascq)
{
  uint8_t sense[18];


  if (s->sense_len > sizeof (sense))
    s->sense_len = sizeof (sense);

  if (!s->sense_len)
    return;

  memset (sense, 0, sizeof (sense));

  sense[0] = 0x80 | resp;
  sense[2] = sk;
  sense[12] = asc;
  sense[13] = ascq;



  memcpy (s->sense_ptr, sense, s->sense_len);


}

static void
generate_nonsense (UXSCSI * s)
{
  s->sense_len = 0;
}


static int
check_condition (UXSCSI * s, uint8_t sk, uint8_t asc, uint8_t ascq)
{
  s->scsi_status = SCSIST_CHECK_CONDITION;

  generate_sense (s, 0x70, sk, asc, ascq);

  if (s->cb)
    s->cb (s->cb_arg, s);

  return 0;
}



static int
success (UXSCSI * s)
{

  s->scsi_status = SCSIST_GOOD;;

  generate_nonsense (s);

  if (s->cb)
    s->cb (s->cb_arg, s);

  return 0;
}


static void
uxscsi_read_cb (void *_s, int ret)
{
  UXSCSI *s = (UXSCSI *) _s;

  if (ret)
    check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
  else
    success (s);
}


static int
uxscsi_read (UXSCSI * s, uint64_t lba, uint64_t count)
{

  if (count > (s->read_len >> SECTOR_SHIFT))
    return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  s->read_len = count << SECTOR_SHIFT;

  s->iov.iov_base = s->read_ptr;
  s->iov.iov_len = count << SECTOR_SHIFT;

  qemu_iovec_init_external (&s->qiov, &s->iov, 1);

  s->aiocb = bdrv_aio_readv (s->bs, lba, &s->qiov, count, uxscsi_read_cb, s);

  if (!s->aiocb)
    check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  return 0;
}



static void
uxscsi_write_cb (void *_s, int ret)
{
  UXSCSI *s = (UXSCSI *) _s;

  if (ret)
    check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
  else
    success (s);

}


static int
uxscsi_write (UXSCSI * s, uint64_t lba, uint64_t count)
{

  if (count > (s->write_len >> SECTOR_SHIFT))
    return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  s->iov.iov_base = s->write_ptr;
  s->iov.iov_len = count << SECTOR_SHIFT;

  qemu_iovec_init_external (&s->qiov, &s->iov, 1);

  s->aiocb =
    bdrv_aio_writev (s->bs, lba, &s->qiov, count, uxscsi_write_cb, s);

  if (!s->aiocb)
    check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  return 0;
}


static int
uxscsi_request_sense (UXSCSI * s, uint64_t count)
{
  if (s->read_len < count)
    return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

//FIXME do proper sense
  memset (s->read_ptr, 0, count);
  s->read_len = count;

  return success (s);
}



static int
uxscsi_read_capacity_10 (UXSCSI * s)
{
  uint64_t n_sectors;
  struct read_capacity_10_pd
  {
    uint32_t lba;
    uint32_t block_len;
  } pd;

  if (s->read_len < sizeof (pd))
    return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  bdrv_get_geometry (s->bs, &n_sectors);
  --n_sectors; // reply is last addressable block

  if (n_sectors > 0xffffffffULL)
    n_sectors = 0xffffffffULL;

  pd.lba = be_32 (n_sectors);
  pd.block_len = be_32 (SECTOR);

  memcpy (s->read_ptr, &pd, sizeof (pd));

  return success (s);
}

static int
uxscsi_read_capacity_16 (UXSCSI * s, uint64_t count)
{
  uint64_t n_sectors;
  struct read_capacity_16_pd
  {
    uint64_t lba;
    uint32_t block_len;
    uint32_t pad[5];
  } pd;

  if (s->read_len < count)
    return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  if (count > sizeof (pd))
    count = sizeof (pd);
  s->read_len = count;

  memset (&pd, 0, sizeof (pd));

  bdrv_get_geometry (s->bs, &n_sectors);
  --n_sectors; // reply is last addressable block

  pd.lba = be_64 (n_sectors);
  pd.block_len = be_32 (SECTOR);

  memcpy (s->read_ptr, &pd, count);

  return success (s);
}

static int
add_page_data (UXSCSI * s, size_t * offset, uint8_t pc, uint8_t page)
{
  size_t len_ptr;


  switch (page)
    {

    case SCSIMP_CACHING:
      (*offset) += safe_reply_8 (s, *offset, page);

      len_ptr = *offset;
      (*offset) += safe_reply_8 (s, *offset, 0); /*length */

      (*offset) += safe_reply_8 (s, *offset, bdrv_enable_write_cache (s->bs) ? 0x4 : 0x0); /*cache bits */
      (*offset) += safe_reply_8 (s, *offset, 0); /*retention */
      (*offset) += safe_reply_be16 (s, *offset, 0); /*disable prefetch len */
      (*offset) += safe_reply_be16 (s, *offset, 0); /*min prefetch len */
      (*offset) += safe_reply_be16 (s, *offset, 0); /*max prefetch len */
      (*offset) += safe_reply_be16 (s, *offset, 0); /*max prefetch ceiling */
      (*offset) += safe_reply_8 (s, *offset, 0); /*more flags */
      (*offset) += safe_reply_8 (s, *offset, 0); /*segments */
      (*offset) += safe_reply_be16 (s, *offset, 0); /*cache segment size */
      (*offset) += safe_reply_be32 (s, *offset, 0); /*non cache segment size */

      /* set the length */
      safe_reply_8 (s, len_ptr, (uint8_t) ((*offset - len_ptr) - 1));

      return 0;
    default:
      return -1;
    }
}

static int
uxscsi_mode_sense_6 (UXSCSI * s, int dbd, uint8_t pc, uint8_t page,
                     uint8_t subpage, uint64_t count)
{
  size_t offset = 0;
  uint64_t n_sectors;

  if (s->read_len < count)
    check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  offset += safe_reply_8 (s, offset, 0); /*len */
  offset += safe_reply_8 (s, offset, 0); /*medium */
  offset += safe_reply_8 (s, offset, 0); /*readonly */
  offset += safe_reply_8 (s, offset, dbd ? 0x0 : 8); /*block desc len */

  if (!dbd)
    {
      bdrv_get_geometry (s->bs, &n_sectors);

      if (n_sectors > 0xffffffffULL)
        n_sectors = 0xffffffff;

      offset += safe_reply_be32 (s, offset, n_sectors);
/*this should be an 8 and 24 bit value, but we want the top byte zero anyway */
      offset += safe_reply_be32 (s, offset, SECTOR);
    }

/* Fixme fail here if pc!=0 */

  if (page == SCSIMP_ALL)
    {
      for (page = 0; page < SCSIMP_ALL; ++page)
        add_page_data (s, &offset, pc, page);
    }
  else
    {
      if (add_page_data (s, &offset, pc, page))
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
    }

  safe_reply_8 (s, 0, (uint8_t) offset - 1);


  if (count > offset)
    count = offset;

  if (s->read_len > count)
    s->read_len = count;

  return success (s);
}



static int
uxscsi_mode_sense_10 (UXSCSI * s, int dbd, uint8_t pc, uint8_t page,
                      uint8_t subpage, uint64_t count)
{
  size_t offset = 0;
  uint64_t n_sectors;


  if (s->read_len < count)
    check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

  offset += safe_reply_be16 (s, offset, 0); /*len */
  offset += safe_reply_8 (s, offset, 0); /*medium */
  offset += safe_reply_8 (s, offset, 0); /*readonly */

  offset += safe_reply_8 (s, offset, 1); /*long lba */
  offset += safe_reply_8 (s, offset, 0); /*reserved */

  offset += safe_reply_8 (s, offset, dbd ? 0x0 : 0x10); /*block desc len */

  if (!dbd)
    {
      bdrv_get_geometry (s->bs, &n_sectors);

      offset += safe_reply_be64 (s, offset, n_sectors);
      offset += safe_reply_be32 (s, offset, 0); /*reserved */
      offset += safe_reply_be32 (s, offset, SECTOR); /*reserved */
    }

/* Fixme fail here if pc!=0 */

  if (page == SCSIMP_ALL)
    {
      for (page = 0; page < SCSIMP_ALL; ++page)
        add_page_data (s, &offset, pc, page);
    }
  else
    {
      if (add_page_data (s, &offset, pc, page))
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
    }

  safe_reply_be16 (s, 0, (uint8_t) offset - 1);

  if (count > offset)
    count = offset;

  if (s->read_len > count)
    s->read_len = count;

  return success (s);
}


static int
uxscsi_parse (UXSCSI * s)
{
  uint64_t lba = 0;
  uint64_t count = 0;


  switch (s->cdb[0])
    {

    case SCSIOP_REQUEST_SENSE:
      if (s->cdb_len < 6)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      count = s->cdb[4];

      return uxscsi_request_sense (s, count);

    case SCSIOP_START_STOP_UNIT:
      if (s->cdb_len < 6)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
      return success (s);




    case SCSIOP_TEST_UNIT_READY:
      if (s->cdb_len < 6)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      return success (s);

    case SCSIOP_MODE_SENSE_6:
      {
        uint8_t pc;
        uint8_t page;
        uint8_t subpage;
        int dbd;

        if (s->cdb_len < 6)
          return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

        dbd = ! !(s->cdb[1] & 0x8);
        pc = s->cdb[2] & 0xc0;
        page = s->cdb[2] & 0x3f;
        subpage = s->cdb[3];
        count = s->cdb[4];


        return uxscsi_mode_sense_6 (s, dbd, pc, page, subpage, count);
      }

    case SCSIOP_MODE_SENSE_10:
      {
        uint8_t pc;
        uint8_t page;
        uint8_t subpage;
        int dbd;

        if (s->cdb_len < 10)
          return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

        dbd = ! !(s->cdb[1] & 0x8);
        pc = s->cdb[2] & 0xc0;
        page = s->cdb[2] & 0x3f;
        subpage = s->cdb[3];
        count = uabe16_to_h (&s->cdb[7]);

        return uxscsi_mode_sense_10 (s, dbd, pc, page, subpage, count);
      }



    case SCSIOP_READ_CAPACITY_10:
      if (s->cdb_len < 10)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      return uxscsi_read_capacity_10 (s);


    case SCSIOP_READ_CAPACITY_16:
      if (s->cdb_len < 16)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      count = uabe32_to_h (&s->cdb[10]);

      return uxscsi_read_capacity_16 (s, count);


    case SCSIOP_SYNCHRONIZE_CACHE_10:
      if (s->cdb_len < 10)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      return success (s);

    case SCSIOP_SYNCHRONIZE_CACHE_16:
      if (s->cdb_len < 16)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      return success (s);

    case SCSIOP_READ_6:

      if (s->cdb_len < 6)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = (s->cdb[1] & 0x1f) << 16;
      lba |= s->cdb[2] << 8;
      lba |= s->cdb[3];
      count = s->cdb[4];

      if (!count)
        count = 256;

      return uxscsi_read (s, lba, count);

    case SCSIOP_READ_10:
      if (s->cdb_len < 10)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = uabe32_to_h (&s->cdb[2]);
      count = uabe16_to_h (&s->cdb[7]);

      return uxscsi_read (s, lba, count);

    case SCSIOP_READ_12:
      if (s->cdb_len < 12)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = uabe32_to_h (&s->cdb[2]);
      count = uabe32_to_h (&s->cdb[6]);

      return uxscsi_read (s, lba, count);
    case SCSIOP_READ_16:
      if (s->cdb_len < 16)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = uabe64_to_h (&s->cdb[2]);
      count = uabe32_to_h (&s->cdb[10]);

      return uxscsi_read (s, lba, count);
    case SCSIOP_WRITE_6:
      if (s->cdb_len < 6)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = (s->cdb[1] & 0x1f) << 16;
      lba |= s->cdb[2] << 8;
      lba |= s->cdb[3];
      count = s->cdb[4];

      if (!count)
        count = 256;

      return uxscsi_write (s, lba, count);

    case SCSIOP_WRITE_10:
      if (s->cdb_len < 10)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = uabe32_to_h (&s->cdb[2]);
      count = uabe16_to_h (&s->cdb[7]);

      return uxscsi_write (s, lba, count);

    case SCSIOP_WRITE_12:
      if (s->cdb_len < 12)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = uabe32_to_h (&s->cdb[2]);
      count = uabe32_to_h (&s->cdb[6]);

      return uxscsi_write (s, lba, count);

    case SCSIOP_WRITE_16:
      if (s->cdb_len < 16)
        return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);

      lba = uabe64_to_h (&s->cdb[2]);
      count = uabe32_to_h (&s->cdb[10]);

      return uxscsi_write (s, lba, count);
	  
#ifdef __APPLE__
    case SCSIOP_INQUIRY:
      {
        const uint8_t standard_inquiry_cdb[6] =
        { SCSIOP_INQUIRY, 0x00, 0x00, 0x00, 0x24, 0x00 };
        const uint8_t evpd_supported_inquiry_cdb[6] =
        { SCSIOP_INQUIRY, 0x01, 0x00, 0x00, 0x40, 0x00 };
        if (s->cdb_len < 6)
          return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
        if (0 == memcmp(s->cdb, standard_inquiry_cdb, 6)) {
          //standard inquiry - get the serial number etc and craft the response
          s->read_len = uxscsi_inquiry(s->read_ptr, s->read_len);
          return success (s);
        } else if (0 == memcmp(s->cdb, evpd_supported_inquiry_cdb, 4)
                   && s->cdb[5] == evpd_supported_inquiry_cdb[5]) {
          // Don't support any EVPD, empty response
          s->read_len = 0;
          return success (s);
        }
      }
#endif
    }
  return check_condition (s, SCSISK_ILLEGAL_REQUEST, 0, 0);
}


int
uxscsi_start (UXSCSI * s, BlockDriverState * bs,
              size_t c_len, void *c_ptr,
              size_t w_len, void *w_ptr,
              size_t r_len, void *r_ptr,
              size_t s_len, void *s_ptr, UXSCSI_callback * cb, void *cb_arg)
{
  int ret;


  if (c_len < 6)
    return -1;

  s->bs = bs;

  s->cdb = c_ptr;
  s->cdb_len = c_len;

  s->write_ptr = w_ptr;
  s->write_len = w_len;

  s->read_ptr = r_ptr;
  s->read_len = r_len;

  s->sense_ptr = s_ptr;
  s->sense_len = s_len;


  s->cb = cb;
  s->cb_arg = cb_arg;



  ret = uxscsi_parse (s);

  return ret;
}
