/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2017-2020 Linaro LTD
 * Copyright (c) 2017-2019 JUUL Labs
 * Copyright (c) 2019-2021 Arm Limited
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef H_BOOTUTIL_PRIV_
#define H_BOOTUTIL_PRIV_

#include <string.h>

#include "sysflash/sysflash.h"

#include <flash_map_backend/flash_map_backend.h>

#include "bootutil/bootutil.h"
#include "bootutil/image.h"
#include "bootutil/fault_injection_hardening.h"
#include "mcuboot_config/mcuboot_config.h"

#ifdef MCUBOOT_ENC_IMAGES
#include "bootutil/enc_key.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct flash_area;

#define BOOT_TMPBUF_SZ  256

#define NO_ACTIVE_SLOT UINT32_MAX

/** Number of image slots in flash; currently limited to two. */
#if defined(MCUBOOT_SINGLE_APPLICATION_SLOT) || defined(MCUBOOT_SINGLE_APPLICATION_SLOT_RAM_LOAD)
#define BOOT_NUM_SLOTS                  1
#else
#define BOOT_NUM_SLOTS                  2
#endif

#if (defined(MCUBOOT_OVERWRITE_ONLY) + \
     defined(MCUBOOT_SWAP_USING_MOVE) + \
     defined(MCUBOOT_SWAP_USING_OFFSET) + \
     defined(MCUBOOT_DIRECT_XIP) + \
     defined(MCUBOOT_RAM_LOAD) + \
     defined(MCUBOOT_FIRMWARE_LOADER) + \
     defined(MCUBOOT_SWAP_USING_SCRATCH)) > 1
#error "Please enable only one of MCUBOOT_OVERWRITE_ONLY, MCUBOOT_SWAP_USING_MOVE, MCUBOOT_SWAP_USING_OFFSET, MCUBOOT_DIRECT_XIP, MCUBOOT_RAM_LOAD or MCUBOOT_FIRMWARE_LOADER"
#endif

#if !defined(MCUBOOT_DIRECT_XIP) && \
     defined(MCUBOOT_DIRECT_XIP_REVERT)
#error "MCUBOOT_DIRECT_XIP_REVERT cannot be enabled unless MCUBOOT_DIRECT_XIP is used"
#endif

#if !defined(MCUBOOT_OVERWRITE_ONLY) && \
    !defined(MCUBOOT_SWAP_USING_MOVE) && \
    !defined(MCUBOOT_SWAP_USING_OFFSET) && \
    !defined(MCUBOOT_DIRECT_XIP) && \
    !defined(MCUBOOT_RAM_LOAD) && \
    !defined(MCUBOOT_SINGLE_APPLICATION_SLOT) && \
    !defined(MCUBOOT_FIRMWARE_LOADER)
#define MCUBOOT_SWAP_USING_SCRATCH 1
#endif

#if defined(MCUBOOT_SWAP_USING_OFFSET)
#define BOOT_STATUS_OP_SWAP     1
#else
#define BOOT_STATUS_OP_MOVE     1
#define BOOT_STATUS_OP_SWAP     2
#endif

#if (BOOT_IMAGE_NUMBER > 1)
#define IMAGES_ITER(x) for ((x) = 0; (x) < BOOT_IMAGE_NUMBER; ++(x))
#else
#define IMAGES_ITER(x)
#endif

/*
 * Maintain state of copy progress.
 */
struct boot_status {
    uint32_t idx;         /* Which area we're operating on */
    uint8_t state;        /* Which part of the swapping process are we at */
    uint8_t op;           /* What operation are we performing? */
    uint8_t use_scratch;  /* Are status bytes ever written to scratch? */
    uint8_t swap_type;    /* The type of swap in effect */
    uint32_t swap_size;   /* Total size of swapped image */
#ifdef MCUBOOT_ENC_IMAGES
    uint8_t enckey[BOOT_NUM_SLOTS][BOOT_ENC_KEY_ALIGN_SIZE];
#if MCUBOOT_SWAP_SAVE_ENCTLV
    uint8_t enctlv[BOOT_NUM_SLOTS][BOOT_ENC_TLV_ALIGN_SIZE];
#endif
#endif
    int source;           /* Which slot contains swap status metadata */
};

#define BOOT_STATUS_IDX_0   1

#define BOOT_STATUS_STATE_0 1
#define BOOT_STATUS_STATE_1 2
#define BOOT_STATUS_STATE_2 3

/**
 * End-of-image slot structure.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~                                                               ~
 *  ~    Swap status (BOOT_MAX_IMG_SECTORS * min-write-size * 3)    ~
 *  ~                                                               ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Encryption key 0 (16 octets) [*]              |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    0xff padding as needed                     |
 *  |  (BOOT_MAX_ALIGN minus 16 octets from Encryption key 0) [*]   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                 Encryption key 1 (16 octets) [*]              |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    0xff padding as needed                     |
 *  |  (BOOT_MAX_ALIGN minus 16 octets from Encryption key 1) [*]   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Swap size (4 octets)                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    0xff padding as needed                     |
 *  |        (BOOT_MAX_ALIGN minus 4 octets from Swap size)         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Swap info   |  0xff padding (BOOT_MAX_ALIGN minus 1 octet)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Copy done   |  0xff padding (BOOT_MAX_ALIGN minus 1 octet)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Image OK    |  0xff padding (BOOT_MAX_ALIGN minus 1 octet)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    0xff padding as needed                     |
 *  |         (BOOT_MAX_ALIGN minus 16 octets from MAGIC)           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       MAGIC (16 octets)                       |
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * [*]: Only present if the encryption option is enabled
 *      (`MCUBOOT_ENC_IMAGES`).
 */

union boot_img_magic_t
{
    struct {
        uint16_t align;
        uint8_t magic[14];
    };
    uint8_t val[16];
};

extern const union boot_img_magic_t boot_img_magic;

#define BOOT_IMG_MAGIC  (boot_img_magic.val)

#if BOOT_MAX_ALIGN == 8
#define BOOT_IMG_ALIGN  (BOOT_MAX_ALIGN)
#else
#define BOOT_IMG_ALIGN  (boot_img_magic.align)
#endif

_Static_assert(sizeof(boot_img_magic) == BOOT_MAGIC_SZ, "Invalid size for image magic");

#if !defined(MCUBOOT_DIRECT_XIP) && !defined(MCUBOOT_RAM_LOAD)
#define ARE_SLOTS_EQUIVALENT()    0
#else
#define ARE_SLOTS_EQUIVALENT()    1

#if defined(MCUBOOT_DIRECT_XIP) && defined(MCUBOOT_ENC_IMAGES)
#error "Image encryption (MCUBOOT_ENC_IMAGES) is not supported when MCUBOOT_DIRECT_XIP is selected."
#endif /* MCUBOOT_DIRECT_XIP && MCUBOOT_ENC_IMAGES */
#endif /* MCUBOOT_DIRECT_XIP || MCUBOOT_RAM_LOAD */

#define BOOT_MAX_IMG_SECTORS       MCUBOOT_MAX_IMG_SECTORS

#define BOOT_LOG_IMAGE_INFO(slot, hdr)                                    \
    BOOT_LOG_INF("%-9s slot: version=%u.%u.%u+%u",                        \
                 ((slot) == BOOT_PRIMARY_SLOT) ? "Primary" : "Secondary", \
                 (hdr)->ih_ver.iv_major,                                  \
                 (hdr)->ih_ver.iv_minor,                                  \
                 (hdr)->ih_ver.iv_revision,                               \
                 (hdr)->ih_ver.iv_build_num)

#if MCUBOOT_SWAP_USING_MOVE
#define BOOT_STATUS_MOVE_STATE_COUNT    1
#define BOOT_STATUS_SWAP_STATE_COUNT    2
#define BOOT_STATUS_STATE_COUNT         (BOOT_STATUS_MOVE_STATE_COUNT + BOOT_STATUS_SWAP_STATE_COUNT)
#elif MCUBOOT_SWAP_USING_OFFSET
#define BOOT_STATUS_SWAP_STATE_COUNT    2
#define BOOT_STATUS_STATE_COUNT         BOOT_STATUS_SWAP_STATE_COUNT
#else
#define BOOT_STATUS_STATE_COUNT         3
#endif

/** Maximum number of image sectors supported by the bootloader. */
#define BOOT_STATUS_MAX_ENTRIES         BOOT_MAX_IMG_SECTORS

#define BOOT_PRIMARY_SLOT               0
#define BOOT_SECONDARY_SLOT             1

#define BOOT_STATUS_SOURCE_NONE         0
#define BOOT_STATUS_SOURCE_SCRATCH      1
#define BOOT_STATUS_SOURCE_PRIMARY_SLOT 2

/**
 * Compatibility shim for flash sector type.
 *
 * This can be deleted when flash_area_to_sectors() is removed.
 */
#ifdef MCUBOOT_USE_FLASH_AREA_GET_SECTORS
typedef struct flash_sector boot_sector_t;
#else
typedef struct flash_area boot_sector_t;
#endif

/** Private state maintained during boot. */
struct boot_loader_state {
    struct {
        struct image_header hdr;
        const struct flash_area *area;
        boot_sector_t *sectors;
        uint32_t num_sectors;
    } imgs[BOOT_IMAGE_NUMBER][BOOT_NUM_SLOTS];

#if MCUBOOT_SWAP_USING_SCRATCH
    struct {
        const struct flash_area *area;
        boot_sector_t *sectors;
        uint32_t num_sectors;
    } scratch;
#endif

    uint8_t swap_type[BOOT_IMAGE_NUMBER];
    uint32_t write_sz;

#if defined(MCUBOOT_SWAP_USING_OFFSET)
    uint32_t secondary_offset[BOOT_IMAGE_NUMBER];
#if defined(MCUBOOT_BOOTSTRAP)
    bool bootstrap_secondary_offset_set[BOOT_IMAGE_NUMBER];
#endif
#endif

#if defined(MCUBOOT_ENC_IMAGES)
    struct enc_key_data enc[BOOT_IMAGE_NUMBER][BOOT_NUM_SLOTS];
#endif

#if (BOOT_IMAGE_NUMBER > 1)
    uint8_t curr_img_idx;
    bool img_mask[BOOT_IMAGE_NUMBER];
#endif

#if defined(MCUBOOT_DIRECT_XIP) || defined(MCUBOOT_RAM_LOAD)
    struct slot_usage_t {
        /* Index of the slot chosen to be loaded */
        uint32_t active_slot;
        bool slot_available[BOOT_NUM_SLOTS];
#if defined(MCUBOOT_RAM_LOAD)
        /* Image destination and size for the active slot */
        uint32_t img_dst;
        uint32_t img_sz;
#endif
#if defined(MCUBOOT_DIRECT_XIP_REVERT) || defined(MCUBOOT_RAM_LOAD_REVERT)
        /* Swap status for the active slot */
        struct boot_swap_state swap_state;
#endif
    } slot_usage[BOOT_IMAGE_NUMBER];
#endif /* MCUBOOT_DIRECT_XIP || MCUBOOT_RAM_LOAD */
};

struct boot_sector_buffer {
    boot_sector_t primary[BOOT_IMAGE_NUMBER][BOOT_MAX_IMG_SECTORS];
    boot_sector_t secondary[BOOT_IMAGE_NUMBER][BOOT_MAX_IMG_SECTORS];
#if MCUBOOT_SWAP_USING_SCRATCH
    boot_sector_t scratch[BOOT_MAX_IMG_SECTORS];
#endif
};

/* The function is intended for verification of image hash against
 * provided signature.
 */
fih_ret bootutil_verify_sig(uint8_t *hash, uint32_t hlen, uint8_t *sig,
                            size_t slen, uint8_t key_id);

/* The function is intended for direct verification of image
 * against provided signature.
 */
fih_ret bootutil_verify_img(uint8_t *img, uint32_t size,
                            uint8_t *sig, size_t slen, uint8_t key_id);

fih_ret boot_fih_memequal(const void *s1, const void *s2, size_t n);

const struct flash_area *boot_find_status(const struct boot_loader_state *state,
                                          int image_index);
int boot_magic_compatible_check(uint8_t tbl_val, uint8_t val);
uint32_t boot_status_sz(uint32_t min_write_sz);
uint32_t boot_trailer_sz(uint32_t min_write_sz);
/* Get offset of trailer aligned to either device erase unit or alignment
 * depending on whether device has erase or not.
 */
int boot_trailer_scramble_offset(const struct flash_area *fa, size_t alignment,
                                 size_t *off);
/* Get size of header aligned to device erase unit or write block,
 * depending on whether device has erase or not.
 */
int boot_header_scramble_off_sz(const struct flash_area *fa, int slot, size_t *off,
                                size_t *size);
int boot_status_entries(int image_index, const struct flash_area *fap);
uint32_t boot_status_off(const struct flash_area *fap);
int boot_read_swap_state(const struct flash_area *fap,
                         struct boot_swap_state *state);
int boot_write_magic(const struct flash_area *fap);
int boot_write_status(const struct boot_loader_state *state, struct boot_status *bs);
int boot_write_copy_done(const struct flash_area *fap);
int boot_write_image_ok(const struct flash_area *fap);
int boot_write_swap_info(const struct flash_area *fap, uint8_t swap_type,
                         uint8_t image_num);
int boot_write_swap_size(const struct flash_area *fap, uint32_t swap_size);
int boot_write_trailer(const struct flash_area *fap, uint32_t off,
                       const uint8_t *inbuf, uint8_t inlen);
int boot_write_trailer_flag(const struct flash_area *fap, uint32_t off,
                            uint8_t flag_val);
int boot_read_swap_size(const struct flash_area *fap, uint32_t *swap_size);
int boot_slots_compatible(struct boot_loader_state *state);
uint32_t boot_status_internal_off(const struct boot_status *bs, int elem_sz);
int boot_read_image_header(struct boot_loader_state *state, int slot,
                           struct image_header *out_hdr, struct boot_status *bs);
#if defined(MCUBOOT_SWAP_USING_OFFSET) && defined(MCUBOOT_ENC_IMAGES)
int boot_copy_region(struct boot_loader_state *state,
                     const struct flash_area *fap_src,
                     const struct flash_area *fap_dst,
                     uint32_t off_src, uint32_t off_dst, uint32_t sz, uint32_t sector_off);
#else
int boot_copy_region(struct boot_loader_state *state,
                     const struct flash_area *fap_src,
                     const struct flash_area *fap_dst,
                     uint32_t off_src, uint32_t off_dst, uint32_t sz);
#endif
/* Prepare for write device that requires erase prior to write. This will
 * do nothing on devices without erase requirement.
 */
int boot_erase_region(const struct flash_area *fap, uint32_t off, uint32_t sz, bool backwards);
/* Similar to boot_erase_region but will always remove data */
int boot_scramble_region(const struct flash_area *fap, uint32_t off, uint32_t sz, bool backwards);
/* Makes slot unbootable, either by scrambling header magic, header sector
 * or entire slot, depending on settings.
 * Note: slot is passed here becuase at this point there is no function
 * matching flash_area object to slot */
int boot_scramble_slot(const struct flash_area *fap, int slot);
bool boot_status_is_reset(const struct boot_status *bs);

#ifdef MCUBOOT_ENC_IMAGES
int boot_write_enc_key(const struct flash_area *fap, uint8_t slot,
                       const struct boot_status *bs);
int boot_read_enc_key(const struct flash_area *fap, uint8_t slot,
                      struct boot_status *bs);
#endif

#if MCUBOOT_SWAP_USING_SCRATCH
/*
 * Similar to `boot_trailer_sz` but this function returns the space used to
 * store status in the scratch partition. The scratch partition only stores
 * status during the swap of the last sector from primary/secondary (which
 * is the first swap operation) and thus only requires space for one swap.
 */
uint32_t boot_scratch_trailer_sz(uint32_t min_write_sz);
#endif

/**
 * Checks that a buffer is erased according to what the erase value for the
 * flash device provided in `flash_area` is.
 *
 * @returns true if the buffer is erased; false if any of the bytes is not
 * erased, or when buffer is NULL, or when len == 0.
 */
bool bootutil_buffer_is_erased(const struct flash_area *area,
                               const void *buffer, size_t len);

/**
 * Opens the flash areas of all images.
 *
 * @param state Bootloader state.
 *
 * @return 0 on success, another value otherwise.
 */
int boot_open_all_flash_areas(struct boot_loader_state *state);

/**
 * Closes the flash areas of all images.
 *
 * @param state Bootloader state.
 */
void boot_close_all_flash_areas(struct boot_loader_state *state);

#if !defined(MCUBOOT_DIRECT_XIP) && !defined(MCUBOOT_RAM_LOAD)
/**
 * Determines the sector layout of both image slots and the scratch area.
 *
 * This information is necessary for calculating the number of bytes to erase
 * and copy during an image swap. The information collected during this
 * function is used to populate the state.
 *
 * @param state   Bootloader state.
 * @param sectors Buffers where to store the sector layout. If NULL, the statically-allocated
 *                buffers in loader.c will be used.
 */
int boot_read_sectors(struct boot_loader_state *state, struct boot_sector_buffer *sectors);
#endif

/**
 * Safe (non-overflowing) uint32_t addition.  Returns true, and stores
 * the result in *dest if it can be done without overflow.  Otherwise,
 * returns false.
 */
static inline bool boot_u32_safe_add(uint32_t *dest, uint32_t a, uint32_t b)
{
    /*
     * "a + b <= UINT32_MAX", subtract 'b' from both sides to avoid
     * the overflow.
     */
    if (a > UINT32_MAX - b) {
        return false;
    } else {
        *dest = a + b;
        return true;
    }
}

/**
 * Safe (non-overflowing) uint16_t addition.  Returns true, and stores
 * the result in *dest if it can be done without overflow.  Otherwise,
 * returns false.
 */
static inline bool boot_u16_safe_add(uint16_t *dest, uint16_t a, uint16_t b)
{
    uint32_t tmp = a + b;
    if (tmp > UINT16_MAX) {
        return false;
    } else {
        *dest = tmp;
        return true;
    }
}

/*
 * Accessors for the contents of struct boot_loader_state.
 */

/* These are macros so they can be used as lvalues. */
#if (BOOT_IMAGE_NUMBER > 1)
#define BOOT_CURR_IMG(state) ((state)->curr_img_idx)
#else
#define BOOT_CURR_IMG(state) 0
#endif
#ifdef MCUBOOT_ENC_IMAGES
#define BOOT_CURR_ENC(state) ((state)->enc[BOOT_CURR_IMG(state)])
#else
#define BOOT_CURR_ENC(state) NULL
#endif
#define BOOT_IMG(state, slot) ((state)->imgs[BOOT_CURR_IMG(state)][(slot)])
#define BOOT_IMG_AREA(state, slot) (BOOT_IMG(state, slot).area)
#define BOOT_WRITE_SZ(state) ((state)->write_sz)
#define BOOT_SWAP_TYPE(state) ((state)->swap_type[BOOT_CURR_IMG(state)])
#define BOOT_TLV_OFF(hdr) ((hdr)->ih_hdr_size + (hdr)->ih_img_size)

#define BOOT_IS_UPGRADE(swap_type)             \
    (((swap_type) == BOOT_SWAP_TYPE_TEST) ||   \
     ((swap_type) == BOOT_SWAP_TYPE_REVERT) || \
     ((swap_type) == BOOT_SWAP_TYPE_PERM))

static inline struct image_header*
boot_img_hdr(struct boot_loader_state *state, size_t slot)
{
    return &BOOT_IMG(state, slot).hdr;
}

static inline size_t
boot_img_num_sectors(const struct boot_loader_state *state, size_t slot)
{
    return BOOT_IMG(state, slot).num_sectors;
}

/*
 * Offset of the slot from the beginning of the flash device.
 */
static inline uint32_t
boot_img_slot_off(struct boot_loader_state *state, size_t slot)
{
    return flash_area_get_off(BOOT_IMG_AREA(state, slot));
}

#ifndef MCUBOOT_USE_FLASH_AREA_GET_SECTORS

static inline size_t
boot_img_sector_size(const struct boot_loader_state *state,
                     size_t slot, size_t sector)
{
    return flash_area_get_size(&BOOT_IMG(state, slot).sectors[sector]);
}

/*
 * Offset of the sector from the beginning of the image, NOT the flash
 * device.
 */
static inline uint32_t
boot_img_sector_off(const struct boot_loader_state *state, size_t slot,
                    size_t sector)
{
    return flash_area_get_off(&BOOT_IMG(state, slot).sectors[sector]) -
           flash_area_get_off(&BOOT_IMG(state, slot).sectors[0]);
}

#else  /* defined(MCUBOOT_USE_FLASH_AREA_GET_SECTORS) */

static inline size_t
boot_img_sector_size(const struct boot_loader_state *state,
                     size_t slot, size_t sector)
{
    return flash_sector_get_size(&BOOT_IMG(state, slot).sectors[sector]);
}

static inline uint32_t
boot_img_sector_off(const struct boot_loader_state *state, size_t slot,
                    size_t sector)
{
    return flash_sector_get_off(&BOOT_IMG(state, slot).sectors[sector]) -
           flash_sector_get_off(&BOOT_IMG(state, slot).sectors[0]);
}

#endif  /* !defined(MCUBOOT_USE_FLASH_AREA_GET_SECTORS) */

#ifdef MCUBOOT_RAM_LOAD
#   ifdef __BOOTSIM__

/* Query for the layout of a RAM buffer appropriate for holding the
 * image.  This will be per-test-thread, and therefore must be queried
 * through this call. */
struct bootsim_ram_info {
    uint32_t start;
    uint32_t size;
    uintptr_t base;
};
struct bootsim_ram_info *bootsim_get_ram_info(void);

#define IMAGE_GET_FIELD(field) (bootsim_get_ram_info()->field)
#define IMAGE_RAM_BASE IMAGE_GET_FIELD(base)
#define IMAGE_EXECUTABLE_RAM_START IMAGE_GET_FIELD(start)
#define IMAGE_EXECUTABLE_RAM_SIZE IMAGE_GET_FIELD(size)

#   else
#       define IMAGE_RAM_BASE ((uintptr_t)0)
#   endif

#define LOAD_IMAGE_DATA(hdr, fap, start, output, size)       \
    (memcpy((output),(void*)(IMAGE_RAM_BASE + (hdr)->ih_load_addr + (start)), \
    (size)), 0)

int boot_load_image_to_sram(struct boot_loader_state *state);
#else
#define IMAGE_RAM_BASE ((uintptr_t)0)

#define LOAD_IMAGE_DATA(hdr, fap, start, output, size)       \
    (flash_area_read((fap), (start), (output), (size)))

#endif /* MCUBOOT_RAM_LOAD */

uint32_t bootutil_max_image_size(struct boot_loader_state *state, const struct flash_area *fap);

int boot_read_image_size(struct boot_loader_state *state, int slot,
                         uint32_t *size);

/* Helper macro to avoid compile errors with systems that do not
 * provide function to check device type.
 * Note: it used to be inline, but somehow compiler would not
 * optimize out branches that were impossible when this evaluated to
 * just "true".
 */
#if defined(MCUBOOT_SUPPORT_DEV_WITHOUT_ERASE) && defined(MCUBOOT_SUPPORT_DEV_WITH_ERASE)
#define device_requires_erase(fa) (flash_area_erase_required(fa))
#elif defined(MCUBOOT_SUPPORT_DEV_WITHOUT_ERASE)
#define device_requires_erase(fa) (false)
#else
#define device_requires_erase(fa) (true)
#endif

#ifdef __cplusplus
}
#endif

#endif
