/*
 * Copyright (c) 2010-2014 Wind River Systems, Inc.
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <zephyr/kernel.h>
#include <zephyr/linker/linker-defs.h>
#include "chacha20.h"

#ifdef CONFIG_REQUIRES_STACK_CANARIES
#ifdef CONFIG_STACK_CANARIES_TLS
extern Z_THREAD_LOCAL volatile uintptr_t __stack_chk_guard;
#else
extern volatile uintptr_t __stack_chk_guard;
#endif /* CONFIG_STACK_CANARIES_TLS */
#endif /* CONFIG_REQUIRES_STACK_CANARIES */


static void decode_data_section(void *data_start, int size_of_buffer)
{
    // imp data decryption here
    struct chacha20_context ctx;
    char key[32] = {};
    char nonce[12] = {};
    memset(nonce, 0, sizeof(nonce));
    
    key[0]  = 0xe3;
    key[1]  = 0x82;
    key[2]  = 0x84;
    key[3]  = 0xe3;
    key[4]  = 0x82;
    key[5]  = 0x8a;
    key[6]  = 0xe3;
    key[7]  = 0x81;
    key[8]  = 0xbe;
    key[9]  = 0xe3;
    key[10] = 0x81;
    key[11] = 0x99;
    key[12] = 0xe3;
    key[13] = 0x81;
    key[14] = 0xad;
    key[15] = 0xe3;
    key[16] = 0x82;
    key[17] = 0x84;
    key[18] = 0xe3;
    key[19] = 0x82;
    key[20] = 0x8a;
    key[21] = 0xe3;
    key[22] = 0x81;
    key[23] = 0xbe;
    key[24] = 0xe3;
    key[25] = 0x81;
    key[26] = 0x99;
    key[27] = 0xe3;
    key[28] = 0x81;
    key[29] = 0xad;
    key[30] = 0x0;
    key[31] = 0x0;

    chacha20_init_context(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, data_start, size_of_buffer);
}

/**
 * @brief Copy the data section from ROM to RAM
 *
 * This routine copies the data section from ROM to RAM.
 */
void z_data_copy(void)
{
	memcpy(&__data_region_start, &__data_region_load_start,
		       __data_region_end - __data_region_start);
    
    void *start_addr = &__rodata_region_start;
    void *end_addr = &__rodata_region_end;
    decode_data_section(start_addr, end_addr - start_addr);

#ifdef CONFIG_ARCH_HAS_RAMFUNC_SUPPORT
	memcpy(&__ramfunc_region_start, &__ramfunc_load_start,
		       __ramfunc_end - __ramfunc_region_start);
#endif /* CONFIG_ARCH_HAS_RAMFUNC_SUPPORT */
#if DT_NODE_HAS_STATUS_OKAY(DT_CHOSEN(zephyr_ccm))
	memcpy(&__ccm_data_start, &__ccm_data_rom_start,
		       __ccm_data_end - __ccm_data_start);
#endif
#if DT_NODE_HAS_STATUS_OKAY(DT_CHOSEN(zephyr_itcm))
	memcpy(&__itcm_start, &__itcm_load_start,
		       (uintptr_t) &__itcm_size);
#endif
#if DT_NODE_HAS_STATUS_OKAY(DT_CHOSEN(zephyr_dtcm))
	memcpy(&__dtcm_data_start, &__dtcm_data_load_start,
		       __dtcm_data_end - __dtcm_data_start);
#endif
#ifdef CONFIG_CODE_DATA_RELOCATION
	extern void data_copy_xip_relocation(void);

	data_copy_xip_relocation();
#endif	/* CONFIG_CODE_DATA_RELOCATION */
#ifdef CONFIG_USERSPACE
#ifdef CONFIG_REQUIRES_STACK_CANARIES
	/* stack canary checking is active for all C functions.
	 * __stack_chk_guard is some uninitialized value living in the
	 * app shared memory sections. Preserve it, and don't make any
	 * function calls to perform the memory copy. The true canary
	 * value gets set later in z_cstart().
	 */
	uintptr_t guard_copy = __stack_chk_guard;
	uint8_t *src = (uint8_t *)&_app_smem_rom_start;
	uint8_t *dst = (uint8_t *)&_app_smem_start;
	uint32_t count = _app_smem_end - _app_smem_start;

	guard_copy = __stack_chk_guard;
	while (count > 0) {
		*(dst++) = *(src++);
		count--;
	}
	__stack_chk_guard = guard_copy;
#else
	memcpy(&_app_smem_start, &_app_smem_rom_start,
		       _app_smem_end - _app_smem_start);
#endif /* CONFIG_REQUIRES_STACK_CANARIES */
#endif /* CONFIG_USERSPACE */
}