/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *	Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *	Contributed by Mike Johnston <johnston@intel.com>
 *	Contributed by Chris Ahna <christopher.j.ahna@intel.com>
 *
 * This file is part of the ELILO, the EFI Linux boot loader.
 *
 *  ELILO is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  ELILO is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ELILO; see the file COPYING.  If not, write to the Free
 *  Software Foundation, 59 Temple Place - Suite 330, Boston, MA
 *  02111-1307, USA.
 *
 * Please check out the elilo.txt for complete documentation on how
 * to use this program.
 */

/*
 * this file contains all the IA-32 specific code expected by generic loader
 */
#include <efi.h>
#include <efilib.h>

#include "elilo.h"
#include "loader.h"

#include "rmswitch.h"

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/* extern loader_ops_t plain_loader, gzip_loader; */

efi_ia32_boot_params_t efi_ia32_bp;


/*
 * Descriptor table base addresses & limits for Linux startup.
 */

dt_addr_t gdt_addr = { 0x800, 0x94000 };
dt_addr_t idt_addr = { 0, 0 };

/*
 * Initial GDT layout for Linux startup.
 */

UINT16 init_gdt[] = {
	/* gdt[0]: dummy */
	0, 0, 0, 0, 
	
	/* gdt[1]: unused */
	0, 0, 0, 0,

	/* gdt[2]: code */
	0xFFFF,		/* 4Gb - (0x100000*0x1000 = 4Gb) */
	0x0000,		/* base address=0 */
	0x9A00,		/* code read/exec */
	0x00CF,		/* granularity=4096, 386 (+5th nibble of limit) */

	/* gdt[3]: data */
	0xFFFF,		/* 4Gb - (0x100000*0x1000 = 4Gb) */
	0x0000,		/* base address=0 */
	0x9200,		/* data read/write */
	0x00CF,		/* granularity=4096, 386 (+5th nibble of limit) */
};

UINTN sizeof_init_gdt = sizeof init_gdt;


/*
 * Highest available base memory address.
 *
 * For traditional kernels and loaders this is always at 0x90000.
 * For updated kernels and loaders this is computed by taking the
 * highest available base memory address and rounding down to the
 * nearest 64 kB boundary and then subtracting 64 kB.
 *
 * A non-compressed kernel is automatically assumed to be an updated
 * kernel.  A compressed kernel that has bit 6 (0x40) set in the
 * loader_flags field is also assumed to be an updated kernel.
 */

UINTN high_base_mem = 0x90000;

/*
 * Highest available extended memory address.
 *
 * This is computed by taking the highest available extended memory
 * address and rounding down to the nearest EFI_PAGE_SIZE (usually
 * 4 kB) boundary.  The ia32 Linux kernel can only support up to
 * 2 GB (AFAIK).
 */

UINTN high_ext_mem = 32 * 1024 * 1024;

/*
 * Starting location and size of runtime memory blocks.
 */

boot_params_t *param_start = NULL;
UINTN param_size = 0;

VOID *kernel_start = (VOID *)0x100000;	/* 1M */
UINTN kernel_size = 0x200000;		/* 2M (largest x86 kernel image) */

VOID *initrd_start = NULL;
UINTN initrd_size = 0;

/*
 * Boot parameters can be relocated if TRUE.
 * Boot parameters must be placed at 0x90000 if FALSE.
 *
 * This will be set to TRUE if bit 6 (0x40) is set in the loader_flags
 * field in a compressed x86 boot format kernel.  This will also be set
 * to TRUE if the kernel is an uncompressed ELF32 image.
 *
 * To remote boot w/ the universal network driver and a 16-bit UNDI
 * this must be set to TRUE.
 */

BOOLEAN can_reloc_boot_params = FALSE;

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
static INTN
probe_bzImage_boot(CHAR16 *kname)
{
	EFI_STATUS efi_status;
	UINTN size;
	fops_fd_t fd;
	UINT8 bootsect[512];

	DBG_PRT((L"probe_bzImage_boot()\n"));

	if (!kname) {
		ERR_PRT((L"kname == %xh", kname));
		free_kmem();
		return -1;
	}

	/*
	 * Open kernel image.
	 */

	DBG_PRT((L"opening %s...\n", kname));

	efi_status = fops_open(kname, &fd);

	if (EFI_ERROR(efi_status)) {
		ERR_PRT((L"Could not open %s.", kname));
		free_kmem();
		return -1;
	}

	/*
	 * Read boot sector.
	 */

	DBG_PRT((L"\nreading boot sector...\n"));

	size = sizeof bootsect;
	efi_status = fops_read(fd, bootsect, &size);

	if (EFI_ERROR(efi_status) || size != sizeof bootsect) {
		ERR_PRT((L"Could not read boot sector from %s.", kname));
		fops_close(fd);
		free_kmem();
		return -1;
	}

	/*
	 * Verify boot sector signature.
	 */

	if (bootsect[0x1FE] != 0x55 || bootsect[0x1FF] != 0xAA) {
		ERR_PRT((L"%s is not a bzImage kernel image.\n", kname));
		fops_close(fd);
		free_kmem();
		return -1;
	}

	/*
	 * Check for out of range setup data size.
	 * Will almost always be 7, but we will accept 1 to 64.
	 */

	DBG_PRT((L"bootsect[1F1h] == %d setup sectors\n", bootsect[0x1F1]));

	if (bootsect[0x1F1] < 1 || bootsect[0x1F1] > 64) {
		ERR_PRT((L"%s is not a valid bzImage kernel image.",
			kname));

		fops_close(fd);
		free_kmem();
		return -1;
	}

	/*
	 * Allocate and read setup data.
	 */

	DBG_PRT((L"reading setup data...\n"));

	param_size = (bootsect[0x1F1] + 1) * 512;
	//param_start = alloc(param_size, EfiBootServicesData);
	param_start = alloc(param_size, EfiLoaderData);

	DBG_PRT((L"param_size=%d param_start=%x", param_size, param_start));

	if (!param_start) {
		ERR_PRT((L"Could not allocate %d bytes of setup data.",
			param_size));

		fops_close(fd);
		free_kmem();
		return -1;
	}

	CopyMem(param_start, bootsect, sizeof bootsect);

	size = param_size - 512;
	efi_status = fops_read(fd, ((UINT8 *)param_start) + 512, &size);

	if (EFI_ERROR(efi_status) || size != param_size - 512) {
		ERR_PRT((L"Could not read %d bytes of setup data.",
			param_size - 512));

		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		free_kmem();
		return -1;
	}

	/*
	 * Check for setup data signature.
	 */

	{ UINT8 *c = ((UINT8 *)param_start)+514;
	DBG_PRT((L"param_start(c=%x): %c-%c-%c-%c", c, (CHAR16)c[0],(CHAR16) c[1], (CHAR16)c[2], (CHAR16)c[3]));
	}
	if (CompareMem(((UINT8 *)param_start) + 514, "HdrS", 4)) {
		ERR_PRT((L"%s does not have a setup signature.",
			kname));

		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		free_kmem();
		return -1;
	}

	/*
	 * Allocate memory for kernel.
	 */

	if (alloc_kmem(kernel_start, EFI_SIZE_TO_PAGES(kernel_size))) {
		ERR_PRT((L"Could not allocate kernel memory."));
		return -1;
	} else {
		VERB_PRT(3, Print(L"kernel_start: 0x%x  kernel_size: %d\n", kernel_start, kernel_size));
	}

	/*
	 * Now read the rest of the kernel image into memory.
	 */

	DBG_PRT((L"reading kernel image...\n"));

	size = kernel_size;

	efi_status = fops_read(fd, kernel_start, &size);

	if (EFI_ERROR(efi_status) || size < 0x10000) {
		ERR_PRT((L"Error reading kernel image %s.", kname));
		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		free_kmem();
		return -1;
	}

	DBG_PRT((L"kernel image read:  %d bytes, %d Kbytes\n", size, size / 1024));

	/*
	 * Boot sector, setup data and kernel image loaded.
	 */

	fops_close(fd);
	return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
static INTN
load_bzImage_boot(CHAR16 *kname, kdesc_t *kd)
{
	DBG_PRT((L"load_bzImage_boot()\n"));

	if (!kname || !kd) {
		ERR_PRT((L"kname=0x%x  kd=0x%x", kname, kd));

		free(param_start);
		param_start = NULL;
		param_size = 0;
		free_kmem();
		return -1;
	}

	kd->kstart = kd->kentry = kernel_start;
	kd->kend = ((UINT8 *)kd->kstart) + kernel_size;

	DBG_PRT((L"kstart=0x%x  kentry=0x%x  kend=0x%x\n", kd->kstart, kd->kentry, kd->kend));

	return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
static loader_ops_t loader_bzImage_boot = {
	NULL,
	L"loader_bzImage_boot",
	&probe_bzImage_boot,
	&load_bzImage_boot
};

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
INTN
sysdeps_init(EFI_HANDLE dev)
{

	DBG_PRT((L"sysdeps_init()\n"));

	/*
	 * Register our loader(s)...
	 */

	loader_register(&loader_bzImage_boot);
	/* loader_register(&plain_loader); */	
	/* loader_register(&gzip_loader); */


	return 0;
}

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/*
 * initrd_get_addr()
 *	Compute a starting address for the initial RAMdisk image.
 *	For now, this image is placed immediately after the end of
 *	the kernel memory.  Inside the start_kernel() code, the
 *	RAMdisk image will be relocated to the top of available
 *	extended memory.
 */
INTN
sysdeps_initrd_get_addr(kdesc_t *kd, memdesc_t *imem)
{
	DBG_PRT((L"initrd_get_addr()\n"));

	if (!kd || !imem) {
		ERR_PRT((L"kd=0x%x imem=0x%x", kd, imem));
		return -1;
	}

	VERB_PRT(3, Print(L"kstart=0x%x  kentry=0x%x  kend=0x%x\n", 
		kd->kstart, kd->kentry, kd->kend));

	imem->start_addr = kd->kend;

	VERB_PRT(3, Print(L"initrd start_addr=0x%x pgcnt=%d\n", imem->start_addr, imem->pgcnt));

	return 0;
}

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
VOID
sysdeps_free_boot_params(boot_params_t *bp)
{
	mmap_desc_t md;

	ZeroMem(&md, sizeof md);
	md.md = (VOID *)bp->s.efi_mem_map;
	free_memmap(&md);
}

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
/*
 * IA-32 specific boot parameters initialization routine
 */
INTN
sysdeps_create_boot_params(
	boot_params_t *bp,
	CHAR8 *cmdline,
	memdesc_t *initrd,
	UINTN *cookie)
{
	mmap_desc_t mdesc;
	EFI_STATUS efi_status;
	UINTN rows, cols;
	UINT8 row, col;
	UINT8 mode;
	UINT16 hdr_version;

	DBG_PRT((L"fill_boot_params()\n"));

	if (!bp || !cmdline || !initrd || !cookie) {
		ERR_PRT((L"bp=0x%x  cmdline=0x%x  initrd=0x%x cookie=0x%x",
			bp, cmdline, initrd, cookie));

		free(param_start);
		param_start = NULL;
		param_size = 0;
		free_kmem();
		return -1;
	}

	/*
	 * Copy temporary boot sector and setup data storage to
	 * elilo allocated boot parameter storage.  We only need
	 * the first two sectors (1K).  The rest of the storage
	 * can be used by the command line.
	 */

	CopyMem(bp, param_start, 0x2000);

	free(param_start);
	param_start = NULL;
	param_size = 0;

	/*
	 * Save off our header revision information.
	 */

	hdr_version = (bp->s.hdr_major << 8) | bp->s.hdr_minor;

	/*
	 * Clear out unused memory in boot sector image.
	 */

	bp->s.unused_1 = 0;
	bp->s.unused_2 = 0;
	ZeroMem(bp->s.unused_3, sizeof bp->s.unused_3);
	ZeroMem(bp->s.unused_4, sizeof bp->s.unused_4);
	ZeroMem(bp->s.unused_5, sizeof bp->s.unused_5);
	bp->s.unused_6 = 0;

	/*
	 * Tell kernel this was loaded by an advanced loader type.
	 * If this field is zero, the initrd_start and initrd_size
	 * fields are ignored by the kernel.
	 */

	bp->s.loader_type = LDRTYPE_ELILO;

	/*
	 * Setup command line information.
	 */

	bp->s.cmdline_magik = CMDLINE_MAGIK;
	bp->s.cmdline_offset = (UINT8 *)cmdline - (UINT8 *)bp;

	/*
	 * Setup hard drive parameters.
	 * %%TBD - It should be okay to zero fill the hard drive
	 * info buffers.  The kernel should do its own detection.
	 */

	ZeroMem(bp->s.hd0_info, sizeof bp->s.hd0_info);
	ZeroMem(bp->s.hd1_info, sizeof bp->s.hd1_info);

#if 0
	CopyMem(bp->s.hd0_info, *((VOID **)(0x41 * 4)),
		sizeof bp->s.hd0_info);

	CopyMem(bp->s.hd1_info, *((VOID **)(0x46 * 4)),
		sizeof bp->s.hd1_info);
#endif

	/*
	 * Memory info.
	 */

	bp->s.alt_mem_k = high_ext_mem / 1024;

	if (bp->s.alt_mem_k <= 65535) {
		bp->s.ext_mem_k = (UINT16)bp->s.alt_mem_k;
	} else {
		bp->s.ext_mem_k = 65535;
	}

	if (hdr_version < 0x0202)
		bp->s.base_mem_size = high_base_mem;

	/*
	 * Initial RAMdisk and root device stuff.
	 */

	DBG_PRT((L"initrd->start_addr=0x%x  initrd->pgcnt=%d\n",
		initrd->start_addr, initrd->pgcnt));

	/* These RAMdisk flags are not needed, just zero them. */
	bp->s.ramdisk_flags = 0;

	if (initrd->start_addr && initrd->pgcnt) {
		/* %%TBD - This will probably have to be changed. */
		bp->s.initrd_start = (UINT32)initrd->start_addr;
		bp->s.initrd_size = (UINT32)(initrd->pgcnt * EFI_PAGE_SIZE);

		/*
		 * This is the RAMdisk root device for RedHat 2.2.x
		 * kernels (major 0x01, minor 0x00).
		 * %%TBD - Will this work for other distributions and
		 * 2.3.x and 2.4.x kernels?  I do not know, yet.
		 */

		bp->s.orig_root_dev = 0x0100;
	} else {
		bp->s.initrd_start = 0;
		bp->s.initrd_size = 0;

		/* Do not change the root device if there is no RAMdisk. */
		/* bp->s.orig_root_dev = 0; */
	}

	/*
	 * APM BIOS info.
	 */

/* %%TBD - How to do Int 15h calls to get this info? */
	bp->s.apm_bios_ver = NO_APM_BIOS;
	bp->s.bios_code_seg = 0;
	bp->s.bios_entry_point = 0;
	bp->s.bios_code_seg16 = 0;
	bp->s.bios_data_seg = 0;
	bp->s.apm_bios_flags = 0;
	bp->s.bios_code_len = 0;
	bp->s.bios_data_len = 0;

	/*
	 * MCA BIOS info (misnomer).
	 */

/* %%TBD - How to do Int 15h call to get this info? */
	bp->s.mca_info_len = 0;
	ZeroMem(bp->s.mca_info_buf, sizeof bp->s.mca_info_buf);

	/*
	 * Pointing device presence.
	 */

/* %%TBD - How to do Int 11h call to get this info? */
	bp->s.aux_dev_info = NO_MOUSE;

	/*
	 * EFI loader signature and address of EFI system table.
	 */

	CopyMem(bp->s.efi_loader_sig, EFI_LOADER_SIG, 4);
	bp->s.efi_sys_tbl = 0; /* %%TBD */

	/*
	 * Kernel entry point.
	 */

	bp->s.kernel_start = (UINT32)kernel_start;

	/*
	 * When changing stuff in the parameter structure compare
	 * the offsets of the fields with the offsets used in the
	 * boot sector and setup source files.
	 *   arch/i386/boot/bootsect.S
	 *   arch/i386/boot/setup.S
	 *   arch/i386/kernel/setup.c
	 */

#define CHECK_OFFSET(n, o, f) \
{ \
	UINTN p = (UINT8 *)&bp->s.n - (UINT8 *)bp; \
	UINTN q = (UINTN)(o); \
	if (p != q) { \
		test |= 1; \
		Print(L"%20a:  %3xh  %3xh  ", #n, p, q); \
		if (*f) { \
			Print(f, bp->s.n); \
		} \
		Print(L"\n"); \
	} \
}

#define WAIT_FOR_KEY() \
{ \
	EFI_INPUT_KEY key; \
	while (ST->ConIn->ReadKeyStroke(ST->ConIn, &key) != EFI_SUCCESS) { \
		; \
	} \
}

	{
		UINTN test = 0;

		CHECK_OFFSET(orig_cursor_col, 0x00, L"%xh");
		CHECK_OFFSET(orig_cursor_row, 0x01, L"%xh");
		CHECK_OFFSET(ext_mem_k, 0x02, L"%xh");
		CHECK_OFFSET(orig_video_page, 0x04, L"%xh");
		CHECK_OFFSET(orig_video_mode, 0x06, L"%xh");
		CHECK_OFFSET(orig_video_cols, 0x07, L"%xh");
		CHECK_OFFSET(orig_ega_bx, 0x0A, L"%xh");
		CHECK_OFFSET(orig_video_rows, 0x0E, L"%xh");
		CHECK_OFFSET(is_vga, 0x0F, L"%xh");
		CHECK_OFFSET(orig_video_points, 0x10, L"%xh");
		CHECK_OFFSET(lfb_width, 0x12, L"%xh");
		CHECK_OFFSET(lfb_height, 0x14, L"%xh");
		CHECK_OFFSET(lfb_depth, 0x16, L"%xh");
		CHECK_OFFSET(lfb_base, 0x18, L"%xh");
		CHECK_OFFSET(lfb_size, 0x1C, L"%xh");
		CHECK_OFFSET(cmdline_magik, 0x20, L"%xh");
		CHECK_OFFSET(cmdline_offset, 0x22, L"%xh");
		CHECK_OFFSET(lfb_line_len, 0x24, L"%xh");
		CHECK_OFFSET(lfb_red_size, 0x26, L"%xh");
		CHECK_OFFSET(lfb_red_pos, 0x27, L"%xh");
		CHECK_OFFSET(lfb_green_size, 0x28, L"%xh");
		CHECK_OFFSET(lfb_green_pos, 0x29, L"%xh");
		CHECK_OFFSET(lfb_blue_size, 0x2A, L"%xh");
		CHECK_OFFSET(lfb_blue_pos, 0x2B, L"%xh");
		CHECK_OFFSET(lfb_rsvd_size, 0x2C, L"%xh");
		CHECK_OFFSET(lfb_rsvd_pos, 0x2D, L"%xh");
		CHECK_OFFSET(vesa_seg, 0x2E, L"%xh");
		CHECK_OFFSET(vesa_off, 0x30, L"%xh");
		CHECK_OFFSET(lfb_pages, 0x32, L"%xh");
		CHECK_OFFSET(lfb_reserved, 0x34, L"");
		CHECK_OFFSET(apm_bios_ver, 0x40, L"%xh");
		CHECK_OFFSET(bios_code_seg, 0x42, L"%xh");
		CHECK_OFFSET(bios_entry_point, 0x44, L"%xh");
		CHECK_OFFSET(bios_code_seg16, 0x48, L"%xh");
		CHECK_OFFSET(bios_data_seg, 0x4A, L"%xh");
		CHECK_OFFSET(apm_bios_flags, 0x4C, L"%xh");
		CHECK_OFFSET(bios_code_len, 0x4E, L"%xh");
		CHECK_OFFSET(bios_data_len, 0x52, L"%xh");
		CHECK_OFFSET(hd0_info, 0x80, L"");
		CHECK_OFFSET(hd1_info, 0x90, L"");
		CHECK_OFFSET(mca_info_len, 0xA0, L"%xh");
		CHECK_OFFSET(mca_info_buf, 0xA2, L"");
		CHECK_OFFSET(efi_loader_sig, 0x1C0, L"'%-4.4a'");
		CHECK_OFFSET(efi_sys_tbl, 0x1C4, L"%xh");
		CHECK_OFFSET(efi_mem_desc_size, 0x1C8, L"%xh");
		CHECK_OFFSET(efi_mem_desc_ver, 0x1CC, L"%xh");
		CHECK_OFFSET(efi_mem_map, 0x1D0, L"%xh");
		CHECK_OFFSET(efi_mem_map_size, 0x1D4, L"%xh");
		CHECK_OFFSET(loader_start, 0x1D8, L"%xh");
		CHECK_OFFSET(loader_size, 0x1DC, L"%xh");
		CHECK_OFFSET(alt_mem_k, 0x1E0, L"%xh");
		CHECK_OFFSET(setup_sectors, 0x1F1, L"%xh");
		CHECK_OFFSET(mount_root_rdonly, 0x1F2, L"%xh");
		CHECK_OFFSET(sys_size, 0x1F4, L"%xh");
		CHECK_OFFSET(swap_dev, 0x1F6, L"%xh");
		CHECK_OFFSET(ramdisk_flags, 0x1F8, L"%xh");
		CHECK_OFFSET(video_mode_flag, 0x1FA, L"%xh");
		CHECK_OFFSET(orig_root_dev, 0x1FC, L"%xh");
		CHECK_OFFSET(aux_dev_info, 0x1FF, L"%xh");
		CHECK_OFFSET(jump, 0x200, L"%xh");
		CHECK_OFFSET(setup_sig, 0x202, L"'%-4.4a'");
		CHECK_OFFSET(hdr_minor, 0x206, L"%xh");
		CHECK_OFFSET(hdr_major, 0x207, L"%xh");
		CHECK_OFFSET(rm_switch, 0x208, L"%xh");
		CHECK_OFFSET(start_sys_seg, 0x20C, L"%xh");
		CHECK_OFFSET(kernel_verstr_offset, 0x20E, L"%xh");
		CHECK_OFFSET(loader_type, 0x210, L"%xh");
		CHECK_OFFSET(loader_flags, 0x211, L"%xh");
		CHECK_OFFSET(setup_move_size, 0x212, L"%xh");
		CHECK_OFFSET(kernel_start, 0x214, L"%xh");
		CHECK_OFFSET(initrd_start, 0x218, L"%xh");
		CHECK_OFFSET(initrd_size, 0x21C, L"%xh");
		CHECK_OFFSET(bootsect_helper, 0x220, L"%xh");
		CHECK_OFFSET(heap_end_ptr, 0x224, L"%xh");
		CHECK_OFFSET(base_mem_size, 0x226, L"%xh");

		if (test) {
			ERR_PRT((L"Boot sector and/or setup parameter alignment error."));
			free_kmem();
			return -1;
		}
	}

	/*
	 * Get video information.
	 * Do this last so that any other cursor positioning done
	 * in the fill routine gets accounted for.
	 */

	efi_status = ST->ConOut->QueryMode(
		ST->ConOut,
		ST->ConOut->Mode->Mode,
		&cols,
		&rows);

	if (EFI_ERROR(efi_status)) {
		ERR_PRT((L"QueryMode failed.  Fake it."));

		mode = 3;
		rows = 25;
		cols = 80;
		row = 24;
		col = 0;
	} else {
		mode = (UINT8)ST->ConOut->Mode->Mode;
		col = (UINT8)ST->ConOut->Mode->CursorColumn;
		row = (UINT8)ST->ConOut->Mode->CursorRow;
	}

	bp->s.orig_cursor_col = col;
	bp->s.orig_cursor_row = row;
	bp->s.orig_video_page = 0;
	bp->s.orig_video_mode = mode;
	bp->s.orig_video_cols = (UINT8)cols;
	bp->s.orig_video_rows = (UINT8)rows;

/* %%TBD - How to do Int 10h calls to get video info? */
	bp->s.orig_ega_bx = 0;
	bp->s.is_vga = 0;
	bp->s.orig_video_points = 0;

/* %%TBD - How to do Int 10h calls to get frame buffer info? */
	bp->s.lfb_width = 0;
	bp->s.lfb_height = 0;
	bp->s.lfb_depth = 0;
	bp->s.lfb_base = 0;
	bp->s.lfb_size = 0;
	bp->s.lfb_line_len = 0;
	bp->s.lfb_red_size = 0;
	bp->s.lfb_red_pos = 0;
	bp->s.lfb_green_size = 0;
	bp->s.lfb_green_pos = 0;
	bp->s.lfb_blue_size = 0;
	bp->s.lfb_blue_pos = 0;
	bp->s.lfb_rsvd_size = 0;
	bp->s.lfb_rsvd_pos = 0;
	bp->s.lfb_pages = 0;
	bp->s.vesa_seg = 0;
	bp->s.vesa_off = 0;

	/*
	 * Get memory map description and cookie for ExitBootServices()
	 */

	if (get_memmap(&mdesc)) {
		ERR_PRT((L"Could not get memory map."));
		free_kmem();
		return -1;
	}

	*cookie = mdesc.cookie;
	bp->s.efi_mem_map = (UINTN)mdesc.md;
	bp->s.efi_mem_map_size = mdesc.map_size;
	bp->s.efi_mem_desc_size = mdesc.desc_size;
	bp->s.efi_mem_desc_ver = mdesc.desc_version;
	bp->s.efi_sys_tbl = (UINTN)systab;
	
	/*
	 * my_ia32_boot_params and get ready to slap them into 0x00104c00
	 */

	efi_ia32_bp.size= sizeof(efi_ia32_bp);
	efi_ia32_bp.command_line = (UINT32) cmdline;
	efi_ia32_bp.efi_sys_tbl = bp->s.efi_sys_tbl;
	efi_ia32_bp.efi_mem_map = bp->s.efi_mem_map;
	efi_ia32_bp.efi_mem_map_size = bp->s.efi_mem_map_size;
	efi_ia32_bp.efi_mem_desc_size = bp->s.efi_mem_desc_size;
	efi_ia32_bp.efi_mem_desc_version = bp->s.efi_mem_desc_ver;
	efi_ia32_bp.initrd_start = (UINTN)initrd->start_addr;
	efi_ia32_bp.initrd_size = initrd->pgcnt * EFI_PAGE_SIZE;
	efi_ia32_bp.loader_start = 0;
	efi_ia32_bp.loader_size = 0;
	efi_ia32_bp.kernel_start = bp->s.kernel_start;
	efi_ia32_bp.kernel_size = kernel_size;
	efi_ia32_bp.num_cols = cols;
	efi_ia32_bp.num_rows = rows;
	efi_ia32_bp.orig_x = col;
	efi_ia32_bp.orig_y = row;


	return 0;
}
