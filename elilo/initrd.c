/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *	Contributed by Stephane Eranian <eranian@hpl.hp.com>
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

#include <efi.h>
#include <efilib.h>

#include "elilo.h"

/*
 * This function allocates memory for the initial ramdisk (initrd) and loads it to memory
 * OUTPUTS:
 * 	- ELILO_LOAD_SUCCESS: if everything works
 * 	- ELILO_LOAD_ABORTED: in case the user decided to abort loading
 * 	- ELILO_LOAD_ERROR: there was an error during alloc/read
 *
 * Adapted from Bill Nottingham <notting@redhat.com>  patch for ELI.
 */
INTN
load_initrd(CHAR16 *filename, memdesc_t *initrd)
{
	EFI_STATUS status;
	VOID *start_addr = initrd->start_addr;
	UINT64 size = 0;
	UINTN pgcnt;
	fops_fd_t fd;
	INTN ret  = ELILO_LOAD_ERROR;
	

	if (filename == NULL || filename[0] == 0) return -1;

	/* Open the file */
	status = fops_open(filename, &fd);
	if (EFI_ERROR(status)) {
		ERR_PRT((L"Open initrd file %s failed: %r", filename, status));
		return -1;
	}

	DBG_PRT((L"initrd_open %s worked", filename));

	/* warning: this function allocates memory  */
	status = fops_infosize(fd, &size);
	if (EFI_ERROR(status)) {
		ERR_PRT((L"Couldn't read initrd file %s info %r",filename, status));
		goto error;
	}
	
	/* round up to get required number of pages (4KB) */
	initrd->pgcnt = pgcnt = EFI_SIZE_TO_PAGES(size);



	start_addr = alloc_pages(pgcnt, EfiLoaderData, start_addr ? AllocateAddress : AllocateAnyPages, start_addr);
	if (start_addr == NULL) {
		ERR_PRT((L"Failed to allocate %d pages for initrd", pgcnt));
		goto error;
	}
	VERB_PRT(2, Print(L"initrd: total_size: %ld bytes base: 0x%lx pages %d\n", 
			size, (UINT64)start_addr, pgcnt));

	Print(L"Loading initrd %s...", filename);

	ret = read_file(fd, size, start_addr);	

	fops_close(fd);

	if (ret != ELILO_LOAD_SUCCESS) {
		ERR_PRT((L"read initrd(%s) failed: %d", filename, ret));
		goto error;
	}

	Print(L"done\n");

	initrd->start_addr = start_addr;

	return ELILO_LOAD_SUCCESS;

error:
	if (start_addr) free(start_addr);

	/*
	 * make sure nothing is passed to kernel
	 * in case of error.
	 */
	initrd->start_addr = 0;
	initrd->pgcnt      = 0;

	return ret;
}

