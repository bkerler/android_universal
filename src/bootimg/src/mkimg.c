// https://github.com/osm0sis/mkbootimg/blob/master/mkbootimg.c

/* tools/mkbootimg/mkbootimg.c
**
** Copyright 2007, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifndef WIN32
#include <unistd.h>
#include <stdbool.h>
#endif

#include "bootimg.h"
#include "sha.h"

static void *load_file(const char *fn, unsigned *_sz)
{
	void	*data;
	int		size;
	FILE	*f;

	data = 0;
	f = fopen(fn, "rb");
	if (f == NULL)
		return 0;

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	if (size < 0)
		goto oops;

	fseek(f, 0, SEEK_SET);

	data = malloc(size);
	if (data == 0)
		goto oops;

	if (size != fread(data, 1, size, f))
		goto oops;

	fclose(f);

	if (_sz)
		*_sz = size;
	return data;

oops:
	fclose(f);
	if (data != 0)
		free(data);
	return 0;
}

int usage_mkimg(void)
{
	fprintf(stderr,"usage: mkbootimg\n"
			"       --kernel <filename>\n"
			"       --ramdisk <filename>\n"
			"       [ --second <2ndbootloader-filename> ]\n"
			"       [ --cmdline <kernel-commandline> ]\n"
			"       [ --board <boardname> ]\n"
			"       [ --base <address> ]\n"
			"       [ --pagesize <pagesize> ]\n"
			"       [ --kernel_offset <base offset> ]\n"
			"       [ --ramdisk_offset <base offset> ]\n"
			"       [ --second_offset <base offset> ]\n"
			"       [ --tags_offset <base offset> ]\n"
			"       [ --dt <filename> ]\n"
			"       [ --id ]\n"
			"       -o|--output <filename>\n"
			);
	return 1;
}



static unsigned char padding[131072] = { 0, };

static void print_id(const uint8_t *id, size_t id_len) {
	unsigned i = 0;

	printf("0x");
	for (i = 0; i < id_len; i++)
		printf("%02x", id[i]);
	printf("\n");
}

int write_padding(FILE *f, unsigned pagesize, unsigned itemsize)
{
	unsigned pagemask = pagesize - 1;
	size_t count;

	if ((itemsize & pagemask) == 0) {
		return 0;
	}

	count = pagesize - (itemsize & pagemask);

	if (fwrite(padding, 1, count, f) != count) {
		return -1;
	} else {
		return 0;
	}
}

int main_mkimg(int argc, char **argv)
{
	boot_img_hdr hdr;

	char *kernel_fn = NULL;
	void *kernel_data = NULL;
	char *ramdisk_fn = NULL;
	void *ramdisk_data = NULL;
	char *second_fn = NULL;
	void *second_data = NULL;
	char *cmdline = "";
	char *bootimg = NULL;
	char *board = "";
	char *dt_fn = NULL;
	void *dt_data = NULL;
	uint32_t pagesize = 2048;
	FILE	*f;
	SHA_CTX ctx;
	const uint8_t* sha;
	uint32_t base           = 0x10000000U;
	uint32_t kernel_offset  = 0x00008000U;
	uint32_t ramdisk_offset = 0x01000000U;
	uint32_t second_offset  = 0x00f00000U;
	uint32_t tags_offset    = 0x00000100U;
	size_t cmdlen;
	int get_id;

	argc--;
	argv++;

	memset(&hdr, 0, sizeof(hdr));

	get_id = 0;
	while(argc > 0){
		char *arg = argv[0];
		if (!strcmp(arg, "--id")) {
			get_id = 1;
			argc -= 1;
			argv += 1;
		} else if (argc >= 2) {
			char *val = argv[1];
			argc -= 2;
			argv += 2;
			if (!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
				bootimg = val;
			} else if (!strcmp(arg, "--kernel")) {
				kernel_fn = val;
			} else if (!strcmp(arg, "--ramdisk")) {
				ramdisk_fn = val;
			} else if (!strcmp(arg, "--second")) {
				second_fn = val;
			} else if (!strcmp(arg, "--cmdline")) {
				cmdline = val;
			} else if (!strcmp(arg, "--base")) {
				base = strtoul(val, 0, 16);
			} else if (!strcmp(arg, "--kernel_offset")) {
				kernel_offset = strtoul(val, 0, 16);
			} else if (!strcmp(arg, "--ramdisk_offset")) {
				ramdisk_offset = strtoul(val, 0, 16);
			} else if (!strcmp(arg, "--second_offset")) {
				second_offset = strtoul(val, 0, 16);
			} else if (!strcmp(arg, "--tags_offset")) {
				tags_offset = strtoul(val, 0, 16);
			} else if (!strcmp(arg, "--board")) {
				board = val;
			} else if (!strcmp(arg,"--pagesize")) {
				pagesize = strtoul(val, 0, 10);
				if ((pagesize != 2048) && (pagesize != 4096)
					&& (pagesize != 8192) && (pagesize != 16384)
					&& (pagesize != 32768) && (pagesize != 65536)
					&& (pagesize != 131072)) {
					fprintf(stderr,"error: unsupported page size %d\n", pagesize);
					return -1;
				}
			} else if (!strcmp(arg, "--dt")) {
				dt_fn = val;
			} else {
				return usage_mkimg();
			}
		} else {
			return usage_mkimg();
		}
	}
	hdr.page_size = pagesize;

	hdr.kernel_addr =  base + kernel_offset;
	hdr.ramdisk_addr = base + ramdisk_offset;
	hdr.second_addr =  base + second_offset;
	hdr.tags_addr =    base + tags_offset;

	if (bootimg == 0) {
		fprintf(stderr,"error: no output filename specified\n");
		return usage_mkimg();
	}

	if (kernel_fn == 0) {
		fprintf(stderr,"error: no kernel image specified\n");
		return usage_mkimg();
	}

	if (ramdisk_fn == 0) {
		fprintf(stderr,"error: no ramdisk image specified\n");
		return usage_mkimg();
	}

	if (strlen(board) >= BOOT_NAME_SIZE) {
		fprintf(stderr,"error: board name too large\n");
		return usage_mkimg();
	}

	strcpy((char *) hdr.name, board);

	memcpy(hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

	cmdlen = strlen(cmdline);
	if (cmdlen > (BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE - 2)) {
		fprintf(stderr,"error: kernel commandline too large\n");
		return 1;
	}
	/* Even if we need to use the supplemental field, ensure we
	 * are still NULL-terminated */
	strncpy((char *)hdr.cmdline, cmdline, BOOT_ARGS_SIZE - 1);
	hdr.cmdline[BOOT_ARGS_SIZE - 1] = '\0';
	if (cmdlen >= (BOOT_ARGS_SIZE - 1)) {
		cmdline += (BOOT_ARGS_SIZE - 1);
		strncpy((char *)hdr.extra_cmdline, cmdline, BOOT_EXTRA_ARGS_SIZE);
	}

	kernel_data = load_file(kernel_fn, &hdr.kernel_size);
	if (kernel_data == 0) {
		fprintf(stderr,"error: could not load kernel '%s'\n", kernel_fn);
		return 1;
	}

	if (!strcmp(ramdisk_fn,"NONE")) {
		ramdisk_data = 0;
		hdr.ramdisk_size = 0;
	} else {
		ramdisk_data = load_file(ramdisk_fn, &hdr.ramdisk_size);
		if (ramdisk_data == 0) {
			fprintf(stderr,"error: could not load ramdisk '%s'\n", ramdisk_fn);
			return 1;
		}
	}

	if (second_fn) {
		second_data = load_file(second_fn, &hdr.second_size);
		if (second_data == 0) {
			fprintf(stderr,"error: could not load secondstage '%s'\n", second_fn);
			return 1;
		}
	}

	if (dt_fn) {
		dt_data = load_file(dt_fn, &hdr.dt_size);
		if (dt_data == 0) {
			fprintf(stderr,"error: could not load device tree image '%s'\n", dt_fn);
			return 1;
		}
	}

	/* put a hash of the contents in the header so boot images can be
	 * differentiated based on their first 2k.
	 */
	SHA_init(&ctx);
	SHA_update(&ctx, kernel_data, hdr.kernel_size);
	SHA_update(&ctx, &hdr.kernel_size, sizeof(hdr.kernel_size));
	SHA_update(&ctx, ramdisk_data, hdr.ramdisk_size);
	SHA_update(&ctx, &hdr.ramdisk_size, sizeof(hdr.ramdisk_size));
	SHA_update(&ctx, second_data, hdr.second_size);
	SHA_update(&ctx, &hdr.second_size, sizeof(hdr.second_size));
	if (dt_data) {
		SHA_update(&ctx, dt_data, hdr.dt_size);
		SHA_update(&ctx, &hdr.dt_size, sizeof(hdr.dt_size));
	}
	sha = SHA_final(&ctx);
	memcpy(hdr.id, sha,
		   SHA_DIGEST_SIZE > sizeof(hdr.id) ? sizeof(hdr.id) : SHA_DIGEST_SIZE);

	f = fopen(bootimg, "wb+");
	if (f == NULL) {
		fprintf(stderr,"error: could not create '%s'\n", bootimg);
		return 1;
	}

	if (fwrite(&hdr, 1, sizeof(hdr), f) != sizeof(hdr))
		goto fail;
	if (write_padding(f, pagesize, sizeof(hdr)))
		goto fail;

	if (fwrite(kernel_data, 1, hdr.kernel_size, f) != (size_t) hdr.kernel_size)
		goto fail;
	if (write_padding(f, pagesize, hdr.kernel_size))
		goto fail;

	if (fwrite(ramdisk_data, 1, hdr.ramdisk_size, f) != (size_t) hdr.ramdisk_size)
		goto fail;
	if (write_padding(f, pagesize, hdr.ramdisk_size))
		goto fail;

	if (second_data) {
		if (fwrite(second_data, 1, hdr.second_size, f) != (size_t) hdr.second_size)
			goto fail;
		if (write_padding(f, pagesize, hdr.second_size))
			goto fail;
	}

	if (dt_data) {
		if (fwrite(dt_data, 1, hdr.dt_size, f) != (size_t)
			hdr.dt_size) goto fail;
		if (write_padding(f, pagesize, hdr.dt_size))
			goto fail;
	}

	if (get_id) {
		print_id((uint8_t *) hdr.id, sizeof(hdr.id));
	}

	return 0;

fail:
	unlink(bootimg);
	fclose(f);
	fprintf(stderr,"error: failed writing '%s': %s\n", bootimg, strerror(errno));
	return 1;
}
