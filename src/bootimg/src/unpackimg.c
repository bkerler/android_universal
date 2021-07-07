#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

#include "bootimg.h"

void unpackimg_die(int quiet, int rc, const char *why, ...)
{
	if (!quiet) {
		va_list ap;
		va_start(ap, why);
		fprintf(stderr,"error: ");
		vfprintf(stderr, why, ap);
		fprintf(stderr,"\n");
		va_end(ap);
	}
	exit(rc);
}

int unpackimg_usage() {
	fprintf(stderr, "Usage: unpackimg -i kernel_image [-k kernel | -r ramdisk | -d dtb ]\n\n");
	return 200;
}

int main_unpackimg(int argc, char** argv)
{
	char		*image_file = NULL;
    char		*out_file[4] = { NULL, NULL, NULL };
    size_t		obj_pos[4];
    size_t		obj_len[4];
    size_t		obj_off[4];
    static char	*obj_name[] = { "KERNEL", "RAMDISK", "SECOND", "TAGS"};
	int			quiet = 0;

	int		i;
	FILE*	f;
	boot_img_hdr header;

	int		pagemask;
	int		pagesize = 0;

	argc--;
	argv++;
	while(argc > 0){
		char *arg = argv[0];
		if (!strcmp(arg, "-q")) {
			quiet = 1;
			argc -= 1;
			argv += 1;
		} else if (argc >= 2) {
			char *val = argv[1];
			argc -= 2;
			argv += 2;
			if (!strcmp(arg, "-i"))
				image_file = val;
			else if (!strcmp(arg, "-k"))
				out_file[0] = val;
			else if (!strcmp(arg, "-r"))
				out_file[1] = val;
			else if (!strcmp(arg, "-d"))
				out_file[2] = val;
			else if (!strcmp(arg, "-p"))
				if (val[0] == '0' && val[1] == 'x')
					pagesize = strtoul(val+2, 0, 16);
				else
					pagesize = strtoul(val, 0, 10);
			else
				return unpackimg_usage();
		} else {
			return unpackimg_usage();
		}
	}

	if (image_file == NULL)
		return unpackimg_usage();

	f = fopen(image_file, "rb");
	if (f == NULL)
		unpackimg_die(quiet, 1, "Could not open file %s\n", image_file);

	if (fread(&header, 1, sizeof(header), f) != sizeof(header) ||
		memcmp(&header.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0)
		unpackimg_die(quiet, 1, "Android boot magic not found\n");

	printf("BOARD_KERNEL_CMDLINE=\"%s\"\n", header.cmdline);
	printf("BOARD_KERNEL_BOARD=\"%s\"\n", header.name);
	printf("BOARD_PAGE_SIZE=\"%d\"\n", header.page_size);

	if (pagesize == 0)
		pagesize = header.page_size;
	pagemask = pagesize - 1;

	obj_pos[0] = (sizeof(header) + pagemask) & ~pagemask;
	obj_len[0] = header.kernel_size;
	obj_off[0] = header.kernel_addr;

	obj_pos[1] = (obj_pos[0] + obj_len[0] + pagemask) & ~pagemask;
	obj_len[1] = header.ramdisk_size;
	obj_off[1] = header.ramdisk_addr;

    obj_pos[2] = (obj_pos[1] + obj_len[1] + pagemask) & ~pagemask;
    obj_len[2] = header.second_size;
    obj_off[2] = header.second_addr;

    obj_pos[3] = (obj_pos[2] + obj_len[2] + pagemask) & ~pagemask;
    obj_len[3] = header.dt_size;
    obj_off[3] = header.tags_addr;



    for (i=0; i<4; i++) {
		void	*buffer;
		FILE	*fout;

        printf("BOARD_%s_OFFSET=\"%08x\"\n", obj_name[i], obj_off[i]);

		if (!out_file[i] || obj_len[i] == 0)
			continue;

		buffer = malloc(obj_len[i]);
		fseek(f, obj_pos[i], SEEK_SET);
		fread(buffer, 1, obj_len[i], f);
		fout = fopen(out_file[i], "wb");
		fwrite(buffer, 1, obj_len[i], fout);
		fclose(fout);

		if (obj_len[i] > 4 && 0 == memcmp(buffer, "QCDT", 4))
			printf("BOARD_QCDT=\"1\"\n");
		free(buffer);
	}

	fclose(f);
	return 0;
}
