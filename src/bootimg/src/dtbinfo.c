#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const unsigned char dtb_magic[]= { 0xd0, 0x0d, 0xfe, 0xed };
static const char* dtb_props[]= { "model", "compatible" };

typedef uint32_t fdt32_t;
typedef uint64_t fdt64_t;

struct fdt_header {
	fdt32_t magic;					/* magic word FDT_MAGIC */
	fdt32_t totalsize;				/* total size of DT block */
	fdt32_t off_dt_struct;			/* offset to structure */
	fdt32_t off_dt_strings;			/* offset to strings */
	fdt32_t off_mem_rsvmap;			/* offset to memory reserve map */
	fdt32_t version;				/* format version */
	fdt32_t last_comp_version;		/* last compatible version */
 									/* version 2 fields below */
	fdt32_t boot_cpuid_phys;		/* Which physical CPU id we're booting on */
									/* version 3 fields below */
	fdt32_t size_dt_strings;		/* size of the strings block */
									/* version 17 fields below */
	fdt32_t size_dt_struct;			/* size of the structure block */
};

struct fdt_reserve_entry {
	fdt64_t address;
	fdt64_t size;
};

struct fdt_node_header {
	fdt32_t tag;
	char name[0];
} fdt_node_header;

struct fdt_property {
	fdt32_t tag;
	fdt32_t len;
	fdt32_t nameoff;
	char data[0];
} fdt_property;

#define OFF(x,y)		&(((x*)0)->y)

#define	FDT_BEGIN_NODE	0x1		/* Start node: full name */
#define	FDT_END_NODE	0x2		/* End node */
#define	FDT_PROP		0x3		/* Property: name off, size, content */
#define	FDT_NOP			0x4		/* nop */
#define	FDT_END			0x9

long dtbinfo_read_int_be(const void *buffer, const size_t bytes)
{
	size_t	i;
	long	val = 0;

	for (i=0; i<bytes; i++) {
		val <<= 8;
		val |= ((uint8_t*)buffer)[i];
	}
	return val;
}

int mem_find(const void *b, const size_t blen, const void *s, const size_t slen )
{
	size_t	i;
	uint8_t	*p = (uint8_t*)b;

	for (i=0; i+slen < blen; i++, p++) {
		if (memcmp(p, s, slen))
			continue;
		return i;
	}
	return -1;
}

char* find_prop(const void *b, const size_t blen, const void* strings, const size_t slen, const char* prop)
{
	size_t	i;
	long	tag,len,off, labeloff;
	uint8_t	*p = (uint8_t*)b;
	char	*retval;

	labeloff = mem_find(strings, slen, prop, strlen(prop));
	if (labeloff < 0)
		return 0;

	i = 0;
	while (i < blen) {
		tag  = dtbinfo_read_int_be(p+i, 4);
		i += 4;
		if (tag == FDT_BEGIN_NODE) {
			/* Skip name */
			while (i < blen && p[i] != 0)
				i++;
			/* align to 4 */
			i += 3;
			i &= ~3;
			continue;
		}

		if (tag == FDT_END_NODE)
			continue;

		if (tag == FDT_PROP) {
			len = dtbinfo_read_int_be(p+i, 4);
			i += 4;
			off = dtbinfo_read_int_be(p+i, 4);
			i += 4;

			if (off == labeloff) {
				retval = (char*)p + i;
				retval[len] = 0;
				return retval;
			}

			i += len;
			/* align to 4 */
			i += 3;
			i &= ~3;
			continue;
		}
	}
	return NULL;
}

int main_dtbinfo(int argc, char** argv)
{
	FILE				*f;
	int					quiet = 0;
	char				*file = NULL;
	unsigned char		buffer[4096];
	char				strings[4096];
	int					i, p;
	struct fdt_header	*ph = NULL;
	long				off, off_str;
	long				fpos;
	char*				prop;
	int					search_backward = 0;

	--argc;
	argv++;
	while(argc > 0){
		char *arg = argv[0];
		--argc;
		argv++;
		if (!strcmp(arg, "-q"))
			quiet = 1;
		else if (argc >= 1) {
			char *val = argv[0];
			--argc;
			argv++;
			if (!strcmp(arg, "-i"))
				file = val;
		}
	}

	if (!file) {
		fprintf(stderr, "Usage: dtbinfo -i file [ -q ]\n");
		return 0;
	}

	f = fopen(file, "rb");
	if (f == 0) {
		if (!quiet)
			fprintf(stderr, "Could not open image %s\n\n", file);
		return 1;
	}

	fread(buffer, 1, sizeof(buffer), f);
	if (buffer[0] == 0x1f && buffer[1] == 0x8b) {		/* gzip header */
		search_backward = 1;
		fseek(f, 0, SEEK_END);
		fpos = ftell(f);
		fpos -= sizeof(buffer);
		fseek(f, fpos, SEEK_SET);
		fread(buffer, 1, sizeof(buffer), f);
	}

	while (1) {
		p = mem_find(buffer, sizeof(buffer), dtb_magic, sizeof(dtb_magic));
		if (p >= 0) {
			fpos = ftell(f) - sizeof(buffer) + p;
			fseek(f, fpos, SEEK_SET);
			fread(buffer, 1, sizeof(buffer), f);
			ph = (struct fdt_header*)buffer;
			break;
		}

		if (search_backward) {
			fpos -= sizeof(buffer);
			if (fpos <0)
				break;
			fseek(f, fpos, SEEK_SET);
		}

		if (0 == fread(buffer, 1, sizeof(buffer), f))
			break;
	}

	if (!ph) {
		fclose(f);
		if (!quiet)
			fprintf(stderr, "Could not find DTB header\n\n");
		return 2;
	}

	off = dtbinfo_read_int_be(&(ph->off_dt_struct), 4);
	off_str = dtbinfo_read_int_be(&(ph->off_dt_strings), 4);

	fseek(f, fpos+off, SEEK_SET);
	if (sizeof(buffer) != fread(buffer, 1, sizeof(buffer), f) ) {
		fclose(f);
		if (!quiet)
			fprintf(stderr, "Could not read DTB structure\n\n");
		return 2;
	}

	fseek(f, fpos+off_str, SEEK_SET);
	if (sizeof(strings) != fread(strings, 1, sizeof(strings), f)) {
		fclose(f);
		if (!quiet)
			fprintf(stderr, "Could not read DTB strings\n\n");
		return 2;
	}

	fclose(f);

	for (i=0; i<sizeof(dtb_props)/sizeof(dtb_props[0]); i++) {
		prop = find_prop(buffer, sizeof(buffer), strings, sizeof(strings), dtb_props[i]);
		if (prop)
			printf("DTB_%s=\"%s\"\n", dtb_props[i], prop);
	}

	return 0;
}
