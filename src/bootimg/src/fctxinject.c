#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>

void fctxinject_die(int quiet, int rc, const char *why, ...)
{
	if (!quiet) {
		va_list ap;
		va_start(ap, why);
		fprintf(stderr, "error: ");
		vfprintf(stderr, why, ap);
		fprintf(stderr, "\n");
		va_end(ap);
	}
	exit(rc);
}

void fctxinject_info(int verbose, const char *info, ...)
{
	if (verbose) {
		va_list ap;
		va_start(ap, info);
		vprintf(info, ap);
		printf("\n");
		va_end(ap);
	}
}

int fctxinject_usage() {
	fprintf(stderr, "Usage: fctxinject -i input file -o output file -p path -w -c context [ -v (verbodes) ] [ -q (quiet) ]\n\n");
	return 200;
}

uint32_t fctx_read_le4(uint8_t *b, size_t *pos)
{
	uint32_t	retval = 0;

	retval |= b[(*pos)++];
	retval |= (b[(*pos)++]) << 8;
	retval |= (b[(*pos)++]) << 16;
	retval |= (b[(*pos)++]) << 24;
	return retval;
}

void fctx_write_le4(uint8_t *b, size_t *pos, uint32_t val)
{
	b[(*pos)++] = val & 0xff;
	b[(*pos)++] = (val >> 8) & 0xff;
	b[(*pos)++] = (val >> 16) & 0xff;
	b[(*pos)++] = (val >> 24) & 0xff;
}

#define PCRE_START 0x1b
#define PCRE_SINGLE_CHAR 0x1d

int main_fctxinject(int argc, char** argv)
{
	int			quiet = 0, verbose = 0, wildcard = 0, stemid = -1, new_path_regex_start = 0;
	char		*ctx_file = 0, *out_file = 0, *new_ctx = 0, *new_path = 0;
	FILE		*f;
	size_t		pos, tpos, rpos, rlen, len, regex_new_len, slen, num_stem, num_regex, i;
	size_t		pos_num_regex, pos_len1;
	char		*ctx, *regex, regex_new[256];
	size_t		regex_start, regex_new_start = 0;
	uint32_t	pcrereglen, pcrestudylen;

	uint8_t	t[1024], *b = 0;

	argc--;
	argv++;

	while (argc > 0) {
		char *arg = *argv;

		argc -= 1;
		argv += 1;

		if (!strcmp(arg, "-q"))
			quiet = 1;
		else if (!strcmp(arg, "-v"))
			verbose = 1;
		else if (!strcmp(arg, "-w"))
			wildcard = 1;
		else if (argc >= 1) {
			char *val = *argv;

			argc--;
			argv++;
			if (!strcmp(arg, "-i"))
				ctx_file = val;
			else if (!strcmp(arg, "-o"))
				out_file = val;
			else if (!strcmp(arg, "-c"))
				new_ctx = val;
			else if (!strcmp(arg, "-p")) {
				new_path = val;
			}
			else
				return fctxinject_usage();
		} else {
			return fctxinject_usage();
		}
	}

	if (!ctx_file)
		return fctxinject_usage();

	f = fopen(ctx_file, "rb");
	if (f == 0)
		fctxinject_die(quiet, 1, "Could not open file %s\n", ctx_file);

	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);

	b = malloc(len + 1024);
	fread(b, len, 1, f);
	fclose(f);

	if (new_path)
			regex_new_len = snprintf(regex_new, sizeof(regex_new), wildcard ? "%s(/.*)?" : "%s", new_path);
	
	if (b[0] != 0x8a || b[1] !=0xff || b[2] != 0x7c || b[3] != 0xf9)
		fctxinject_die(quiet, 1, "Could not find SELINUX_MAGIC_COMPILED_FCONTEXT in %s\n", ctx_file);

	pos = 4;
	fctxinject_info(verbose, "File version %d", fctx_read_le4(b , &pos));

	slen = fctx_read_le4(b , &pos);
	memset(t, 0, sizeof(t));
	memcpy(t, b + pos, slen);
	fctxinject_info(verbose, "PCRE version %s", t);
	pos += slen;

	num_stem = fctx_read_le4(b , &pos);
	fctxinject_info(verbose, "stems %d", num_stem);

	for (i = 0; i < num_stem; i++) {
		slen = fctx_read_le4(b , &pos);
		fctxinject_info(verbose, "stem %d: %s", i, b + pos);
		if (0 == strncmp((char*)b + pos, new_path, slen) && new_path[slen] == '/') {
			stemid = i;
			new_path_regex_start = slen;
		}
		pos += slen + 1;
	}

	pos_num_regex = pos;
	num_regex = fctx_read_le4(b , &pos);
	fctxinject_info(verbose, "regex %d", num_regex);

	for (i = 0; i < num_regex; i++) {
		regex_start = pos;
		slen = fctx_read_le4(b , &pos);
		ctx = (char*)b + pos;
		pos += slen;
		slen = fctx_read_le4(b , &pos);
		regex = (char*)b + pos;

		if (new_path && 0 == strcmp(regex_new, regex)) {
			regex_new_start = regex_start;
			if (0 == strcmp(new_ctx, ctx))
				if (!quiet)
					printf("Regex %s already exists with context %s\n", regex, ctx);
		}

		pos += slen;
		pos += 4;		// Skip mode
		pos += 4;		// Skip stempid
		pos += 4;		// Skip hasmeta
		pos += 4;		// Skip specprefixlen
		pcrereglen = fctx_read_le4(b, &pos);
		pos += pcrereglen;
		pcrestudylen = fctx_read_le4(b, &pos);
		pos += pcrestudylen;
		fctxinject_info(verbose, "%s\t%s", regex, ctx);
	}

	if (len != pos)
		fctxinject_die(quiet, 1, "Inconsistent file. Length %08x != end %08x\n", len, pos);

	if (new_ctx && new_path && regex_new_start == 0) {
		/* Add regex entry */
		tpos = 0;
		slen = strlen(new_ctx) + 1;
		fctx_write_le4(t, &tpos, slen);
		memcpy(t + tpos, new_ctx, slen);
		tpos += slen;
		slen = regex_new_len + 1;
		fctx_write_le4(t, &tpos, slen);
		memcpy(t + tpos, regex_new, slen);
		tpos += slen;
		fctx_write_le4(t, &tpos, 0);	// Mode
		fctx_write_le4(t, &tpos, stemid);	// Stem ID
		fctx_write_le4(t, &tpos, wildcard);	// Has Meta
		slen = strlen(new_path);
		fctx_write_le4(t, &tpos, slen);	// Prefix before meta
		tpos += 4;

		rpos = tpos;
		t[rpos++] = 'E';				// Magic
		t[rpos++] = 'R';
		t[rpos++] = 'C';
		t[rpos++] = 'P';
		rpos += 4;						// Skip size for now

		fctx_write_le4(t, &rpos, 0x14);	// Options
		t[rpos++] = 1;					// Flags
		t[rpos++] = 0;
		t[rpos++] = 0;					// Dummy 1
		t[rpos++] = 0;
		for (i = 0; i < 8; i++)			// top_bracket, top_backref, first_byte, req_byte
			t[rpos++] = 0xff;
		for (i = 0; i < 6; i++)			// top_bracket, top_backref, first_byte, req_byte
			t[rpos++] = 0;				// name_table_offset, name_entry_size, name_count
		t[rpos++] = 1;					// Ref count;
		t[rpos++] = 0;
		fctx_write_le4(t, &rpos, 0x00400000);	// Pointer to tables or NULL for std 
		while (rpos - tpos < 0x40)
			t[rpos++] = 0;

		t[rpos++] = 0x83;
		t[rpos++] = 0x00;
		pos_len1 = rpos;
		rpos++;
		t[rpos++] = 0x1b;

		for (i = new_path_regex_start; i < slen; i++) {
			t[rpos++] = 0x1d;
			t[rpos++] = new_path[i];
		}

		if (wildcard) {
			const uint8_t regex_wildcard[] = { 0x92, 0x85, 0x00, 0x09, 0x00, 0x01, 0x1d, 0x2f, 0x55, 0x0d, 0x78, 0x00, 0x09 };

			memcpy(t + rpos, regex_wildcard, sizeof(regex_wildcard));
			rpos += sizeof(regex_wildcard);
		}

		t[rpos++] = 0x19;
		t[rpos++] = 0x78;
		t[rpos++] = 0x00;
		t[rpos]     = (uint8_t)(rpos - pos_len1);
		t[pos_len1] = (uint8_t)(rpos - pos_len1);
		rpos++;
		t[rpos++] = 0x00;

		rlen = rpos - tpos;
		tpos -= 4;
		fctx_write_le4(t, &tpos, rlen);	// Length of compiled regex
		tpos += 4;
		fctx_write_le4(t, &tpos, rlen);	// Length of compiled regex
		tpos += rlen - 8;

		fctx_write_le4(t, &tpos, 0x2c);	// Length of precompiled study
		fctx_write_le4(t, &tpos, 0x2c);	// Total size of structure
		fctx_write_le4(t, &tpos, 2);	// Private flags
		for (i = 0; i < 0x20; i++)		// Starting char bits
			t[tpos++] = 0;
		fctx_write_le4(t, &tpos, slen - new_path_regex_start);	// Minimum subject length

		memmove(b + pos_num_regex + 4 + tpos, b + pos_num_regex + 4, len - pos_num_regex - 4);
		memcpy(b + pos_num_regex + 4 , t, tpos);
		len += tpos;
		num_regex++;
		fctx_write_le4(b, &pos_num_regex, num_regex);
	}

	if (out_file) {
		f = fopen(out_file, "wb");
		fwrite(b, len, 1, f);
		fclose(f);
	}

	return 0;
}
