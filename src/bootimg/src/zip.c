#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <dirent.h>
#else
#include <windows.h>
#include <io.h>

struct dirent {
	unsigned long	d_fileno;	/* file number of entry */
	unsigned short	d_reclen;	/* length of this record */
	unsigned char	d_type; 	/* file type, see below */
	unsigned char	d_namlen;	/* length of string in d_name */
	char			d_name[MAX_PATH];	/* name must be no longer than this */
};

#define S_IFLNK        0xA000          /* link */
#pragma pack(push,1)
#endif

#define ZIP_ENTRY_MAGIC     0x04034b50
#define ZIP_DIR_MAGIC       0x02014b50
#define ZIP_TRAILER_MAGIC   0x06054b50

#define ZIP_VERSION_FILE    10
#define ZIP_VERSION_DIR     20

typedef struct
MS_DOS_TIME {
	union {
		struct time {
			unsigned seconds : 5;
			unsigned minutes : 6;
			unsigned hours   : 5;
		} time;
		uint16_t val;
	};
} MS_DOS_TIME;

typedef struct
MS_DOS_DATE {
	union {
		struct date {
			unsigned day   : 5;
			unsigned month : 4;
			unsigned year  : 7;
		} date;
		uint16_t val;
	};
} MS_DOS_DATE;

typedef struct 
#ifndef WIN32
	__attribute__((__packed__))
#endif
ZIP_ENTRY {
	uint32_t	magic;	// Local file header signature = 0x04034b50 (read as a little-endian number)
	uint16_t	version;
	uint16_t	purpose;
	uint16_t	comp;
	uint16_t	time;
	uint16_t	date;
	uint32_t	crc;
	uint32_t	comp_size;
	uint32_t	uncomp_size;
	uint16_t	fname_len;
	uint16_t	extra_len;
} ZIP_ENTRY;

typedef struct 
#ifndef WIN32
	__attribute__((__packed__))
#endif
ZIP_HEADER {
	uint32_t	magic;
	uint16_t	creator;
	uint16_t	version;
	uint16_t	purpose;
	uint16_t	comp;
	uint16_t	time;
	uint16_t	date;
	uint32_t	crc;
	uint32_t	comp_size;
	uint32_t	uncomp_size;
	uint16_t	fname_len;
	uint16_t	extra_len;
	uint16_t	cmnt_len;
	uint16_t	start_disk;
	uint16_t	int_file_attr;
	uint32_t	ext_file_attr;
	uint32_t	offset;
	char		fname[256];
} ZIP_HEADER;

#define ZIP_HEADER_SIZE	(size_t)(((ZIP_HEADER*)0)->fname)

typedef struct 
#ifndef WIN32
	__attribute__((__packed__))
#endif
ZIP_END {
	uint32_t	magic;
	uint16_t	disc;
	uint16_t	start_disc;
	uint16_t	files_this_disc;
	uint16_t	files_total;
	uint32_t	dir_size;
	uint32_t	dir_offset;
	uint16_t	comment_len;
} ZIP_END;

int				zip_header_array = 0;
int				zip_header_entries = 0;
ZIP_HEADER		*zip_headers = NULL;
int				zip_quiet = 0;
FILE			*zip_file = NULL;

void die_zip(const char *why, ...)
{
	va_list ap;
	va_start(ap, why);
	fprintf(stderr,"error: ");
	vfprintf(stderr, why, ap);
	fprintf(stderr,"\n");
	va_end(ap);
	exit(1);
}

int zip_usage() {
	fprintf(stderr, "Usage: zip -i directory -o zip archive\n\n");
	return 1;
}

void write_int_le(void *buffer, long val, size_t bytes)
{
	uint8_t	*b = (uint8_t*)buffer;

	while (bytes) {
		--bytes;
		*(b++) = val &0xff;
		val >>= 8;
	}
}

long read_int_le(void *buffer, size_t bytes)
{
	uint8_t *b = (uint8_t*)buffer;
	long	val = 0;

	while (bytes) {
		--bytes;
		val <<= 8;
		val |= b[bytes];
	}
	return val;
}

uint32_t crc32(uint32_t crc, const uint8_t *buf, size_t len)
{
	static uint32_t table[256];
	static int have_table = 0;
	uint32_t rem;
	uint8_t octet;
	int i, j;
	const uint8_t *p, *q;
 
	/* This check is not thread safe; there is no mutex. */
	if (have_table == 0) {
		/* Calculate CRC table. */
		for (i = 0; i < 256; i++) {
			rem = i;  /* remainder from polynomial division */
			for (j = 0; j < 8; j++) {
				if (rem & 1) {
					rem >>= 1;
					rem ^= 0xedb88320;
				} else
					rem >>= 1;
			}
			table[i] = rem;
		}
		have_table = 1;
	}
 
	crc = ~crc;
	q = buf + len;
	for (p = buf; p < q; p++) {
		octet = *p;  /* Cast to unsigned octet. */
		crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
	}
	return ~crc;
}

void write_entry(int type, char *fname, char* name, struct stat *s)
{
	ZIP_HEADER* zh;
	ZIP_ENTRY	ze;
	MS_DOS_TIME	mt;
	MS_DOS_DATE	md;
	size_t		name_len;
	size_t		fpos;

#ifdef WIN32
	struct tm	*td;

	td = gmtime((const time_t*)&(s->st_mtime));
	md.date.day = td->tm_mday;
	md.date.month = td->tm_mon + 1;
	md.date.year = td->tm_year - 80;
	mt.time.seconds = td->tm_sec / 2;
	mt.time.minutes = td->tm_min;
	mt.time.hours = td->tm_hour;
#else
	md.val = 0;
	mt.val = 0;
#endif

	name_len = strlen(name);

	memset(&ze, 0, sizeof(ze));
	write_int_le(&(ze.magic), ZIP_ENTRY_MAGIC, sizeof(ze.magic));
	write_int_le(&(ze.version), type, sizeof(ze.version));
	write_int_le(&(ze.time), mt.val, sizeof(ze.time));
	write_int_le(&(ze.date), md.val, sizeof(ze.date));
	write_int_le(&(ze.comp_size), s->st_size, sizeof(ze.comp_size));
	write_int_le(&(ze.uncomp_size), s->st_size, sizeof(ze.uncomp_size));
	write_int_le(&(ze.fname_len), name_len, sizeof(ze.fname_len));

	fpos = ftell(zip_file);
	fwrite(&ze, 1, sizeof(ze), zip_file);
	fwrite(name, 1, name_len, zip_file);
	if (s->st_size != 0) {
		uint8_t		b[4096];
		size_t		flen = s->st_size;
		uint32_t	crc = 0;
		FILE		*f = fopen(fname, "rb");
		size_t		act_pos;

		if (f == NULL)
			die_zip("could not open %s\n", fname);

		while (flen) {
			size_t read;
			size_t toread = sizeof(b);

			if (toread > flen)
				toread = flen;

			read = fread(b, 1, toread, f);
			if (read != toread)
				die_zip("could not read from %s\n", fname);

			fwrite(b, 1, read, zip_file);
			crc = crc32(crc, b, read);
			flen -= read;
		}
		fclose(f);
		write_int_le(&(ze.crc), crc, sizeof(ze.crc));
		act_pos = ftell(zip_file);
		fseek(zip_file, fpos, SEEK_SET);
		fwrite(&ze, 1, sizeof(ze), zip_file);
		fseek(zip_file, act_pos, SEEK_SET);
	}

	if (zip_header_entries == zip_header_array) {
		int arr_size = zip_header_array + 8;
		ZIP_HEADER *arr = (ZIP_HEADER*)malloc(sizeof(ZIP_HEADER) * arr_size);
		if (arr == NULL)
			die_zip("out of memory");
		if (zip_headers) {
			memcpy(arr, zip_headers, sizeof(ZIP_HEADER) * zip_header_array);
			free(zip_headers);
		}
		zip_headers = arr;
		zip_header_array = arr_size;
	}

	zh = zip_headers + zip_header_entries;
	memset(zh, 0, sizeof(*zh));
	write_int_le(&(zh->magic), ZIP_DIR_MAGIC, sizeof(zh->magic));
	zh->creator = 0x3f;
	zh->version = ze.version;
	zh->time = ze.time;
	zh->date = ze.date;
	zh->crc = ze.crc;
	zh->comp_size = ze.comp_size;
	zh->uncomp_size = ze.uncomp_size;
	write_int_le(&(zh->offset), fpos, sizeof(zh->offset));
	zh->fname_len = ze.fname_len;
	strcpy((char*)&(zh->fname), name);
	zip_header_entries++;
}

void dump_dir(char *dir, int basedirlen)
{
	int				is_empty = 1;
	struct dirent	*de;
	struct stat		s;
	char			path[260];
#ifndef WIN32
	DIR				*d;
#else
	HANDLE			d;
	WIN32_FIND_DATA	ffd;
	wchar_t			dirname[MAX_PATH];
	int				first = 1;
#endif

#ifndef WIN32	
	d = opendir(dir);
	if(d == 0)
		die_zip("cannot open directory '%s'", dir);
	while ((de = readdir(d)) != 0) {
#else
	de = (struct dirent*)malloc(sizeof(*de));
	wsprintf(dirname, L"%S\\*.*", dir);
	d = FindFirstFile(dirname, &ffd);
	if(d == INVALID_HANDLE_VALUE)
		die_zip("cannot open directory '%s'", dir);
	while (first || FindNextFile(d, &ffd)) {
		if (first)
			first = 0;

		de->d_namlen = WideCharToMultiByte(CP_ACP, 0, ffd.cFileName, -1, de->d_name, MAX_PATH, 0, NULL);
#endif
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		is_empty = 0;

		sprintf(path, "%s/%s", dir, de->d_name);
		if (stat(path, &s))
			die_zip("could not stat '%s'\n", path);

		if ((s.st_mode & S_IFMT) == S_IFREG)
			write_entry(ZIP_VERSION_FILE, path, path+basedirlen+1, &s);
		else if ((s.st_mode & S_IFMT) == S_IFDIR)
			dump_dir(path, basedirlen);
	}

#ifndef WIN32	
	closedir(d);
#else
	FindClose(d);
	free(de);
#endif

	if (is_empty) {
		char dirname[260];

		stat(dir, &s);
		s.st_size = 0;
		sprintf(dirname, "%s/", dir + basedirlen + 1);
		write_entry(ZIP_VERSION_DIR, 0, dirname, &s);
	}
}

int main_zip(int argc, char* argv[])
{
	int				i;
	int				rc = 0;
	ZIP_END			trailer;
	size_t			dir_size;
	char			*zip_file_name = NULL;
	char			*indir = NULL;

	--argc;
	argv++;
	while(argc > 0){
		char *arg = argv[0];
		--argc;
		argv++;
		if (!strcmp(arg, "-q"))
			zip_quiet = 1;
		else if (argc >= 1) {
			char *val = argv[0];
			--argc;
			argv++;
			if (!strcmp(arg, "-o"))
				zip_file_name = val;
			else if (!strcmp(arg, "-i"))
				indir = val;
		} else {
			return zip_usage();
		}
	}

	if (!zip_file_name || !indir)
		return zip_usage();

	zip_file = fopen(zip_file_name, "wb");
	if (zip_file == NULL) {
		fprintf(stderr, "Error: Could not open file %s\n\n", zip_file_name);
		return 1;
	}

	dump_dir(indir, strlen(indir));

	memset(&trailer, 0, sizeof(trailer));
	write_int_le(&(trailer.magic), ZIP_TRAILER_MAGIC, sizeof(trailer.magic));
	write_int_le(&(trailer.dir_offset), ftell(zip_file), sizeof(trailer.dir_offset));
	dir_size = 0;

	for (i=0; i<zip_header_entries; i++) {
		size_t len = ZIP_HEADER_SIZE + read_int_le(&(zip_headers[i].fname_len), 2);
		fwrite(zip_headers+i, 1, len, zip_file);
		dir_size += len;
	}

	write_int_le(&(trailer.files_this_disc), zip_header_entries, sizeof(trailer.files_this_disc));
	write_int_le(&(trailer.files_total), zip_header_entries, sizeof(trailer.files_total));
	write_int_le(&(trailer.dir_size), dir_size, sizeof(trailer.dir_size));
	fwrite(&trailer, 1, sizeof(trailer), zip_file);

	if (zip_headers)
		free(zip_headers);


	fclose(zip_file);
	return rc;
}
