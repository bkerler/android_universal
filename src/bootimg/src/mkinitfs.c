// android / platform / system / core / master / . / cpio / mkbootfs.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include "android_filesystem_config.h"
#include <errno.h>

#ifdef WIN32
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
#define lstat(f,s) lstat_replacement(f,s)
#else
#include <unistd.h>
#include <dirent.h>
#endif

/* NOTES
**
** - see buffer-format.txt from the linux kernel docs for
**   an explanation of this file format
** - dotfiles are ignored
** - directories named 'root' are ignored
** - device notes, pipes, etc are not supported (error)
*/

#ifdef WIN32

int lstat_replacement(const char *path, struct stat *buf)
{
	static __int64				secs_to_epoc = 0;

	HANDLE						file;
	wchar_t						fname[MAX_PATH];
	int							fname_len, i;
	BY_HANDLE_FILE_INFORMATION	file_info;
	BOOL						success;
	__int64						ftime;
	time_t						utime;

	memset(buf, 0, sizeof(*buf));
	fname_len = MultiByteToWideChar(CP_ACP, 0, path, -1, fname, MAX_PATH);
	for (i = 0; i < fname_len; i++)
		if (fname[i] == L'/')
			fname[i] = L'\\';

	file = CreateFile(fname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		errno = EACCES;
		return -1;
	}

	success = GetFileInformationByHandle(file, &file_info);
	CloseHandle(file);

	if (!success) {
		errno = EACCES;
		return -1;
	}

	buf->st_size = file_info.nFileSizeLow;
	buf->st_mode = file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? S_IFDIR : S_IFREG;
	buf->st_mode |= 0644;

	if (secs_to_epoc == 0) {
		SYSTEMTIME st_epoc = { 1970, 1, 1, 1, 0, 0, 0, 0 };
		FILETIME ft;
		SystemTimeToFileTime(&st_epoc, &ft);
		secs_to_epoc = ft.dwHighDateTime;
		secs_to_epoc <<= 32;
		secs_to_epoc |= ft.dwLowDateTime;
		secs_to_epoc /= 10000000;
	}

	ftime = file_info.ftLastWriteTime.dwHighDateTime;
	ftime <<= 32;
	ftime |= file_info.ftLastWriteTime.dwLowDateTime;
	utime = ftime / 10000000;
	if (utime > secs_to_epoc)
		buf->st_mtime = utime - secs_to_epoc;

	return 0;
}
#endif

void die_mkinitfs(const char *why, ...)
{
	va_list ap;
	va_start(ap, why);
	fprintf(stderr,"error: ");
	vfprintf(stderr, why, ap);
	fprintf(stderr,"\n");
	va_end(ap);
	exit(1);
}

struct fs_config_entry {
	char* name;
	int uid, gid, mode;
};

static struct fs_config_entry* canned_config = NULL;
static char *target_out_path = NULL;
/* Each line in the canned file should be a path plus three ints (uid,
 * gid, mode). */
#ifdef PATH_MAX
#define CANNED_LINE_LENGTH  (PATH_MAX+100)
#else
#define CANNED_LINE_LENGTH  (1024)
#endif

static int verbose = 0;
static int total_size = 0;

static int perm_from_name(char *path, int *path_len)
{
	int	perm = 0;
	int len = *path_len;
	char c;
	int pos;

	if (len < 5 || path[len-5] != '@')
		return 0;

	for (pos = len-4; pos < len; pos++) {
		c = path[pos];
		if (c < '0' || c > '7')
			return 0;
		perm <<= 3;
		perm |= c - '0';
	}

	len -= 5;
	path[len] = 0;
	*path_len = len;

	return perm;
}

static void fix_stat(const char *path, int *path_len, struct stat *s)
{
	uint64_t	capabilities;

	if (canned_config) {
		struct fs_config_entry* empty_path_config = NULL;
		struct fs_config_entry* p;
		for (p = canned_config; p->name; ++p) {
			if (!p->name[0])
				empty_path_config = p;

			if (strcmp(p->name, path) == 0) {
				s->st_uid = p->uid;
				s->st_gid = p->gid;
				s->st_mode = p->mode | (s->st_mode & ~07777);
				return;
			}
		}
		s->st_uid = empty_path_config->uid;
		s->st_gid = empty_path_config->gid;
		s->st_mode = empty_path_config->mode | (s->st_mode & ~07777);
	} else {
		unsigned int	mode, uid, gid;

		uid = s->st_uid;
		gid = s->st_gid;
		mode = s->st_mode;
		fs_config(path, (s->st_mode & S_IFMT) == S_IFDIR, target_out_path, &uid, &gid, &mode, &capabilities);
		s->st_mode = mode;
		s->st_uid = uid;
		s->st_gid = gid;
	}
}

#define MIN_FAT_TIME (60*60*24)*((365*10)+2)

static void eject(struct stat *s, char *out, int olen, const char *data, unsigned datasize)
{
	static unsigned		next_inode = 300000;
	int					perm = 0;

	while (total_size & 3) {
		total_size++;
		putchar(0);
	}

	if ((s->st_mode & S_IFMT) != S_IFDIR)
		perm = perm_from_name(out, &olen);

	fix_stat(out, &olen, s);

	if (perm) {
		s->st_mode &= 0xf800;
		s->st_mode |= perm;
	}

	if (s->st_mtime == MIN_FAT_TIME)
		s->st_mtime = 0;

	if (verbose)
		fprintf(stderr, "_eject %s: mode=0%o\n", out, s->st_mode);

	printf("%06x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%s%c",
		   0x070701,
		   next_inode++,  //  s.st_ino,
		   s->st_mode,
		   0, // s.st_uid,
		   0, // s.st_gid,
		   1, // s.st_nlink,
		   (unsigned int)s->st_mtime, // s.st_mtime,
		   datasize,
		   0, // volmajor
		   0, // volminor
		   0, // devmajor
		   0, // devminor,
		   olen + 1,
		   0,
		   out,
		   0
		   );

	total_size += 6 + 8*13 + olen + 1;
	if(strlen(out) != (unsigned int)olen)
		die_mkinitfs("ACK!");

	while(total_size & 3) {
		total_size++;
		putchar(0);
	}

	if (datasize) {
		fwrite(data, datasize, 1, stdout);
		total_size += datasize;
	}
}

static void eject_trailer()
{
	struct stat s;
	memset(&s, 0, sizeof(s));
	eject(&s, "TRAILER!!!", 10, 0, 0);

	while(total_size & 0xff) {
		total_size++;
		putchar(0);
	}
}

static void archive(char *in, char *out, int ilen, int olen);

static int compare(const void* a, const void* b)
{
	return strcmp(*(const char**)a, *(const char**)b);
}

static void archive_subdir(char *in, char *out, int ilen, int olen)
{
	int i, t;
	struct dirent	*de;
	int				size;
	int				entries;
	char**			names;
#ifndef WIN32
	DIR				*d;
#else
	HANDLE			d;
	WIN32_FIND_DATA	ffd;
	wchar_t			dirname[MAX_PATH];
	int				first = 1;
#endif 

	if(verbose)
		fprintf(stderr,"_archive_dir('%s','%s',%d,%d)\n", in, out, ilen, olen);

#ifndef WIN32
	d = opendir(in);
	if(d == 0)
		die_mkinitfs("cannot open directory '%s'", in);
#else
	de = (struct dirent*)malloc(sizeof(*de));
	wsprintf(dirname, L"%S\\*.*", in);
	d = FindFirstFile(dirname, &ffd);
	if(d == INVALID_HANDLE_VALUE)
		die_mkinitfs("cannot open directory '%s'", in);
#endif

	size = 32;
	entries = 0;
	names = (char**)malloc(size * sizeof(char*));
	if (names == NULL) {
		fprintf(stderr, "failed to allocate dir names array (size %d)\n", size);
		exit(1);
	}

#ifndef WIN32
	while ((de = readdir(d)) != 0) {
#else
	while (first || FindNextFile(d, &ffd)) {
		if (first)
			first = 0;

		de->d_namlen = WideCharToMultiByte(CP_ACP, 0, ffd.cFileName, -1, de->d_name, MAX_PATH, 0, NULL);
#endif
		if (de->d_name[0] == '.')
			continue;

		if(!strcmp(de->d_name, "root"))
			continue;

		if (entries >= size) {
			size *= 2;
			names = (char**)realloc(names, size * sizeof(char*));
			if (names == NULL) {
				fprintf(stderr, "failed to reallocate dir names array (size %d)\n", size);
				exit(1);
			}
		}

		names[entries] = strdup(de->d_name);
		if (names[entries] == NULL) {
			fprintf(stderr, "failed to strdup name \"%s\"\n", de->d_name);
			exit(1);
		}
		++entries;
	}

	qsort(names, entries, sizeof(char*), compare);
	for (i = 0; i < entries; ++i) {
		t = strlen(names[i]);
		in[ilen] = '/';
		memcpy(in + ilen + 1, names[i], t + 1);
		if(olen > 0) {
			out[olen] = '/';
			memcpy(out + olen + 1, names[i], t + 1);
			archive(in, out, ilen + t + 1, olen + t + 1);
		} else {
			memcpy(out, names[i], t + 1);
			archive(in, out, ilen + t + 1, t);
		}
		in[ilen] = 0;
		out[olen] = 0;
		free(names[i]);
	}
	free(names);

#ifndef WIN32	
	closedir(d);
#else
	FindClose(d);
	free(de);
#endif
}

static void archive(char *in, char *out, int ilen, int olen)
{
	struct	stat s;
	FILE	*f;

	if (verbose)
		fprintf(stderr,"archive('%s','%s',%d,%d)\n", in, out, ilen, olen);

	if (lstat(in, &s))
		die_mkinitfs("could not stat '%s, reason: %d'\n", in, errno);

	if (olen > 7 && 0 == strcmp(out+olen-7, "__lnk__")) {
		s.st_mode &= 0xfff;
		s.st_mode |= S_IFLNK;
		olen -= 7;
		out[olen] = 0;
	}

	if ((s.st_mode & S_IFMT) == S_IFREG) {
		char	*tmp;

		f = fopen(in, "rb");
		if (f == NULL)
			die_mkinitfs("cannot open '%s' for read", in);

		tmp = (char*) malloc(s.st_size);
		if(tmp == 0)
			die_mkinitfs("cannot allocate %d bytes", s.st_size);

		if (fread(tmp, 1, s.st_size, f) != s.st_size)
			die_mkinitfs("cannot read %d bytes", s.st_size);

		eject(&s, out, olen, tmp, s.st_size);
		free(tmp);
		fclose(f);
	} else if ((s.st_mode & S_IFMT) == S_IFDIR) {
		eject(&s, out, olen, 0, 0);
		archive_subdir(in, out, ilen, olen);
	} else if ((s.st_mode & S_IFMT) == S_IFLNK) {
		char	buf[1024];
		int		size = -1;

#ifndef WIN32
		size = readlink(in, buf, 1024);
#endif
		if (size < 0) {
			f = fopen(in, "rb");

			if (f == NULL)
				die_mkinitfs("cannot read symlink '%s'", in);
			size = fread(buf, 1, s.st_size, f);
			fclose(f);
		}
		eject(&s, out, olen, buf, size);
	} else
		die_mkinitfs("Unknown '%s' (mode %d)?\n", in, s.st_mode);
}

void archive_dir(const char *start, const char *prefix)
{
	char	in[8192];
	char	out[8192];

	strcpy(in, start);
	strcpy(out, prefix);
	archive_subdir(in, out, strlen(in), strlen(out));
}

static void read_canned_config(char* filename)
{
	int		allocated = 8;
	int		used = 0;
	char	line[CANNED_LINE_LENGTH];
	FILE	*f;

	canned_config = (struct fs_config_entry*)malloc(allocated * sizeof(struct fs_config_entry));
	f = fopen(filename, "r");
	if (f == NULL)
		die_mkinitfs("failed to open canned file");

	while (fgets(line, CANNED_LINE_LENGTH, f) != NULL) {
		struct fs_config_entry* cc;
		
		if (!line[0])
			break;

		if (used >= allocated) {
			allocated *= 2;
			canned_config = (struct fs_config_entry*)realloc(canned_config, allocated * sizeof(struct fs_config_entry));
		}

		cc = canned_config + used;
		if (isspace(line[0])) {
			cc->name = strdup("");
			cc->uid = atoi(strtok(line, " \n"));
		} else {
			cc->name = strdup(strtok(line, " \n"));
			cc->uid = atoi(strtok(NULL, " \n"));
		}
		cc->gid = atoi(strtok(NULL, " \n"));
		cc->mode = strtol(strtok(NULL, " \n"), NULL, 8);
		++used;
	}
	if (used >= allocated) {
		++allocated;
		canned_config = (struct fs_config_entry*)realloc(
			canned_config, allocated * sizeof(struct fs_config_entry));
	}
	canned_config[used].name = NULL;
	fclose(f);
}

int main_mkinitfs(int argc, char *argv[])
{
	argc--;
	argv++;
	if (argc > 1 && strcmp(argv[0], "-d") == 0) {
		target_out_path = argv[1];
		argc -= 2;
		argv += 2;
	}
	if (argc > 1 && strcmp(argv[0], "-f") == 0) {
		read_canned_config(argv[1]);
		argc -= 2;
		argv += 2;
	}

	if(argc == 0)
		die_mkinitfs("no directories to process?!");

#ifdef WIN32
	_setmode(_fileno(stdout), O_BINARY);
#endif

	while(argc-- > 0){
		char *x = strchr(*argv, '=');
		if(x != 0) {
			*x++ = 0;
		} else {
			x = "";
		}
		archive_dir(*argv, x);
		argv++;
	}

	eject_trailer();
	return 0;
}
