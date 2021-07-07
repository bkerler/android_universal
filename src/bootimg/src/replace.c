#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef WIN32
#include <utime.h>
#else
#include <sys/utime.h>
#endif

int main_replace(int argc, char** argv)
{
	char				*str = NULL;
	size_t				str_len = 0;
	char				*replace = NULL;
	size_t				replace_len = 0;
	char				*file = NULL;
	FILE				*f;
	int					quiet = 0;
	int					modified = 0;

	unsigned char		buffer[4096];
	size_t				buffer_len;
	size_t				read;
	size_t				file_pos;
	size_t				p;
	size_t				len;
	size_t				current_file_pos;
	struct	stat		s;
	struct utimbuf		times;

	--argc;
	argv++;
	while (argc > 0){
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
			else if (!strcmp(arg, "-s"))
				str = val;
			else if (!strcmp(arg, "-r"))
				replace = val;
		}
	}

	if (!file || !str || !replace) {
		fprintf(stderr, "Usage: replace -i file -s string -r replace[ -q ]\n");
		return 1;
	}

	str_len = strlen(str);
	replace_len = strlen(replace);
	if (replace_len > str_len) {
		fprintf(stderr, "The replace string needs to be shorter than the string to be replaced\n");
		return 1;
	}

	f = fopen(file, "r+b");
	if (f == 0) {
		if (!quiet)
			fprintf(stderr, "Could not open file %s\n\n", file);
		return 2;
	}

	buffer_len = 0;
	file_pos = 0;
	while (1) {
		read = fread(buffer + buffer_len, 1, sizeof(buffer)-buffer_len, f);
		if (read == 0)
			break;

		if (read < 0)
			return 2;

		buffer_len += read;

		for (p = 0; p < buffer_len - str_len; p++) {
			if (memcmp(buffer + p, str, str_len))
				continue;

			if (p != 0) {
				file_pos += p;
				buffer_len -= p;
				memmove(buffer, buffer + p, buffer_len);

				read = fread(buffer + buffer_len, 1, sizeof(buffer) - buffer_len, f);
				if (read < 0)
					return 2;

				buffer_len += read;
				p = 0;
			}

			for (len = 0; len < 256 && buffer[len] != 0; len++);
			if (len >= 256)
				continue;

			len++;
			if (!quiet)
				fprintf(stdout, "%s", buffer);
			memcpy(buffer, replace, replace_len);
			memcpy(buffer + replace_len, buffer + str_len, len - str_len);
			if (!quiet)
				fprintf(stdout, " -> %s\n", buffer);

			if (modified == 0) {
				modified = 1;
				stat(file, &s);
			}

			current_file_pos = ftell(f);
			fseek(f, file_pos, SEEK_SET);
			fwrite(buffer, 1, len, f);
			fseek(f, current_file_pos, SEEK_SET);
		}

		if (buffer_len > str_len) {
			file_pos += buffer_len - str_len;
			memmove(buffer, buffer + buffer_len - str_len, str_len);
			buffer_len = str_len;
		}
		else {
			file_pos += buffer_len;
			buffer_len = 0;
		}
	}

	fclose(f);

	if (modified) {
		times.actime = s.st_atime;
		times.modtime = s.st_mtime;
		utime(file, &times);
	}

	return 0;
}
