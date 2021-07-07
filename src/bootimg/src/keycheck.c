#ifndef WIN32
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/poll.h>
#include <linux/input.h>
#include <errno.h>
#ifndef WIN32
    #include <time.h>
#endif
static struct pollfd *ufds;
static char **device_names;
static int nfds;

static int open_device(const char *device)
{
	int version;
	int fd;
	int clkid = CLOCK_MONOTONIC;
	struct pollfd *new_ufds;
	char **new_device_names;
	char name[80];
	char location[80];
	char idstr[80];
	struct input_id id;

	fd = open(device, O_RDWR);
	if(fd < 0)
		return -1;

	if(ioctl(fd, EVIOCGVERSION, &version))
		return -1;

	if(ioctl(fd, EVIOCGID, &id))
		return -1;

	name[sizeof(name) - 1] = '\0';
	location[sizeof(location) - 1] = '\0';
	idstr[sizeof(idstr) - 1] = '\0';

	if(ioctl(fd, EVIOCGNAME(sizeof(name) - 1), &name) < 1)
		name[0] = '\0';

	if(ioctl(fd, EVIOCGPHYS(sizeof(location) - 1), &location) < 1)
		location[0] = '\0';

	if(ioctl(fd, EVIOCGUNIQ(sizeof(idstr) - 1), &idstr) < 1)
		idstr[0] = '\0';

	if (ioctl(fd, EVIOCSCLOCKID, &clkid) != 0) {
		//fprintf(stderr, "Can't enable monotonic clock reporting: %s\n", strerror(errno));
		// a non-fatal error
	}

	new_ufds = realloc(ufds, sizeof(ufds[0]) * (nfds + 1));

	if(new_ufds == NULL)
		return -1;

	ufds = new_ufds;
	new_device_names = realloc(device_names, sizeof(device_names[0]) * (nfds + 1));

	if(new_device_names == NULL)
		return -1;

	device_names = new_device_names;

	ufds[nfds].fd = fd;
	ufds[nfds].events = POLLIN;
	device_names[nfds] = strdup(device);
	nfds++;

	return 0;
}

int close_device(const char *device)
{
	int i;
	for (i=1; i<nfds; i++) {
		if (strcmp(device_names[i], device) == 0) {
			int count = nfds - i - 1;
			free(device_names[i]);
			memmove(device_names + i, device_names + i + 1, sizeof(device_names[0]) * count);
			memmove(ufds + i, ufds + i + 1, sizeof(ufds[0]) * count);
			nfds--;
			return 0;
		}
	}
	return -1;
}

static int read_notify(const char *dirname, int nfd)
{
	int res;
	char devname[PATH_MAX];
	char *filename;
	char event_buf[512];
	int event_size;
	int event_pos = 0;
	struct inotify_event *event;

	res = read(nfd, event_buf, sizeof(event_buf));
	if (res<(int)sizeof(*event)) {
		if (errno == EINTR)
			return 0;
		return 1;
	}

	strcpy(devname, dirname);
	filename = devname + strlen(devname);
	*filename++ = '/';

	while (res >= (int)sizeof(*event)) {
		event = (struct inotify_event *)(event_buf + event_pos);

		if(event->len) {
			strcpy(filename, event->name);
			if(event->mask & IN_CREATE) {
				open_device(devname);
			}
			else {
				close_device(devname);
			}
		}
		event_size = sizeof(*event) + event->len;
		res -= event_size;
		event_pos += event_size;
	}
	return 0;
}

static int scan_dir(const char *dirname)
{
	char devname[PATH_MAX];
	char *filename;
	DIR *dir;
	struct dirent *de;

	dir = opendir(dirname);
	if (dir == NULL)
		return -1;
	
	strcpy(devname, dirname);
	filename = devname + strlen(devname);
	*filename++ = '/';
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.' &&
		   (de->d_name[1] == '\0' ||
		   (de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		strcpy(filename, de->d_name);
		open_device(devname);
	}
	closedir(dir);
	return 0;
}

int main_keycheck(int argc, char *argv[]) {
	int i;
	int res;
	struct input_event event;
	int event_count = 0;
	const char *device_path = "/dev/input";

	nfds = 1;
	ufds = calloc(1, sizeof(ufds[0]));
	ufds[0].fd = inotify_init();
	ufds[0].events = POLLIN;

	res = inotify_add_watch(ufds[0].fd, device_path, IN_DELETE | IN_CREATE);
	if (res < 0)
		return 1;

	res = scan_dir(device_path);
	if (res < 0)
		return 1;

	while (1) {
		poll(ufds, nfds, -1);

		if (ufds[0].revents & POLLIN)
			read_notify(device_path, ufds[0].fd);

		for (i=1; i<nfds; i++) {
			if (ufds[i].revents) {
				if (ufds[i].revents & POLLIN) {
					res = read(ufds[i].fd, &event, sizeof(event));
					if (res < (int)sizeof(event))
						return 1;

					if (event.code == KEY_VOLUMEDOWN || event.code == KEY_VOLUMEUP)
						return event.code;

					if(event_count && --event_count == 0)
						return 0;
				}
			}
		}
	}
}
#endif
