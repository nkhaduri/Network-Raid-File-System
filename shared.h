#ifndef SHARED_H
#define SHARED_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/xattr.h>

#define WRITE_MAX 4096
#define DELIM "="
#define SERVERS_DELIM ","
#define PORT_DELIM ":"
#define DIR_DELIM "/"
#define INIT_DISKS_SIZE 5
#define INIT_SERVERS_SIZE 5
#define HASH_LENGTH 33
#define NUM_CLIENTS 1

enum operation_id {
	zero,
	_getattr,
	_mknod,
	_open,
	_release,
	_unlink,
	_mkdir,
	_opendir,
	_readdir,
	_rmdir,
	_releasedir,
	_rename,
	_read,
	_write,
	_truncate,
	_utime,
	_access,
	_check
};

struct info {
	enum operation_id id;
	char path[PATH_MAX];
	mode_t mode;
	dev_t dev;
	int flags;
	char newpath[PATH_MAX];
	int fd;
	DIR* dir;
	size_t size;
	off_t offset;
	off_t newsize;
	int mask;
	int mode_change;
};

struct getattr_t {
	struct stat statbuf;
	int status;
};

struct opendir_t{
	int status;
	DIR* dir;
};

#endif