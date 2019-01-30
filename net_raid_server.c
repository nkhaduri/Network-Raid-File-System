#include "shared.h"
#include <openssl/md5.h>
#include <sys/epoll.h>


#define BACKLOG 1
#define HASH_ATTR "user.hash"

int cfd;
char* serv_path;

char* hash_file(char* full_path) {
    FILE* file = fopen(full_path, "rb");

    unsigned char c[MD5_DIGEST_LENGTH];
    MD5_CTX mdContext;
    int bytes;
    unsigned char data[1024];

    if (file == NULL) {
        // printf ("%s can't be opened.\n", full_path);
        return NULL;
    }

    MD5_Init (&mdContext);
    while ((bytes = fread (data, 1, 1024, file)) != 0)
        MD5_Update (&mdContext, data, bytes);
    MD5_Final (c, &mdContext);
    
    char* hash = malloc(2 * MD5_DIGEST_LENGTH + 1);
    assert(hash != NULL);
    int i = 0;
    for(; i < MD5_DIGEST_LENGTH; i++) 
        sprintf(&hash[i*2], "%02x", (unsigned int)c[i]);
    hash[2 * MD5_DIGEST_LENGTH] = '\0';
    
    fclose (file);
    return hash;
}

char* get_full_path(char path[PATH_MAX]) {
    if(strlen(serv_path) + strlen(path) > PATH_MAX) {
        // printf("Full path exceeded max length");
        return NULL;
    }

    char* full = malloc(strlen(serv_path) + strlen(path) + 1);
    assert(full != NULL);
    
    strcpy(full, serv_path);
    strcat(full, path);
    return full;
}

int serv_getattr(struct info getattr_info) {
    int status;
    
    // printf(">>>>>>>>>>>> GETATTR\n");

    struct getattr_t res; 
    char* full = get_full_path(getattr_info.path); 
    status = lstat(full, &(res.statbuf));
    // printf("full path: %s\n", full);
    free(full);
    
    if(status < 0)
        status = -errno;
    
    res.status = status;
    send(cfd, &res, sizeof(struct getattr_t), 0);

    // printf("status: %d\n\n", status);
    return status;
}

int serv_mknod(struct info mknod_info) {
    int status;
    
    // printf(">>>>>>>>>>>> MKNOD\n");

    char* full = get_full_path(mknod_info.path); 
    if (S_ISREG(mknod_info.mode)) {
        status = open(full, O_CREAT | O_EXCL | O_WRONLY, mknod_info.mode);
        if(status < 0)
            status = -errno;

        if (status >= 0) {
            status = close(status);
            if(status < 0)
                status = -errno;
        }
    } else {
        status = mknod(full, mknod_info.mode, mknod_info.dev);
        if(status < 0)
            status = -errno;
    }

    if(status >= 0) {
        char* hash = hash_file(full);
        setxattr(full, HASH_ATTR, hash, HASH_LENGTH, 0);
    }

    free(full);
    
    return status;
}

int serv_open(struct info open_info) {
    int status;
    
    // printf(">>>>>>>>>>>> OPEN\n");

    // printf("openpath: %s\n", open_info.path);
    char* full = get_full_path(open_info.path); 
    
    // printf("open flags: %d\n", open_info.flags);
    status = open(full, open_info.flags);
    // printf("open status: %d\n\n", status);
    if(status < 0)
        status = -errno;

    send(cfd, &status, sizeof(int), 0);
    if(status >= 0) {
        send(cfd, hash_file(full), HASH_LENGTH, 0);
        char value[HASH_LENGTH];
        ssize_t x = getxattr(full, HASH_ATTR, value, HASH_LENGTH);
        send(cfd, value, HASH_LENGTH, 0);
    }

    free(full);

    return status;
}

int serv_release(struct info release_info) {
    int status;
    
    // printf(">>>>>>>>>>>> RELEASE\n");
    
    status = close(release_info.fd);
    if(status < 0)
        status = -errno;

    return status;
}

int serv_unlink(struct info unlink_info) {
    int status;
    
    // printf(">>>>>>>>>>>> UNLINK\n");

    char* full = get_full_path(unlink_info.path); 
    
    status = unlink(full);
    if(status < 0)
        status = -errno;

    free(full);

    return status;
}

int serv_mkdir(struct info mkdir_info) {
    int status;
    
    // printf(">>>>>>>>>>>> MKDIR\n");

    char* full = get_full_path(mkdir_info.path); 
    
    status = mkdir(full, mkdir_info.mode);
    if(status < 0)
        status = -errno;

    free(full);

    return status;
}

uint64_t serv_opendir(struct info opendir_info) {
    int status = 0;
    
    // printf(">>>>>>>>>>>> OPENDIR\n");

    char* full = get_full_path(opendir_info.path); 
    
    DIR* stream = opendir(full);
    if(stream == NULL)
        status = -errno;
    
    // printf("path: %s\n", full);
    // printf("opendir status: %d\n\n", status);

    free(full);
    struct opendir_t res;
    res.status = status;
    res.dir = stream;
    send(cfd, &res, sizeof(struct opendir_t), 0);

    return status;
}

int serv_readdir(struct info readdir_info) {
    int status = 0;
    
    // printf(">>>>>>>>>>>> READDIR\n");

    DIR* stream = readdir_info.dir;
    struct dirent* dnt;
    char dirs[16000];
    dirs[0]= '\0';
    int k = 0;
    while((dnt = readdir(stream)) != NULL) {
        strcat(dirs, dnt->d_name);
        strcat(dirs, DIR_DELIM);
        k++;
    }

    if(k == 0)
        status = -errno;

    // printf("dirs: %s\n", dirs);
    // printf("READDIR status: %d\n\n", status);
    int bytes_to_pass = strlen(dirs) + 1;
    send(cfd, &bytes_to_pass, sizeof(int), 0);
    send(cfd, dirs, bytes_to_pass, 0);
    
    return status;
}

int serv_rmdir(struct info rmdir_info) {
    int status;
    
    // printf(">>>>>>>>>>>> MKDIR\n");

    char* full = get_full_path(rmdir_info.path); 
    
    status = rmdir(full);
    if(status < 0)
        status = -errno;

    free(full);

    return status;
}

int serv_releasedir(struct info readdir_info) {
    int status;
    
    // printf(">>>>>>>>>>>> RELEASEDIR\n");

    // printf("releasedir path: %s\n\n", readdir_info.path);

    DIR* stream = readdir_info.dir;
    status = closedir(stream);
    if(status < 0)
        status = -errno;
    
    return status;
}

int serv_rename(struct info rename_info) {
    int status;
    
    // printf(">>>>>>>>>>>> RENAME\n");

    char* full = get_full_path(rename_info.path); 
    char* newfull = get_full_path(rename_info.newpath);

    status = rename(full, newfull);
    if(status < 0)
        status = -errno;

    free(full);
    free(newfull);

    return status;
}

int64_t serv_read(struct info read_info) {
    int64_t status;
    
    // printf(">>>>>>>>>>>> READ\n");

    char* full = get_full_path(read_info.path);
    int fd = read_info.fd; 
    if(read_info.mode_change) {
        fd = fileno(fopen(full, "rb"));
    }

    char buf[read_info.size];
    buf[0] = '\0';

    // printf("read size: %lu\n", read_info.size);
    status = pread(fd, buf, read_info.size, read_info.offset);
    if(status < 0) {
        status = -errno;
    }

    // printf("read status: %li\n\n", status);

    send(cfd, buf, read_info.size, 0);
    send(cfd, &status, sizeof(int64_t), 0);

    if(read_info.mode_change) {
        close(fd);
    }

    free(full);

    return status;
}

int64_t serv_write(struct info write_info) {
    int64_t status;
    
    // printf(">>>>>>>>>>>> WRITE\n");

    char* full = get_full_path(write_info.path); 
    
    int fd = write_info.fd;
    if(write_info.mode_change == 1) {
        fd = fileno(fopen(full, "wb"));
    } else if(write_info.mode_change == 2) {
        fd = fileno(fopen(full, "ab"));
    }

    char buf[write_info.size];
    buf[0] = '\0';

    // printf("write size: %lu\n", write_info.size);
    recv(cfd, buf, write_info.size, 0);
    status = pwrite(fd, buf, write_info.size, write_info.offset);
    if(status < 0) { 
        status = -errno;
    }

    // printf("write status: %li\n\n", status);

    send(cfd, &status, sizeof(int64_t), 0);

    if(status >= 0) {
        setxattr(full, HASH_ATTR, hash_file(full), HASH_LENGTH, 0);
    }

    free(full);

    if(write_info.mode_change) {
        close(fd);
    }

    return status;
}

int serv_truncate(struct info truncate_info) {
    int status;
    
    // printf(">>>>>>>>>>>> TRUNCATE\n");

    char* full = get_full_path(truncate_info.path); 

    status = truncate(full, truncate_info.newsize);
    if(status < 0)
        status = -errno;

    free(full);

    return status;
}

int serv_utime(struct info utime_info) {
    int status;
    
    // printf(">>>>>>>>>>>> UTIME\n");

    struct utimbuf ubuf;
    recv(cfd, &ubuf, sizeof(struct utimbuf), 0);

    char* full = get_full_path(utime_info.path); 

    status = utime(full, &ubuf);
    if(status < 0)
        status = -errno;

    free(full);

    return status;
}

int serv_access(struct info access_info) {
    int status;
    
    // printf(">>>>>>>>>>>> ACCESS\n");

    char* full = get_full_path(access_info.path); 

    status = access(full, access_info.mask);
    if(status < 0)
        status = -errno;

    free(full);

    return status;
}

void client_handler() {
    char buf[WRITE_MAX];
    buf[0] = '\0';
    struct info passed_info; 

    int data_size, status;

    struct epoll_event ev, events[NUM_CLIENTS];
    int epollfd = epoll_create(NUM_CLIENTS);
    ev.events = EPOLLIN;
    ev.data.fd = cfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, cfd, &ev);

    while(true) {
        int nfds = epoll_wait(epollfd, events, NUM_CLIENTS, -1);
        int i;
        for(i = 0; i < nfds; i++) {
            int curr_sfd = events[i].data.fd;
            //printf("\ncurr sfd: %d\n", curr_sfd);
            data_size = recv(curr_sfd, &passed_info, sizeof(struct info), 0);
        }

        if(data_size <= 0)
            continue;

        switch(passed_info.id) {
            case _getattr:
                status = serv_getattr(passed_info);
                break;
            case _mknod:
                status = serv_mknod(passed_info);
                break;
            case _open:
                status = serv_open(passed_info);
                break;
            case _release:
                status = serv_release(passed_info);
                break;
            case _unlink:
                status = serv_unlink(passed_info);
                break;
            case _mkdir:
                status = serv_mkdir(passed_info);
                break;
            case _opendir:
                status = serv_opendir(passed_info);
                break;
            case _readdir:
                status = serv_readdir(passed_info);
                break;
            case _rmdir:
                status = serv_rmdir(passed_info);
                break;
            case _releasedir:
                status = serv_releasedir(passed_info);
                break;
            case _rename:
                status = serv_rename(passed_info);
                break;
            case _read:
                status = serv_read(passed_info);
                break;
            case _write:
                status = serv_write(passed_info);
                break;
            case _truncate:
                status = serv_truncate(passed_info);
                break;
            case _utime:
                status = serv_utime(passed_info);
                break;
            case _access:
                status = serv_access(passed_info);
                break;
            case _check:
                status = 0;
                break;
            default:
                break;
        }

        if(passed_info.id != _getattr && passed_info.id != _opendir && 
            passed_info.id != _read && passed_info.id != _write && passed_info.id != _open)
            send(cfd, &status, sizeof(int), 0);
    }
    
    close(cfd);
}

int main(int argc, char *argv[]) {
	if(argc != 4) {
		printf("Incompatible arguments\n");
		return 0;
	}

	char* ip = argv[1];
	char* port_str = argv[2];
	serv_path = argv[3];

	char* endptr;
	int port = strtol(port_str, &endptr, 10);
	if(*endptr != '\0') {
		printf("Invalid port");
		return 0;
	}

	int sfd;
    struct sockaddr_in addr;
    struct sockaddr_in peer_addr;

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    bind(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
    listen(sfd, BACKLOG);
    
    int peer_addr_size = sizeof(struct sockaddr_in);
    cfd = accept(sfd, (struct sockaddr *) &peer_addr, &peer_addr_size);

    // printf("----------Accepted connection %d\n", cfd);

    client_handler(cfd);

    close(sfd);

	return 0;
}