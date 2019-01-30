#define FUSE_USE_VERSION 26
#define FDPATHS_INIT_SIZE 5
#define CACHE_INIT_LEN 5

#include <fuse.h>
#include <pthread.h>
#include "shared.h"

struct cache_entry {
	char* path;
	off_t offset;
	size_t size;
	char* data;
	time_t last_use;
};

struct cache {
	struct cache_entry* entries;
	size_t log_len;
	size_t alloc_len;
	size_t cache_size;
};

struct client {
	char* errorlog;
	uint64_t cache_size;
	char* cache_replacement;
	size_t timeout;
};

struct disk {
	char* diskname;
	char* mountpoint;
	size_t raid;
	char** servers;
	int* ports;
	int* sfds;
	char* hotswap;
	int hotswap_port;
	size_t num_servers;
	size_t servers_size;
	char** fdpaths;
	size_t fdpaths_size;
	pthread_mutex_t* mutexes;
	struct cache* cache;
};

struct server_checker_data {
	size_t ind;
	time_t** last_server_checks;
	pthread_mutex_t* mutex;
	struct disk* d;
};


struct client* cl; 
struct disk** disks;
size_t disks_size, num_disks;
FILE* log_file;
bool hotswap_added, server_down[2]; 
pthread_mutex_t hotswap_mutex; 

bool parse_client(char* str) {
	char* key = strtok(str, DELIM);
   	
   	char* value = strtok(NULL, DELIM);
   	if(value != NULL) {
   		value++;
   	} else
   		return false;

   	if(value[strlen(value) - 1] == ' ' || value[strlen(value) - 1] == '\n') {
   		value[strlen(value) - 1] = '\0';
   	}

	if(!strcmp(key, "errorlog ")) {
		cl->errorlog = malloc(strlen(value) + 1);
		assert(cl->errorlog != NULL);

		strcpy(cl->errorlog, value);
		return true;
	} else if(!strcmp(key, "cache_size ")) {
		if(value[strlen(value) - 1] == 'K') {
			cl->cache_size = 1024;
		} else if(value[strlen(value) - 1] == 'M') {
			cl->cache_size = 1024 * 1024;
		} else if(value[strlen(value) - 1] == 'G') {
			cl->cache_size = 1024 * 1024 * 1024;
		} else {
			return false;
		}

		value[strlen(value) - 1] = '\0';

		char* endptr;
		cl->cache_size *= strtoll(value, &endptr, 10);
		if(*endptr != '\0') {
			return false;
		}
		return true;
	} else if(!strcmp(key, "cache_replacement ")) {
		cl->cache_replacement = malloc(strlen(value) + 1);
		assert(cl->cache_replacement != NULL);

		strcpy(cl->cache_replacement, value);
		return true;
	} else if(!strcmp(key, "timeout ")) {
		char* endptr;
		cl->timeout = strtol(value, &endptr, 10);
		if(*endptr != '\0') {
			return false;
		}
		return true;
	}

	return false;
}

bool parse_disk(char* str) {
	char* key = strtok(str, DELIM);
   	
   	char* value = strtok(NULL, DELIM);
   	if(value != NULL) {
   		value++;
   	} else
   		return false;

   	if(value[strlen(value) - 1] == ' ' || value[strlen(value) - 1] == '\n') {
   		value[strlen(value) - 1] = '\0';
   	}

	if(!strcmp(key, "diskname ")) {
		disks[num_disks]->diskname = malloc(strlen(value) + 1);
		assert(disks[num_disks]->diskname != NULL);

		strcpy(disks[num_disks]->diskname, value);
		return true;
	} else if(!strcmp(key, "mountpoint ")) {
		disks[num_disks]->mountpoint = malloc(strlen(value) + 1);
		assert(disks[num_disks]->mountpoint != NULL);

		strcpy(disks[num_disks]->mountpoint, value);
		return true;
	} else if(!strcmp(key, "raid ")) {
		char* endptr;
		disks[num_disks]->raid = strtol(value, &endptr, 10);
		if(*endptr != '\0') {
			return false;
		}
		return true;
	} else if(!strcmp(key, "servers ")) {
		disks[num_disks]->servers = malloc(INIT_SERVERS_SIZE * sizeof(char*));
		assert(disks[num_disks]->servers != NULL);
		disks[num_disks]->ports = malloc(INIT_SERVERS_SIZE * sizeof(int));
		assert(disks[num_disks]->ports != NULL);
		
		char* token = strtok(value, SERVERS_DELIM);

		disks[num_disks]->num_servers = 0;
		disks[num_disks]->servers_size = INIT_SERVERS_SIZE;
		char* serv;
		char* port_str;
		while(token != NULL) {
			value += strlen(token) + 1;
			if(token[0] == ' ')
				token++;
			
			serv = strtok(token, PORT_DELIM);
			port_str = strtok(NULL, PORT_DELIM);
			char* endptr;
			disks[num_disks]->ports[disks[num_disks]->num_servers] = strtol(port_str, &endptr, 10);
			if(*endptr != '\0') {
				return false;
			}

			disks[num_disks]->servers[disks[num_disks]->num_servers] = malloc(strlen(serv) + 1);
			assert(disks[num_disks]->servers[disks[num_disks]->num_servers] != NULL);
			strcpy(disks[num_disks]->servers[disks[num_disks]->num_servers], serv);

			disks[num_disks]->num_servers++;
			if(disks[num_disks]->num_servers > disks[num_disks]->servers_size) {
				disks[num_disks]->servers_size *= 2;
				disks[num_disks]->servers = realloc(disks[num_disks]->servers, disks[num_disks]->servers_size * sizeof(char*));
				assert(disks[num_disks]->servers != NULL);
				disks[num_disks]->ports = realloc(disks[num_disks]->servers, disks[num_disks]->servers_size * sizeof(char*));
				assert(disks[num_disks]->ports != NULL);
			}

			token = strtok(value, SERVERS_DELIM);
		}

		return true;
	} else if(!strcmp(key, "hotswap ")) {
		char* serv = strtok(value, PORT_DELIM);
		char* port_str = strtok(NULL, PORT_DELIM);
		
		char* endptr;
		disks[num_disks]->hotswap_port = strtol(port_str, &endptr, 10);
		if(*endptr != '\0') {
			return false;
		}
		disks[num_disks]->hotswap = malloc(strlen(serv) + 1);
		assert(disks[num_disks]->hotswap != NULL);

		strcpy(disks[num_disks]->hotswap, serv);
		return true;
	}

	return false;
}

bool parse(char* str, bool flag) {
	if(!flag)
		return parse_client(str);

	return parse_disk(str);
}

void log_in_file(const char* action, struct disk* d, int serv_ind) {
	time_t t = time(NULL);
	struct tm* t_info = localtime(&t);
	char* time_str = asctime(t_info);
	time_str[strlen(time_str) - 1] = '\0';
	fprintf(log_file, "[%s] %s %s:%d %s\n", time_str, d->diskname, d->servers[serv_ind], d->ports[serv_ind], action);
	fflush(log_file);
}

void regenerate_file(int sfd_from, int sfd_to, pthread_mutex_t* mutex_from, pthread_mutex_t* mutex_to, const char* path) {
    struct info pass_info;
    int64_t status = -1, size = 4096;
    off_t offset = 0;
	strcpy(pass_info.path, path);
    while(true) {
    	// printf("\n\n\nREGENERATE FILE: %li %lu \n", status, offset);
    	pass_info.id = _read;
		pass_info.size = size;
		pass_info.offset = offset;
	    pass_info.mode_change = 1;
		char buf[size];

		pthread_mutex_lock(mutex_from);
		send(sfd_from, &pass_info, sizeof(struct info), 0);
		recv(sfd_from, buf, size, 0);
    	recv(sfd_from, &status, sizeof(int64_t), 0);
    	pthread_mutex_unlock(mutex_from);

    	// printf("REGENERATE FILE read status: %li\n", status);
    	if(status <= 0)
    		break;

    	size = status;

    	pass_info.id = _write;
	    pass_info.size = size;
	    pass_info.offset = offset;
	    if(offset > 0)
	    	pass_info.mode_change = 2;

	    pthread_mutex_lock(mutex_to);
	    send(sfd_to, &pass_info, sizeof(struct info), 0);
	    send(sfd_to, buf, size, 0);
	    recv(sfd_to, &status, sizeof(int64_t), 0);
	    pthread_mutex_unlock(mutex_to);

	    // printf("REGENERATE FILE write status: %li\n", status);
	    if(status < 0)
	    	break;

	    offset += size;
    }
}

int recreate_file(int sfd_from, int sfd_to, pthread_mutex_t* mutex_from, pthread_mutex_t* mutex_to, const char* path, int flags) {
	int status = -1;
	struct info pass_info;

    pass_info.id = _mknod;
    strcpy(pass_info.path, path);
    pass_info.mode = 0666;
    
    pthread_mutex_lock(mutex_to);
    send(sfd_to, &pass_info, sizeof(struct info), 0);
    recv(sfd_to, &status, sizeof(int), 0);
    pthread_mutex_unlock(mutex_to);

    // printf("recreate path: %s\nrecreate status: %d\n", path, status);

    if(status < 0) 
    	return status;

    if(flags != -1) {
	    pass_info.id = _open;
	    strcpy(pass_info.path, path);
	    pass_info.flags = flags;

	    pthread_mutex_lock(mutex_to);
	    send(sfd_to, &pass_info, sizeof(struct info), 0);
	    recv(sfd_to, &status, sizeof(int), 0);

	    if (status >= 0){
	    	char hash_temp[HASH_LENGTH];
			recv(sfd_to, hash_temp, HASH_LENGTH, 0);
			recv(sfd_to, hash_temp, HASH_LENGTH, 0);
	    }
	    pthread_mutex_unlock(mutex_to);
	}

    regenerate_file(sfd_from, sfd_to, mutex_from, mutex_to, path);
    return status;
}

void hotswap_rec(const char* path, struct disk* d, int hotswap_ind, int sfd_ind) {
	// printf("hotswap rec path: %s\n\n", path);
	struct info pass_info;
	int status;

	pass_info.id = _getattr;
    strcpy(pass_info.path, path);

    pthread_mutex_lock(&d->mutexes[sfd_ind]);
    send(d->sfds[sfd_ind], &pass_info, sizeof(struct info), 0);
    struct getattr_t res;
    recv(d->sfds[sfd_ind], &res, sizeof(struct getattr_t), 0);
    pthread_mutex_unlock(&d->mutexes[sfd_ind]);
    if(S_ISREG(res.statbuf.st_mode)) {
    	recreate_file(d->sfds[sfd_ind], d->sfds[hotswap_ind], &d->mutexes[sfd_ind], &d->mutexes[sfd_ind], path, -1);
    } else {
    	pass_info.id = _mkdir;
	    strcpy(pass_info.path, path);
	    pass_info.mode = 0777;
	    send(d->sfds[hotswap_ind], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[hotswap_ind], &status, sizeof(int), 0);

		pass_info.id = _opendir;
	    strcpy(pass_info.path, path);
	    pthread_mutex_lock(&d->mutexes[sfd_ind]);
	    send(d->sfds[sfd_ind], &pass_info, sizeof(struct info), 0);
	    struct opendir_t res;
	    recv(d->sfds[sfd_ind], &res, sizeof(struct opendir_t), 0);
	    pthread_mutex_unlock(&d->mutexes[sfd_ind]);
	    // printf("hotswap opendir status %d\n\n", res.status);

	    if(res.status < 0) 
	    	return;

	    pass_info.id = _readdir;
	    pass_info.dir = res.dir;
	    pthread_mutex_lock(&d->mutexes[sfd_ind]);
	    send(d->sfds[sfd_ind], &pass_info, sizeof(struct info), 0);

	    int bytes_to_read;
	    recv(d->sfds[sfd_ind], &bytes_to_read, sizeof(int), 0);
	    
	    char dirs[16000];
	    dirs[0] = '\0';
	    recv(d->sfds[sfd_ind], dirs, bytes_to_read, 0);
	    // printf("hotswap READDIR paths: %s\n", dirs);

	    recv(d->sfds[sfd_ind], &status, sizeof(int), 0);
	    // printf("hotswap READDIR status: %d\n\n", status);

	    pthread_mutex_unlock(&d->mutexes[sfd_ind]);
	    char* dirs_tmp = dirs;
	    char* token = strtok(dirs_tmp, DIR_DELIM);
	    while(token != NULL) {
	    	dirs_tmp += strlen(token) + 1;
	    	if(strcmp(token, ".") != 0 && strcmp(token, "..") != 0) {
		    	char newpath[PATH_MAX];
		    	strcpy(newpath, path);
		    	if(path[strlen(path) - 1] != '/')
		    		strcat(newpath, "/");
		    	strcat(newpath, token);
		    	hotswap_rec(newpath, d, hotswap_ind, sfd_ind);
	    	}
	    	token = strtok(dirs_tmp, DIR_DELIM);
	    }

	    pass_info.id = _releasedir;
	 	pass_info.dir = res.dir;
	 	pthread_mutex_lock(&d->mutexes[sfd_ind]);
	    send(d->sfds[sfd_ind], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[sfd_ind], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[sfd_ind]);
    }
	
}

void add_hotswap(struct disk* d, int sfd_ind) {
	pthread_mutex_lock(&hotswap_mutex);
	if(hotswap_added)
		return;
	hotswap_added = true;
	pthread_mutex_unlock(&hotswap_mutex);

	int hotswap_ind = 1 - sfd_ind;
	struct sockaddr_in addr;
	int ip;
    d->sfds[hotswap_ind] = socket(AF_INET, SOCK_STREAM, 0);
    inet_pton(AF_INET, d->hotswap, &ip);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(d->hotswap_port);
    addr.sin_addr.s_addr = ip;

    connect(d->sfds[hotswap_ind], (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
    strcpy(d->servers[hotswap_ind], d->hotswap);
    d->ports[hotswap_ind] = d->hotswap_port;
    log_in_file("open connection (hotswap)", d, hotswap_ind);

    pthread_mutex_lock(&d->mutexes[hotswap_ind]);
	hotswap_rec("/", d, hotswap_ind, sfd_ind);  
    pthread_mutex_unlock(&d->mutexes[hotswap_ind]);

    log_in_file("duplicated remaining server to hotswap server", d, hotswap_ind);
}


void* server_checker(void* d) {
	struct server_checker_data* data = (struct server_checker_data*) d;
	// printf("server checker %lu started\n", data->ind);
	struct info pass_info;
	pass_info.id = _check;
	time_t curr_time; 
	bool down = false;
	struct sockaddr_in addr;
	int ip;
	while(true) {
		//printf("checker %lu before lock\n", data->ind);
		pthread_mutex_lock(data->mutex);
		//printf("checker %lu after lock\n", data->ind);
		int status = -1;
		if(!down) {
			send(data->d->sfds[data->ind], &pass_info, sizeof(struct info), 0);
			recv(data->d->sfds[data->ind], &status, sizeof(int), 0);
		} else {
		    data->d->sfds[data->ind] = socket(AF_INET, SOCK_STREAM, 0);
		    inet_pton(AF_INET, data->d->servers[data->ind], &ip);

		    addr.sin_family = AF_INET;
		    addr.sin_port = htons(data->d->ports[data->ind]);
		    addr.sin_addr.s_addr = ip;

		    status = connect(data->d->sfds[data->ind], (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
		}

		if(status == 0) {
			time(data->last_server_checks[data->ind]);
			if(down) {
				down = false;
				log_in_file("connection restored", data->d, data->ind);
			}
		} else {
			down = true;
			log_in_file("server not responding", data->d, data->ind);
			time(&curr_time);
			double diff = difftime(curr_time, *data->last_server_checks[data->ind]);
			if(diff >= cl->timeout) {
				// printf("\n------------SERVER %lu LOST\n", data->ind);
				log_in_file("server declared as lost", data->d, data->ind);
				if(!hotswap_added) {
					pthread_mutex_unlock(data->mutex);
					add_hotswap(data->d, 1 - data->ind);
					down = false;
					pthread_mutex_lock(data->mutex);
				} else {
					server_down[data->ind] = true;
					pthread_mutex_unlock(data->mutex);
					pthread_exit(0);
				}
			}
		}
		pthread_mutex_unlock(data->mutex);
		//printf("checker %lu after unlock\n", data->ind);
		sleep(1);
	}
	return NULL;
}

void delete_damaged(int sfd, const char* path) {
	int status;
	struct info pass_info;
	pass_info.id = _unlink;
    strcpy(pass_info.path, path);
    send(sfd, &pass_info, sizeof(struct info), 0);
    recv(sfd, &status, sizeof(int), 0);
}

int get_fdpath(char** fdpaths, const char* path, int n) {
	int i = 0;
	for(; i < n; i++) {
		if(fdpaths[i] != NULL && !strcmp(path, fdpaths[i])) 
			return i;
	}
	return -1;
}

int search_cache(struct cache* cache, const char* path, off_t offset, size_t size) {
	int i = 0;
	for(; i < cache->log_len; i++) {
		if(!strcmp(cache->entries[i].path, path) && cache->entries[i].offset == offset && cache->entries[i].size <= size) {
			time(&cache->entries[i].last_use);
			return i;
		}
	}
	return -1;
}

void cache_add_on_index(struct cache* cache, const char* path, off_t offset, size_t size, char* buf, int index) {
	cache->entries[index].path = malloc(strlen(path) + 1);
	assert(cache->entries[index].path != NULL);
	strcpy(cache->entries[index].path, path);

	cache->entries[index].offset = offset;
	cache->entries[index].size = size;			

	cache->entries[index].data = malloc(size);
	assert(cache->entries[index].data != NULL);
	memcpy(cache->entries[index].data, buf, size);

	cache->cache_size += size;
}

void add_to_cache(struct cache* cache, const char* path, off_t offset, size_t size, char* buf) {
	if(cache->cache_size + size <= cl->cache_size) {
		if(cache->log_len == cache->alloc_len) {
			cache->alloc_len *= 2;
			cache->entries = realloc(cache->entries, cache->alloc_len * sizeof(struct cache_entry));
			assert(cache->entries != NULL);
		}
		cache_add_on_index(cache, path, offset, size, buf, cache->log_len);				
		cache->log_len++;	
	} else {
		int i = 0, ev_ind;
		time_t least_recent;
		time(&least_recent);
		for(; i < cache->log_len; i++) {
			if(difftime(least_recent, cache->entries[i].last_use) > 0) {
				least_recent = cache->entries[i].last_use;
				ev_ind = i;
			}
		}

		if(cache->cache_size - cache->entries[ev_ind].size + size > cl->cache_size)
			return;
		
		free(cache->entries[ev_ind].path);
		free(cache->entries[ev_ind].data);
		cache->cache_size -= cache->entries[ev_ind].size;
		cache_add_on_index(cache, path, offset, size, buf, ev_ind);				
	}
}

void cache_remove_file(struct cache* cache, const char* path) {
	int i = cache->log_len - 1;
	for(; i >= 0; i--) {
		if(!strcmp(cache->entries[i].path, path)) {
			free(cache->entries[i].path);
			free(cache->entries[i].data);
			cache->cache_size -= cache->entries[i].size;
			memcpy(cache->entries + i, cache->entries + i + 1, (cache->log_len - i - 1) * sizeof(struct cache_entry));
			cache->log_len--;
		}
	}
}

void cache_rename_file(struct cache* cache, const char* path, const char* newpath) {
	int i = 0;
	for(; i < cache->log_len; i++) {
		if(!strcmp(cache->entries[i].path, path)) {
			cache->entries[i].path = realloc(cache->entries[i].path, strlen(newpath) + 1);
			assert(cache->entries[i].path != NULL);
			strcpy(cache->entries[i].path, newpath);
		}
	}
}

int nr_getattr(const char *path, struct stat *statbuf) {
	// printf(">>>>>>>>>>>> GETATTR\n");
	fflush(stdout);
	
	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = 1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _getattr;
    strcpy(pass_info.path, path);

    //printf("getattr before lock\n");
    pthread_mutex_lock(&d->mutexes[0]);
    //printf("getattr after lock\n");
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);

    struct getattr_t res;
    res.status = -1;
    ssize_t bytes_read = recv(d->sfds[0], &res, sizeof(struct getattr_t), 0);
    pthread_mutex_unlock(&d->mutexes[0]);
    //printf("getattr after unlock\n");

    status = res.status;
    memcpy(statbuf, &(res.statbuf), sizeof(struct stat));

    if(status != 0 || bytes_read < (ssize_t) sizeof(struct getattr_t)) {
    	pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);

	    recv(d->sfds[1], &res, sizeof(struct getattr_t), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);

	    status = res.status;
	    memcpy(statbuf, &(res.statbuf), sizeof(struct stat));
    }

    // printf("path: %s\n", path);
    // printf("status: %d\n\n", status);

    return status;
}

int nr_mknod(const char *path, mode_t mode, dev_t dev){
	// printf(">>>>>>>>>>>> MKNOD\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _mknod;
    strcpy(pass_info.path, path);
    pass_info.mode = mode;
    pass_info.dev = dev;

    pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int), 0);
    pthread_mutex_unlock(&d->mutexes[0]);

    int sec_status = -1;
    if((status >= 0 || bytes_read < (ssize_t) sizeof(int)) && !server_down[1]) {
    	int sec_status;
		pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]); 
	    if(sec_status >= 0 || bytes_read < sizeof(int))
	    	return sec_status;
	}
    
    return status;
}

int nr_open(const char *path, struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> OPEN\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}


    int status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _open;
    strcpy(pass_info.path, path);
    pass_info.flags = fi->flags;
    // printf("open path: %s\n", path);
    char serv1_new_hash[HASH_LENGTH], serv1_hash[HASH_LENGTH], serv2_hash[HASH_LENGTH], serv2_new_hash[HASH_LENGTH]; 
    
    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    fi->fh = status;
	    // printf("open status: %d\n", status);
	    
	    if (status >= 0){
			status = 0;
			recv(d->sfds[0], serv1_new_hash, HASH_LENGTH, 0);
			recv(d->sfds[0], serv1_hash, HASH_LENGTH, 0);
			// printf("server1 new hash: %s\n", serv1_new_hash);
			// printf("server1 hash: %s\n", serv1_hash);
	    }
	    pthread_mutex_unlock(&d->mutexes[0]);
    }

    int serv2_fd = -1;
    if(!server_down[1]) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &serv2_fd, sizeof(int), 0);

	    // printf("serv2_fd: %d\n", serv2_fd);
	    if(serv2_fd > 0) {
	    	if(serv2_fd >= d->fdpaths_size) {
	    		d->fdpaths = realloc(d->fdpaths, (serv2_fd + 100) * sizeof(char*));
	    		assert(d->fdpaths != NULL);
	    		d->fdpaths_size = serv2_fd + 100;
	    	}
	    	d->fdpaths[serv2_fd] = malloc(strlen(path) + 1);
	    	strcpy(d->fdpaths[serv2_fd], path);

	    	recv(d->sfds[1], serv2_new_hash, HASH_LENGTH, 0);
			recv(d->sfds[1], serv2_hash, HASH_LENGTH, 0);
			// printf("server2 new hash: %s\n", serv2_new_hash);
			// printf("server2 hash: %s\n", serv2_hash);
	    } 
	    pthread_mutex_unlock(&d->mutexes[1]);
	}


    if(status == 0 && serv2_fd >= 0 && !server_down[0] && !server_down[1]) {
    	if(strcmp(serv1_hash, serv1_new_hash) != 0 && strcmp(serv2_hash, serv2_new_hash) != 0) {
    		delete_damaged(d->sfds[0], path);
    		delete_damaged(d->sfds[1], path);
    		return -ENOENT;
    	} else if(strcmp(serv1_hash, serv1_new_hash) != 0) {
    		regenerate_file(d->sfds[1], d->sfds[0], &d->mutexes[1], &d->mutexes[0], path);
    	} else if(strcmp(serv2_hash, serv2_new_hash) != 0) {
    		regenerate_file(d->sfds[0], d->sfds[1], &d->mutexes[0], &d->mutexes[1], path);
    	} else if(strcmp(serv2_hash, serv1_hash) != 0) {
    		regenerate_file(d->sfds[0], d->sfds[1], &d->mutexes[0], &d->mutexes[1], path);
    	}
    } 
    else if(status != 0 && serv2_fd >= 0 && !server_down[0] && !server_down[1]) {
    	fi->fh = recreate_file(d->sfds[1], d->sfds[0], &d->mutexes[1], &d->mutexes[0], path, fi->flags);
    	if(fi->fh > 0)
    		status = 0;
    } else if(status == 0 && serv2_fd < 0 && !server_down[0] && !server_down[1]) {
    	serv2_fd = recreate_file(d->sfds[0], d->sfds[1], &d->mutexes[0], &d->mutexes[1], path, fi->flags);
	    if(serv2_fd > 0) {
	    	if(serv2_fd >= d->fdpaths_size) {
	    		d->fdpaths = realloc(d->fdpaths, (serv2_fd + 100) * sizeof(char*));
	    		assert(d->fdpaths != NULL);
	    		d->fdpaths_size = serv2_fd + 100;
	    	}
	    	d->fdpaths[serv2_fd] = malloc(strlen(path) + 1);
	    	strcpy(d->fdpaths[serv2_fd], path);
	    }
    }

    if(status >= 0 || serv2_fd >= 0) 
    	status = 0;

    // printf("open status before return: %d\n\n", status);

    return status;
}

int nr_release(const char *path, struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> RELEASE\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    // printf("here1\n");

    int status = -1, sec_status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _release;
    pass_info.fd = fi->fh;

    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    // printf("here2\n");
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[0]);
	}

	// printf("here3\n");

	if(!server_down[1]) {
	    pass_info.fd = get_fdpath(d->fdpaths, path, d->fdpaths_size);
	    if(pass_info.fd > 0) {
		    pthread_mutex_lock(&d->mutexes[1]);
		    // printf("here4\n");
		    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
		    // printf("here5\n");
		    recv(d->sfds[1], &sec_status, sizeof(int), 0);
		    // printf("here6\n");
		    pthread_mutex_unlock(&d->mutexes[1]);
		    free(d->fdpaths[pass_info.fd]);
		    d->fdpaths[pass_info.fd] = NULL;
		}
	}
	// printf("here7\n");

	if(sec_status == 0 || status == -1)
		status = sec_status;

	// printf("release return status: %d\n\n", status);
    return status;
}

int nr_unlink(const char *path){
	// printf(">>>>>>>>>>>> UNLINK\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}


    int status = -1, sec_status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _unlink;
    strcpy(pass_info.path, path);

    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[0]);
	}

	if(!server_down[1]) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
	}

	if(sec_status == 0 || status == -1)
		status = sec_status;

	if(status >= 0)
    	cache_remove_file(d->cache, path);

    return status;
}

int nr_mkdir(const char *path, mode_t mode){
	// printf(">>>>>>>>>>>> MKDIR\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1, sec_status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _mkdir;
    strcpy(pass_info.path, path);
    pass_info.mode = mode;

    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[0]);
	}

	if(!server_down[1]) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
	}

    if(sec_status == 0 || status == -1)
		return sec_status;

	return status;
}

int nr_opendir(const char *path, struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> OPENDIR\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

	// printf("opendir path: %s\n", path);
	fflush(stdout);

    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _opendir;
    strcpy(pass_info.path, path);
    //printf("opendir before lock\n");
    pthread_mutex_lock(&d->mutexes[0]);
    //printf("opendir after lock\n");
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);

    struct opendir_t res;
    res.status = -1;
    ssize_t bytes_read = recv(d->sfds[0], &res, sizeof(struct opendir_t), 0);
    pthread_mutex_unlock(&d->mutexes[0]);
    //printf("opendir after unlock\n");

    if(res.status < 0 || bytes_read < (ssize_t) sizeof(struct opendir_t)) {
    	pthread_mutex_lock(&d->mutexes[1]);
	    //printf("opendir after lock\n");
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);

	    recv(d->sfds[1], &res, sizeof(struct opendir_t), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
    }
    // printf("opendir status %d\n\n", res.status);

    fi->fh = (intptr_t) res.dir;

    return res.status;
}

int nr_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> READDIR\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _readdir;
    pass_info.dir = (DIR*) (intptr_t)fi->fh;
    pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);

    int bytes_to_read;
    recv(d->sfds[0], &bytes_to_read, sizeof(int), 0);
    
    char dirs[16000];
    dirs[0] = '\0';
    recv(d->sfds[0], dirs, bytes_to_read, 0);
    // printf("READDIR paths: %s\n", dirs);

    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int), 0);
    // printf("READDIR status: %d\n\n", status);
    pthread_mutex_unlock(&d->mutexes[0]);

    if(status < 0 || bytes_read < (ssize_t) sizeof(int)) {
    	pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);

	    recv(d->sfds[1], &bytes_to_read, sizeof(int), 0);
	    dirs[0] = '\0';
	    recv(d->sfds[1], dirs, bytes_to_read, 0);
	    // printf("READDIR paths: %s\n", dirs);

	    recv(d->sfds[1], &status, sizeof(int), 0);
	    // printf("READDIR status: %d\n\n", status);
	    pthread_mutex_unlock(&d->mutexes[1]);
    }

    char* token = strtok(dirs, DIR_DELIM);
    while(token != NULL) {
    	if(filler(buf, token, NULL, 0) != 0) {
    		status = -errno;
    		break;
    	}
    	token = strtok(NULL, DIR_DELIM);
    }

    return status;
}

int nr_rmdir(const char *path){
	// printf(">>>>>>>>>>>> RMDIR\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1, sec_status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _rmdir;
    strcpy(pass_info.path, path);

    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[0]);
	}

	if(!server_down[1]) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
	}

	if(sec_status == 0 || status == -1)
		return sec_status;

    return status;
}

int nr_releasedir(const char *path, struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> RELEASEDIR\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

	// printf("releasedir path: %s\n\n", path);
    int status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _releasedir;
    strcpy(pass_info.path, path);
 	pass_info.dir = (DIR*) (intptr_t)fi->fh;
 	pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int), 0);
    pthread_mutex_unlock(&d->mutexes[0]);

    if(status < 0 || bytes_read < (ssize_t) sizeof(int)) {
		pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);    	
    }

    return status;
}

int nr_rename(const char *path, const char* newpath){
	// printf(">>>>>>>>>>>> RENAME\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1, sec_status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _rename;
    strcpy(pass_info.path, path);
    strcpy(pass_info.newpath, newpath);

    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[0]);
	}

	if(!server_down[1]) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
	}

	if(sec_status == 0 || status == -1)
		status = sec_status;

	if(status == 0) {
		cache_rename_file(d->cache, path, newpath);
	}

    return status;
}

int nr_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> READ\n");
	fflush(stdout);
	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int64_t status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    int cache_ind;
    if((cache_ind = search_cache(d->cache, path, offset, size)) >= 0) {
    	memcpy(buf, d->cache->entries[cache_ind].data, d->cache->entries[cache_ind].size);
    	// printf("read from cache, size: %lu\n\n", d->cache->entries[cache_ind].size);
    	return d->cache->entries[cache_ind].size;
    }

    struct info pass_info;

    pass_info.id = _read;
    pass_info.fd = fi->fh;
    pass_info.size = size;
    pass_info.offset = offset;
    strcpy(pass_info.path, path);
    pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);

    recv(d->sfds[0], buf, size, 0);

    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int64_t), 0);
    pthread_mutex_unlock(&d->mutexes[0]);

    // printf("read first server status: %li\nfirst server bytes read: %li\n", status, bytes_read);

    if(status < 0 || bytes_read < (ssize_t) sizeof(int64_t)) {
    	pass_info.fd = get_fdpath(d->fdpaths, path, d->fdpaths_size);
    	if(pass_info.fd > 0) {
		    pthread_mutex_lock(&d->mutexes[1]);
		    send(d->sfds[1], &pass_info, sizeof(struct info), 0);

		    recv(d->sfds[1], buf, size, 0);

		    recv(d->sfds[1], &status, sizeof(int64_t), 0);
		    pthread_mutex_unlock(&d->mutexes[1]);  
	    }  	
    }
    // printf("read status: %li\n\n", status);

    if(status >= 0)
    	add_to_cache(d->cache, path, offset, status, buf);

    return (int)status;
}

int nr_write(const char *path, const char *buf, size_t size, off_t offset,
	     struct fuse_file_info *fi){
	// printf(">>>>>>>>>>>> WRITE\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int64_t status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _write;
    pass_info.fd = fi->fh;
    pass_info.size = size;
    pass_info.offset = offset;
    pass_info.mode_change = 0;
    strcpy(pass_info.path, path);
    // printf("write size: %lu\n", size);
    pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
    send(d->sfds[0], buf, size, 0);
    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int64_t), 0);
    pthread_mutex_unlock(&d->mutexes[0]);

    int64_t sec_status = -1;
    if((status >= 0 || bytes_read < (ssize_t) sizeof(int64_t)) && !server_down[1]) {
	    pass_info.fd = get_fdpath(d->fdpaths, path, d->fdpaths_size);
	    if(pass_info.fd > 0) {
		    pthread_mutex_lock(&d->mutexes[1]);
		    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
		    send(d->sfds[1], buf, size, 0);
		    recv(d->sfds[1], &sec_status, sizeof(int64_t), 0);
		    pthread_mutex_unlock(&d->mutexes[1]);
		    if(sec_status >= 0 || bytes_read < sizeof(int64_t))
		    	status = sec_status;
		}
	}
    // printf("write status: %li\n\n", status);

    if(status >= 0)
    	cache_remove_file(d->cache, path);

    return (int)status;
}

int nr_truncate(const char *path, off_t newsize){
	// printf(">>>>>>>>>>>> TRUNCATE\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _truncate;
    strcpy(pass_info.path, path);
    pass_info.newsize = newsize;
    pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int), 0);
    pthread_mutex_unlock(&d->mutexes[0]);

    int sec_status = -1;
    if((status >= 0 || bytes_read < (ssize_t) sizeof(int)) && !server_down[1]) {
    	// printf("truncate sending to server2\n");
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
	    if(sec_status >= 0 || bytes_read < sizeof(int))
	    	status = sec_status;
	}

	// printf("truncate return status: %d\n\n", status);

    return status;
}

int nr_utime(const char *path, struct utimbuf *ubuf){
	// printf(">>>>>>>>>>>> UTIME\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1, sec_status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _utime;
    strcpy(pass_info.path, path);

    if(!server_down[0]) {
	    pthread_mutex_lock(&d->mutexes[0]);
	    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
	    send(d->sfds[0], ubuf, sizeof(struct utimbuf), 0);
	    recv(d->sfds[0], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[0]);
	}

	if(!server_down[1]) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    send(d->sfds[1], ubuf, sizeof(struct utimbuf), 0);
	    recv(d->sfds[1], &sec_status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);
	}

	if(sec_status == 0 || status == -1)
		return sec_status;

    return status;
}

int nr_access(const char *path, int mask){
	// printf(">>>>>>>>>>>> ACCESS\n");
	fflush(stdout);

	if(strlen(path) >= PATH_MAX) {
		// printf("Path exceeded max length for path\n");
		return -1;
	}

    int status = -1;
    struct disk* d = (struct disk*) fuse_get_context()->private_data;

    struct info pass_info;

    pass_info.id = _access;
    strcpy(pass_info.path, path);
    pass_info.mask = mask;
    //printf("access before lock\n");
    pthread_mutex_lock(&d->mutexes[0]);
    send(d->sfds[0], &pass_info, sizeof(struct info), 0);
    ssize_t bytes_read = recv(d->sfds[0], &status, sizeof(int), 0);
    pthread_mutex_unlock(&d->mutexes[0]);

    if(status < 0 || bytes_read < (ssize_t) sizeof(struct info)) {
	    pthread_mutex_lock(&d->mutexes[1]);
	    send(d->sfds[1], &pass_info, sizeof(struct info), 0);
	    recv(d->sfds[1], &status, sizeof(int), 0);
	    pthread_mutex_unlock(&d->mutexes[1]);    	
    }
    //printf("access after unlock\n");

    return status;
}

void* nr_init(struct fuse_conn_info *conn) {
	struct disk* d = (struct disk*) fuse_get_context()->private_data;

    time_t** times = malloc(d->num_servers * sizeof(time_t*));
	assert(times != NULL); 

	pthread_t* threads = malloc(d->num_servers * sizeof(pthread_t));
	assert(threads != NULL);

	int j;
	for(j = 0; j < d->num_servers; j++) {
	    times[j] = malloc(sizeof(time_t));
	    time(times[j]);
	    struct server_checker_data* data = malloc(sizeof(struct server_checker_data));
	    data->ind = j;
	    data->last_server_checks = times;
	    data->mutex = &d->mutexes[j];
	    data->d = d;
	    //printf("AAA %lu\n", data->ind);
	    pthread_create(&threads[j], NULL, server_checker, data);
	}

    return fuse_get_context()->private_data;
}

struct fuse_operations nr_operations = {
	.init = nr_init,
	.getattr = nr_getattr,
	.mknod = nr_mknod,
	.open = nr_open,
	.release = nr_release,
	.unlink = nr_unlink,
	.mkdir = nr_mkdir,
	.opendir = nr_opendir,
	.readdir = nr_readdir,
	.rmdir = nr_rmdir,
	.releasedir = nr_releasedir,
	.rename = nr_rename,
	.read = nr_read,
	.write = nr_write,
	.truncate = nr_truncate,
	.utime = nr_utime,
	.access = nr_access,
};

int main(int argc, char *argv[]) {
	int status = 0;
	
	if(argc != 2) {
		printf("Incompatible arguments\n");
		return -1;
	}

	char* filename = argv[1];
	FILE* conf_file = fopen(filename, "r");

	if(conf_file == NULL) {
		printf("Couldn't open config file\n");
		return -1;
	}

	cl = malloc(sizeof(struct client));
	assert(cl != NULL);

	disks = malloc(INIT_DISKS_SIZE * sizeof(struct disk*));
	assert(disks != NULL);

	disks_size = INIT_DISKS_SIZE;
	num_disks = 0;

	char* str = NULL;
	size_t n = 0;
	bool flag = false;
	while (getline(&str, &n, conf_file) != -1) {
		if(!strcmp(str, "\n")) {
			if(!flag)
				flag = true;
			else {
				num_disks++;
				if(num_disks > disks_size) {
					disks_size *= 2;
					disks = realloc(disks, disks_size * sizeof(struct disk*));
					assert(disks != NULL);
				}
			}
			disks[num_disks] = malloc(sizeof(struct disk));
			assert(disks[num_disks] != NULL);
			continue;
		}
		if(!parse(str, flag)) {
			printf("Invalid config file %s\n", str);
			break;
		}
	}

	num_disks++;

	log_file = fopen(cl->errorlog, "w");

	size_t i, j;
    struct sockaddr_in addr;
    int ip;
    hotswap_added = false;
    server_down[0] = false;
    server_down[1] = false;
    hotswap_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

	i = 0;
	int x;
	int child_pids[num_disks];
    for(; i < num_disks; i++) {
    	j = 0;
    	x = fork();
    	switch(x) {
            case -1:
                status = 100;
                goto frees;
            case 0:
            	disks[i]->sfds = malloc(disks[i]->num_servers * sizeof(int));
            	assert(disks[i]->sfds != NULL);

				disks[i]->mutexes = malloc(disks[i]->num_servers * sizeof(pthread_mutex_t)); 
				assert(disks[i]->mutexes != NULL);

				disks[i]->cache = malloc(sizeof(struct cache));
				assert(disks[i]->cache != NULL);
				disks[i]->cache->entries = malloc(CACHE_INIT_LEN * sizeof(struct cache_entry));
				assert(disks[i]->cache->entries != NULL);
				disks[i]->cache->alloc_len = CACHE_INIT_LEN;
				disks[i]->cache->log_len = 0;
				disks[i]->cache->cache_size = 0;

				for(j = 0; j < disks[i]->num_servers; j++) {
				    disks[i]->sfds[j] = socket(AF_INET, SOCK_STREAM, 0);
				    inet_pton(AF_INET, disks[i]->servers[j], &ip);

				    addr.sin_family = AF_INET;
				    addr.sin_port = htons(disks[i]->ports[j]);
				    addr.sin_addr.s_addr = ip;

				    connect(disks[i]->sfds[j], (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
				    log_in_file("open connection", disks[i], j);
				    
				    disks[i]->mutexes[j] = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
				}
				disks[i]->fdpaths = malloc(FDPATHS_INIT_SIZE * sizeof(char*));
				disks[i]->fdpaths_size = FDPATHS_INIT_SIZE;
				
				argv[1] = malloc(strlen(disks[i]->mountpoint) + 1);
				assert(argv[1] != NULL);
				strcpy(argv[1], disks[i]->mountpoint);
                int k = fuse_main(argc, argv, &nr_operations, disks[i]);
				exit(k);
            default:
            	child_pids[i] = x;
                continue;
		}
	}

	frees: {};
	pid_t w_pid;
	int st;
	for(i = 0; i < num_disks; i++){
		waitpid(child_pids[i], &st, 0);
	}


    free(str);
    fclose(conf_file);
    free(cl->errorlog);
    free(cl->cache_replacement);
    free(cl);

    i = 0;
    for(; i < num_disks; i++) {
    	free(disks[i]->diskname);
    	free(disks[i]->mountpoint);

    	j = 0;
		for(; j < disks[i]->num_servers; j++) {
			free(disks[i]->servers[j]);
		}
		j = 0;
		for(; j < disks[i]->fdpaths_size; j++) {
			if(disks[i]->fdpaths[j] != NULL)
				free(disks[i]->fdpaths[j]);
		}
		free(disks[i]->mutexes);
		free(disks[i]->fdpaths);
		free(disks[i]->servers);
		free(disks[i]->ports);
    	free(disks[i]->sfds);
		free(disks[i]->hotswap);
		free(disks[i]);
	}
	free(disks);

	return status;
}