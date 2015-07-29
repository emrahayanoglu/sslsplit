/*
 * SSLsplit - transparent and scalable SSL/TLS interception
 * Copyright (c) 2009-2014, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sys.h"

#include "log.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <fts.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <linux/if.h>

#ifndef _SC_NPROCESSORS_ONLN
#include <sys/sysctl.h>
#endif /* !_SC_NPROCESSORS_ONLN */

#if HAVE_DARWIN_LIBPROC
#include <libproc.h>
#endif

#include <event2/util.h>

#define xstr(s) str(s)
#define str(s) #s

#define ARP_CACHE		"/proc/net/arp"
#define ARP_STRING_LEN	1023
#define ARP_BUFFER_LEN	(ARP_STRING_LEN + 1)

#define ARP_LINE_FORMAT	"%" xstr(ARP_STRING_LEN) "s %*s %*s " \
 						"%" xstr(ARP_STRING_LEN) "s %*s " \
 						"%" xstr(ARP_STRING_LEN) "s"

/*
 * Permanently drop from root privileges to an unprivileged user account.
 * Sets the real, effective and stored user and group ID and the list of
 * ancillary groups.  This is only safe if the effective user ID is 0.
 * If username is unset and the effective uid != uid, drop privs to uid.
 * This is to support setuid bit configurations.
 * If groupname is set, it will be used instead of the user's default primary
 * group.
 * If jaildir is set, also chroot to jaildir after reading system files
 * but before dropping privileges.
 * Returns 0 on success, -1 on failure.
 */
int
sys_privdrop(const char *username, const char *groupname, const char *jaildir)
{
	struct passwd *pw = NULL;
	struct group *gr = NULL;
	int ret = -1;

	if (groupname) {
		if (!(gr = getgrnam(groupname))) {
			log_err_printf("Failed to getgrnam group '%s': %s\n",
			               groupname, strerror(errno));
			goto error;
		}
	}

	if (username) {
		if (!(pw = getpwnam(username))) {
			log_err_printf("Failed to getpwnam user '%s': %s\n",
			               username, strerror(errno));
			goto error;
		}

		if (gr != NULL) {
			pw->pw_gid = gr->gr_gid;
		}

		if (initgroups(username, pw->pw_gid) == -1) {
			log_err_printf("Failed to initgroups user '%s': %s\n",
			               username, strerror(errno));
			goto error;
		}
	}

	if (jaildir) {
		if (chroot(jaildir) == -1) {
			log_err_printf("Failed to chroot to '%s': %s\n",
			               jaildir, strerror(errno));
			goto error;
		}
		if (chdir("/") == -1) {
			log_err_printf("Failed to chdir to '/': %s\n",
			               strerror(errno));
			goto error;
		}
	}

	if (username) {
		if (setgid(pw->pw_gid) == -1) {
			log_err_printf("Failed to setgid to %i: %s\n",
			               pw->pw_gid, strerror(errno));
			goto error;
		}
		if (setuid(pw->pw_uid) == -1) {
			log_err_printf("Failed to setuid to %i: %s\n",
			               pw->pw_uid, strerror(errno));
			goto error;
		}
	} else if (getuid() != geteuid()) {
		if (setuid(getuid()) == -1) {
			log_err_printf("Failed to setuid(getuid()): %s\n",
			               strerror(errno));
			goto error;
		}
	}

	ret = 0;
error:
	if (pw) {
		endpwent();
	}
	return ret;
}

/*
 * Open and lock process ID file fn.
 * Returns open file descriptor on success or -1 on errors.
 */
int
sys_pidf_open(const char *fn)
{
	int fd;

	if ((fd = open(fn, O_RDWR|O_CREAT, 0640)) == -1) {
		log_err_printf("Failed to open '%s': %s\n", fn,
		               strerror(errno));
		return -1;
	}
	if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
		log_err_printf("Failed to lock '%s': %s\n", fn,
		               strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Write process ID to open process ID file descriptor fd.
 * Returns 0 on success, -1 on errors.
 */
int
sys_pidf_write(int fd)
{
	char pidbuf[4*sizeof(pid_t)];
	int rv;

	rv = snprintf(pidbuf, sizeof(pidbuf), "%d\n", getpid());
	if (rv == -1 || rv >= (int)sizeof(pidbuf))
		return -1;

	write(fd, pidbuf, strlen(pidbuf));
	fsync(fd);

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	return 0;
}

/*
 * Close and remove open process ID file before quitting.
 */
void
sys_pidf_close(int fd, const char *fn)
{
	unlink(fn);
	close(fd);
}

/*
 * Converts a local uid into a printable string representation.
 * Returns an allocated buffer which must be freed by caller, or NULL on error.
 */
char *
sys_user_str(uid_t uid)
{
	static int bufsize = 0;

	if (!bufsize) {
		/* on some platforms this compiles, but does not succeed */
		if ((bufsize = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
			bufsize = 64;
		}
	}

	char *buf, *newbuf;
	struct passwd pwd, *result = NULL;
	int rv;
	char *name;

	if (!(buf = malloc(bufsize)))
		return NULL;

	do {
		rv = getpwuid_r(uid, &pwd, buf, bufsize, &result);
		if (rv == 0) {
			if (result) {
				name = strdup(pwd.pw_name);
				free(buf);
				return name;
			}
			free(buf);

			/* no entry found; return the integer representation */
			if (asprintf(&name, "%llu", (long long) uid) < 0) {
				return NULL;
			}
			return name;
		}
		bufsize *= 2;
		if (!(newbuf = realloc(buf, bufsize))) {
			free(buf);
			return NULL;
		}
		buf = newbuf;
	} while (rv == ERANGE);

	free(buf);
	log_err_printf("Failed to lookup uid: %s (%i)\n", strerror(rv), rv);
	return NULL;
}

/*
 * Converts a local gid into a printable string representation.
 * Returns an allocated buffer which must be freed by caller, or NULL on error.
 */
char *
sys_group_str(gid_t gid)
{
	static int bufsize = 0;

	if (!bufsize) {
		/* on some platforms this compiles, but does not succeed */
		if ((bufsize = sysconf(_SC_GETGR_R_SIZE_MAX)) == -1) {
			bufsize = 64;
		}
	}

	char *buf, *newbuf;
	struct group grp, *result = NULL;
	int rv;
	char *name;

	if (!(buf = malloc(bufsize)))
		return NULL;

	do {
		rv = getgrgid_r(gid, &grp, buf, bufsize, &result);
		if (rv == 0) {
			if (result) {
				name = strdup(grp.gr_name);
				free(buf);
				return name;
			}
			free(buf);

			/* no entry found; return the integer representation */
			if (asprintf(&name, "%llu", (long long) gid) < 0) {
				return NULL;
			}
			return name;
		}
		bufsize *= 2;
		if (!(newbuf = realloc(buf, bufsize))) {
			free(buf);
			return NULL;
		}
		buf = newbuf;
	} while (rv == ERANGE);

	free(buf);
	log_err_printf("Failed to lookup gid: %s (%i)\n", strerror(rv), rv);
	return NULL;
}

/*
 * Parse an ascii host/IP and port tuple into a sockaddr_storage.
 * On success, returns address family and fills in addr, addrlen.
 * Returns -1 on error.
 */
int
sys_sockaddr_parse(struct sockaddr_storage *addr, socklen_t *addrlen,
                   char *naddr, char *nport, int af, int flags)
{
	struct evutil_addrinfo hints;
	struct evutil_addrinfo *ai;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = EVUTIL_AI_ADDRCONFIG | flags;
	rv = evutil_getaddrinfo(naddr, nport, &hints, &ai);
	if (rv != 0) {
		log_err_printf("Cannot resolve address '%s' port '%s': %s\n",
		               naddr, nport, gai_strerror(rv));
		return -1;
	}
	memcpy(addr, ai->ai_addr, ai->ai_addrlen);
	*addrlen = ai->ai_addrlen;
	af = ai->ai_family;
	freeaddrinfo(ai);
	return af;
}

/*
 * Converts an IPv4/IPv6 sockaddr into a printable string representation.
 * Returns an allocated buffer which must be freed by caller, or NULL on error.
 */
char *
sys_sockaddr_str(struct sockaddr *addr, socklen_t addrlen)
{
	char host[INET6_ADDRSTRLEN], serv[6];
	char *buf;
	int rv;
	size_t bufsz;

	bufsz = sizeof(host) + sizeof(serv) + 3;
	buf = malloc(bufsz);
	if (!buf) {
		log_err_printf("Cannot allocate memory\n");
		return NULL;
	}
	rv = getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
	                 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rv != 0) {
		log_err_printf("Cannot get nameinfo for socket address: %s\n",
		               gai_strerror(rv));
		free(buf);
		return NULL;
	}
	snprintf(buf, bufsz, "[%s]:%s", host, serv);
	return buf;
}

char * 
sys_sockaddr_str_host(struct sockaddr *addr, socklen_t addrlen)
{
	char host[INET6_ADDRSTRLEN], serv[6];
	char *buf;
	int rv;

	buf = malloc(sizeof(char) * INET6_ADDRSTRLEN);
	if (!buf) {
		log_err_printf("Cannot allocate memory\n");
		return NULL;
	}
	rv = getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
	                 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rv != 0) {
		log_err_printf("Cannot get nameinfo for socket address: %s\n",
		               gai_strerror(rv));
		free(buf);
		return NULL;
	}
	snprintf(buf, INET6_ADDRSTRLEN, "%s", host);
	return buf;
}


char * 
sys_sockaddr_str_port(struct sockaddr *addr, socklen_t addrlen)
{
	char host[INET6_ADDRSTRLEN], serv[6];
	char *buf;
	int rv;

	buf = malloc(sizeof(char) * 6);
	if (!buf) {
		log_err_printf("Cannot allocate memory\n");
		return NULL;
	}
	rv = getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
	                 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rv != 0) {
		log_err_printf("Cannot get nameinfo for socket address: %s\n",
		               gai_strerror(rv));
		free(buf);
		return NULL;
	}
	snprintf(buf, 6, "%s", serv);
	return buf;
}

/*
 * Returns 1 if path points to an existing directory node in the filesystem.
 * Returns 0 if path is NULL, does not exist, or points to a file of some kind.
 */
int
sys_isdir(const char *path)
{
	struct stat s;

	if (stat(path, &s) == -1)
		return 0;
	if (s.st_mode & S_IFDIR)
		return 1;
	return 0;
}

/*
 * Create directory including parent directories with mode_t.
 * Mode of existing parent directories is not changed.
 * Returns 0 on success, -1 and sets errno on error.
 */
int
sys_mkpath(const char *path, mode_t mode)
{
	char parent[strlen(path)+1];
	char *p;

	memcpy(parent, path, sizeof(parent));

	p = parent;
	do {
		/* skip leading '/' characters */
		while (*p == '/') p++;
		p = strchr(p, '/');
		if (p) {
			/* overwrite '/' to terminate the string at the next
			 * parent directory */
			*p = '\0';
		}

		struct stat sbuf;
		if (stat(parent, &sbuf) == -1) {
			if (errno == ENOENT) {
				if (mkdir(parent, mode) != 0)
					return -1;
			} else {
				return -1;
			}
		} else if (!S_ISDIR(sbuf.st_mode)) {
			errno = ENOTDIR;
			return -1;
		}

		if (p) {
			/* replace the overwritten slash */
			*p = '/';
			p++;
		}
	} while (p);

	return 0;
}


/*
 * Iterate over all files in a directory hierarchy, calling the callback
 * cb for each file, passing the filename and arg as arguments.  Files and
 * directories beginning with a dot are skipped, symlinks are followed.
 */
int
sys_dir_eachfile(const char *dirname, sys_dir_eachfile_cb_t cb, void *arg)
{
	FTS *tree;
	FTSENT *node;
	char * paths[2];

	paths[1] = NULL;
	paths[0] = strdup(dirname);
	if (!paths[0])
		return -1;

	tree = fts_open(paths, FTS_NOCHDIR | FTS_LOGICAL, NULL);
	if (!tree) {
		log_err_printf("Cannot open directory '%s': %s\n",
		               dirname, strerror(errno));
		return -1;
	}

	while ((node = fts_read(tree))) {
		if (node->fts_level > 0 && node->fts_name[0] == '.')
			fts_set(tree, node, FTS_SKIP);
		else if (node->fts_info & FTS_F) {
			cb(node->fts_path, arg);
		}
	}
	if (errno) {
		log_err_printf("Error reading directory entry: %s\n",
		               strerror(errno));
		return -1;
	}
	fts_close(tree);

	free(paths[0]);
	return 0;
}

/*
 * Portably get the number of CPU cores online in the system.
 */
uint32_t
sys_get_cpu_cores(void)
{
#ifdef _SC_NPROCESSORS_ONLN
	return sysconf(_SC_NPROCESSORS_ONLN);
#else /* !_SC_NPROCESSORS_ONLN */
	int mib[2];
	uint32_t n;
	size_t len = sizeof(n);

	mib[0] = CTL_HW;
	mib[1] = HW_AVAILCPU;
	sysctl(mib, sizeof(mib)/sizeof(int), &n, &len, NULL, 0);

	if (n < 1) {
		mib[1] = HW_NCPU;
		sysctl(mib, sizeof(mib)/sizeof(int), &n, &len, NULL, 0);
		if (n < 1) {
			n = 1;
		}
	}
	return n;
#endif /* !_SC_NPROCESSORS_ONLN */
}


/*
 * Get the file size from the system.
 */
off_t 
sys_get_filesize(const char *filename)
{
	struct stat st;

	if(stat(filename, &st) == 0)
		return st.st_size;

	log_err_printf("Cannot determine size of %s: %s\n",
		               filename, strerror(errno));

	return -1;
}


/*
 * Get the mac address from the provided interface and file descriptor
 */
char * 
sys_get_mac_address(const char *interface, int fd)
{
	char *ret = malloc(sizeof(char) * 18);

	struct ifreq s;
	strcpy(s.ifr_name, interface);
	if(fd >= 0 && ret && ioctl(fd, SIOCGIFHWADDR, &s)){
		int i;
		for (i = 0; i < 6; ++i){
			if(i < 5){
				snprintf(ret + i * 3, 18 - i * 3, "%02x:", (unsigned char) s.ifr_addr.sa_data[i]);
			}
			else{
				snprintf(ret + i * 3, 18 - i * 3, "%02x", (unsigned char) s.ifr_addr.sa_data[i]);	
			}
		}
	}
	else{
		free(ret);
		return NULL;
	}

	return ret;
}


/*
 * Search and fetch the mac address from the arp table
 * according to the provided ip address
 */
char * 
sys_get_mac_address_from_arp(const char *ip_addr)
{
	char *ret = malloc(sizeof(char) * ARP_BUFFER_LEN);

	strcpy(ret, "00:00:00:00:00:00");

	FILE *arpCache = fopen(ARP_CACHE, "r");
	if (!arpCache)
	{
		log_err_printf("Arp Cache: Failed to open file \"" ARP_CACHE "\"");
		return NULL;
	}

	char header[ARP_BUFFER_LEN];
	if(!fgets(header, sizeof(header), arpCache))
	{
		return NULL;
	}

	char ipAddr[ARP_BUFFER_LEN], hwAddr[ARP_BUFFER_LEN], device[ARP_BUFFER_LEN];
	while(3 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, hwAddr, device))
	{
		if(strcmp(ip_addr, ipAddr) == 0)
		{
			strcpy(ret, hwAddr);
			fclose(arpCache);
			return ret;
		}
	}
	fclose(arpCache);
	return NULL;
}


char ** 
sys_str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

int 
sys_check_str_has_request_headers(const unsigned char *buf)
{
	if(strstr((char *)buf, "Host") != NULL || strstr((char *)buf, "Connection") != NULL ||
		strstr((char *)buf, "Accept") != NULL || strstr((char *)buf, "User-Agent") != NULL ||
		strstr((char *)buf, "Referer") != NULL || strstr((char *)buf, "Accept-Encoding") != NULL ||
		strstr((char *)buf, "Content-Type") != NULL || strstr((char *)buf, "Content-Length") != NULL ||
		strstr((char *)buf, "Range") != NULL || strstr((char *)buf, "If-Range") != NULL ||
		strstr((char *)buf, "Accept-Language") != NULL || strstr((char *)buf, "Cookie") != NULL)
	{
		return 0;
	}

	return 1;
}


int 
sys_check_str_has_response_headers(const unsigned char *buf)
{
	if(strstr((char *)buf, "Set-Cookie") != NULL || strstr((char *)buf, "Expires") != NULL ||
		strstr((char *)buf, "Content-Type") != NULL || strstr((char *)buf, "Content-Length") != NULL ||
		strstr((char *)buf, "Connection") != NULL || strstr((char *)buf, "Server") != NULL ||
		strstr((char *)buf, "Last-Modified") != NULL || strstr((char *)buf, "Date") != NULL ||
		strstr((char *)buf, "Accept-Ranges") != NULL || strstr((char *)buf, "Content-Encoding") != NULL ||
		strstr((char *)buf, "Location") != NULL || strstr((char *)buf, "Status") != NULL ||
		strstr((char *)buf, "Content-Range") != NULL)
	{
		return 0;
	}

	return 1;
}

/* vim: set noet ft=c: */
