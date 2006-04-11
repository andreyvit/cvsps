/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <search.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cbtcommon/debug.h>

#include "util.h"

typedef int (*compare_func)(const void *, const void *);

static void * string_tree;
char *readfile(char const *filename, char *buf, size_t size)
{
    FILE *fp;
    char *ptr;
    size_t len;

    fp = fopen(filename, "r");
    if (!fp)
	return NULL;

    ptr = fgets(buf, size, fp);
    fclose(fp);

    if (!ptr)
	return NULL;

    len = strlen(buf);
    if (buf[len-1] == '\n')
	buf[len-1] = '\0';
    
    return buf;
}

char *strrep(char *s, char find, char replace)
{
    char * p = s;
    while (*p)
    {
	if (*p == find)
	    *p = replace;
	p++;
    }

    return s;
}

char *get_cvsps_dir()
{
    struct stat sbuf;
    static char prefix[PATH_MAX];
    const char * home;

    if (prefix[0])
	return prefix;

    if (!(home = getenv("HOME")))
    {
	debug(DEBUG_APPERROR, "HOME environment variable not set");
	exit(1);
    }

    if (snprintf(prefix, PATH_MAX, "%s/%s", home, CVSPS_PREFIX) >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "prefix buffer overflow");
	exit(1);
    }

    /* Make sure the prefix directory exists */
    if (stat(prefix, &sbuf) < 0)
    {
	int ret;
	ret = mkdir(prefix, 0777);
	if (ret < 0)
	{
	    debug(DEBUG_SYSERROR, "Cannot create the cvsps directory '%s'", CVSPS_PREFIX);
	    exit(1);
	}
    }
    else
    {
	if (!(S_ISDIR(sbuf.st_mode)))
	    debug(DEBUG_APPERROR, "cvsps directory '%s' is not a directory!", CVSPS_PREFIX);
    }

    return prefix;
}

char *xstrdup(char const *str)
{
    char *ret;
    assert(str);
    ret = strdup(str);
    if (!ret)
    {
	debug(DEBUG_ERROR, "strdup failed");
	exit(1);
    }

    return ret;
}

void strzncpy(char * dst, const char * src, int n)
{
    strncpy(dst, src, n);
    dst[n - 1] = 0;
}

char *get_string(char const *str)
{
    char ** res;

    if (!str)
	return NULL;
    
    res = (char **)tfind(str, &string_tree, (compare_func)strcmp);
    if (!res)
    {
	char *key = xstrdup(str);
	res = (char **)tsearch(key, &string_tree, (compare_func)strcmp);
	*res = key;
    }

    return *res;
}

static int get_int_substr(const char * str, const regmatch_t * p)
{
    char buff[256];
    memcpy(buff, str + p->rm_so, p->rm_eo - p->rm_so);
    buff[p->rm_eo - p->rm_so] = 0;
    return atoi(buff);
}

static time_t mktime_utc(struct tm * tm)
{
    char * old_tz = getenv("TZ");
    time_t ret;

    setenv("TZ", "UTC", 1);

    tzset();
	    
    ret = mktime(tm);

    if (old_tz)
	setenv("TZ", old_tz, 1);
    else 
	unsetenv("TZ");

    tzset();

    return ret;
}

void convert_date(time_t * t, const char * dte)
{
    static regex_t date_re;
    static int init_re;

#define MAX_MATCH 16
    size_t nmatch = MAX_MATCH;
    regmatch_t match[MAX_MATCH];

    if (!init_re) 
    {
	if (regcomp(&date_re, "([0-9]{4})[-/]([0-9]{2})[-/]([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})", REG_EXTENDED)) 
	{
	    fprintf(stderr, "FATAL: date regex compilation error\n");
	    exit(1);
	}
	init_re = 1;
    }
    
    if (regexec(&date_re, dte, nmatch, match, 0) == 0)
    {
	regmatch_t * pm = match;
	struct tm tm = {0};

	/* first regmatch_t is match location of entire re */
	pm++;
	
	tm.tm_year = get_int_substr(dte, pm++);
	tm.tm_mon  = get_int_substr(dte, pm++);
	tm.tm_mday = get_int_substr(dte, pm++);
	tm.tm_hour = get_int_substr(dte, pm++);
	tm.tm_min  = get_int_substr(dte, pm++);
	tm.tm_sec  = get_int_substr(dte, pm++);

	tm.tm_year -= 1900;
	tm.tm_mon--;

	*t = mktime_utc(&tm);
    }
    else
    {
	*t = atoi(dte);
    }
}

static struct timeval start_time;

void timing_start()
{
    gettimeofday(&start_time, NULL);
}

void timing_stop(const char * msg)
{
    struct timeval stop_time;
    gettimeofday(&stop_time, NULL);
    stop_time.tv_sec -= start_time.tv_sec;
    stop_time.tv_usec -= start_time.tv_usec;
    if (stop_time.tv_usec < 0)
	stop_time.tv_sec--,stop_time.tv_usec += 1000000;

    printf("Elapsed time for %s: %d.%06d\n", msg, (int)stop_time.tv_sec, (int)stop_time.tv_usec);
}

extern char ** environ;

/* taken from the linux manual page for system */
int my_system (const char *command) 
{
    int pid, status;
    
    if (command == 0)
	return 1;
    pid = fork();
    if (pid == -1)
	return -1;
    if (pid == 0) {
	char *argv[4];
	argv[0] = "sh";
	argv[1] = "-c";
	argv[2] = (char*)command; /* discard const */
	argv[3] = 0;
	execve("/bin/sh", argv, environ);
	exit(127);
    }
    do {
	if (waitpid(pid, &status, 0) == -1) {
	    if (errno != EINTR)
		return -1;
	} else
	    return status;
    } while(1);
}

int escape_filename(char * dst, int len, const char * src)
{
    static char * naughty_chars = " \\\"'@<>=;|&()#$`?*[!:{";

    if (len > 0)
    {
	while (len > 1 && *src)
	{
	    if (strchr(naughty_chars, *src))
	    {
		if (len == 2)
		    break;
		*dst++ = '\\';
		len--;
	    }
	    
	    *dst++ = *src++;
	    len--;
	}

	*dst = 0;
    }

    return (*src == 0) ? 0 : -1;
}
