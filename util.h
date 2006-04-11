/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef UTIL_H
#define UTIL_H

#define CVSPS_PREFIX ".cvsps"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

char *xstrdup(char const *);
void strzncpy(char * dst, const char * src, int n);
char *readfile(char const *filename, char *buf, size_t size);
char *strrep(char *s, char find, char replace);
char *get_cvsps_dir();
char *get_string(char const *str);
void convert_date(time_t *, const char *);
void timing_start();
void timing_stop(const char *);
int my_system(const char *);
int escape_filename(char *, int, const char *);

#endif /* UTIL_H */
