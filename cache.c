/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <cbtcommon/hash.h>
#include <cbtcommon/debug.h>

#include "cache.h"
#include "cvsps_types.h"
#include "cvsps.h"
#include "util.h"

#define CACHE_DESCR_BOUNDARY "-=-END CVSPS DESCR-=-\n"

/* change this when making the on-disk cache-format invalid */
static int cache_version = 1;

/* the tree walk API pretty much requries use of globals :-( */
static FILE * cache_fp;
static int ps_counter;

static void write_patch_set_to_cache(PatchSet *);
static void parse_cache_revision(PatchSetMember *, const char *);
static void dump_patch_set(FILE *, PatchSet *);

static FILE *cache_open(char const *mode)
{
    char *prefix;
    char fname[PATH_MAX];
    char root[PATH_MAX];
    char repository[PATH_MAX];
    FILE * fp;

    /* Get the prefix */
    prefix = get_cvsps_dir();
    if (!prefix)
	return NULL;
    
    /* Generate the full path */
    strcpy(root, root_path);
    strcpy(repository, repository_path);

    strrep(root, '/', '#');
    strrep(repository, '/', '#');

    snprintf(fname, PATH_MAX, "%s/%s#%s", prefix, root, repository);
    
    if (!(fp = fopen(fname, mode)) && *mode == 'r')
    {
	if ((fp = fopen("CVS/cvsps.cache", mode)))
	{
	    fprintf(stderr, "\n");
	    fprintf(stderr, "****WARNING**** Obsolete CVS/cvsps.cache file found.\n");
	    fprintf(stderr, "                New file will be re-written in ~/%s/\n", CVSPS_PREFIX);
	    fprintf(stderr, "                Old file will be ignored.\n");
	    fprintf(stderr, "                Please manually remove the old file.\n");
	    fprintf(stderr, "                Continuing in 5 seconds.\n");
	    sleep(5);
	    fclose(fp);
	    fp = NULL;
	}
    }

    return fp;
}

/* ************ Reading ************ */

enum
{
    CACHE_NEED_FILE,
    CACHE_NEED_BRANCHES,
    CACHE_NEED_SYMBOLS,
    CACHE_NEED_REV,
    CACHE_NEED_PS,
    CACHE_NEED_PS_DATE,
    CACHE_NEED_PS_AUTHOR,
    CACHE_NEED_PS_TAG,
    CACHE_NEED_PS_TAG_FLAGS,
    CACHE_NEED_PS_BRANCH,
    CACHE_NEED_PS_BRANCH_ADD,
    CACHE_NEED_PS_DESCR,
    CACHE_NEED_PS_EOD,
    CACHE_NEED_PS_MEMBERS,
    CACHE_NEED_PS_EOM
};

time_t read_cache()
{
    FILE * fp;
    char buff[BUFSIZ];
    int state = CACHE_NEED_FILE;
    CvsFile * f = NULL;
    PatchSet * ps = NULL;
    char datebuff[20] = "";
    char authbuff[AUTH_STR_MAX] = "";
    char tagbuff[LOG_STR_MAX] = "";
    int tag_flags = 0;
    char branchbuff[LOG_STR_MAX] = "";
    int branch_add = 0;
    char logbuff[LOG_STR_MAX] = "";
    time_t cache_date = -1;
    int read_version;

    if (!(fp = cache_open("r")))
	goto out;

    /* first line is cache version  format "cache version: %d\n" */
    if (!fgets(buff, BUFSIZ, fp) || strncmp(buff, "cache version:", 14))
    {
	debug(DEBUG_APPERROR, "bad cvsps.cache file");
	goto out_close;
    }

    if ((read_version = atoi(buff + 15)) != cache_version)
    {
	debug(DEBUG_APPERROR, "bad cvsps.cache version %d, expecting %d.  ignoring cache",
	      read_version, cache_version);
	goto out_close;
    }

    /* second line is date cache was created, format "cache date: %d\n" */
    if (!fgets(buff, BUFSIZ, fp) || strncmp(buff, "cache date:", 11))
    {
	debug(DEBUG_APPERROR, "bad cvsps.cache file");
	goto out_close;
    }

    cache_date = atoi(buff + 12);
    debug(DEBUG_STATUS, "read cache_date %d", (int)cache_date);

    while (fgets(buff, BUFSIZ, fp))
    {
	int len = strlen(buff);

	switch(state)
	{
	case CACHE_NEED_FILE:
	    if (strncmp(buff, "file:", 5) == 0)
	    {
		len -= 6;
		f = create_cvsfile();
		f->filename = xstrdup(buff + 6);
		f->filename[len-1] = 0; /* Remove the \n at the end of line */
		debug(DEBUG_STATUS, "read cache filename '%s'", f->filename);
		put_hash_object_ex(file_hash, f->filename, f, HT_NO_KEYCOPY, NULL, NULL);
		state = CACHE_NEED_BRANCHES;
	    }
	    else
	    {
		state = CACHE_NEED_PS;
	    }
	    break;
	case CACHE_NEED_BRANCHES:
	    if (buff[0] != '\n')
	    {
		char * tag;

		tag = strchr(buff, ':');
		if (tag)
		{
		    *tag = 0;
		    tag += 2;
		    buff[len - 1] = 0;
		    cvs_file_add_branch(f, buff, tag);
		}
	    }
	    else
	    {
		f->have_branches = 1;
		state = CACHE_NEED_SYMBOLS;
	    }
	    break;
	case CACHE_NEED_SYMBOLS:
	    if (buff[0] != '\n')
	    {
		char * rev;

		rev = strchr(buff, ':');
		if (rev)
		{
		    *rev = 0;
		    rev += 2;
		    buff[len - 1] = 0;
		    cvs_file_add_symbol(f, rev, buff);
		}
	    }
	    else
	    {
		state = CACHE_NEED_REV;
	    }
	    break;
	case CACHE_NEED_REV:
	    if (isdigit(buff[0]))
	    {
		char * p = strchr(buff, ' ');
		if (p)
		{
		    CvsFileRevision * rev;
		    *p++ = 0;
		    buff[len-1] = 0;
		    rev = cvs_file_add_revision(f, buff);
		    if (strcmp(rev->branch, p) != 0)
		    {
			debug(DEBUG_APPERROR, "branch mismatch for %s:%s %s != %s", 
			      rev->file->filename, rev->rev, rev->branch, p);
		    }
		}
	    }
	    else
	    {
		state = CACHE_NEED_FILE;
	    }
	    break;
	case CACHE_NEED_PS:
	    if (strncmp(buff, "patchset:", 9) == 0)
		state = CACHE_NEED_PS_DATE;
	    break;
	case CACHE_NEED_PS_DATE:
	    if (strncmp(buff, "date:", 5) == 0)
	    {
		/* remove prefix "date: " and LF from len */
		len -= 6;
		strzncpy(datebuff, buff + 6, MIN(len, sizeof(datebuff)));
		state = CACHE_NEED_PS_AUTHOR;
	    }
	    break;
	case CACHE_NEED_PS_AUTHOR:
	    if (strncmp(buff, "author:", 7) == 0)
	    {
		/* remove prefix "author: " and LF from len */
		len -= 8;
		strzncpy(authbuff, buff + 8, MIN(len, AUTH_STR_MAX));
		state = CACHE_NEED_PS_TAG;
	    }
	    break;
	case CACHE_NEED_PS_TAG:
	    if (strncmp(buff, "tag:", 4) == 0)
	    {
		/* remove prefix "tag: " and LF from len */
		len -= 5;
		strzncpy(tagbuff, buff + 5, MIN(len, LOG_STR_MAX));
		state = CACHE_NEED_PS_TAG_FLAGS;
	    }
	    break;
	case CACHE_NEED_PS_TAG_FLAGS:
	    if (strncmp(buff, "tag_flags:", 10) == 0)
	    {
		/* remove prefix "tag_flags: " and LF from len */
		len -= 11;
		tag_flags = atoi(buff + 11);
		state = CACHE_NEED_PS_BRANCH;
	    }
	    break;
	case CACHE_NEED_PS_BRANCH:
	    if (strncmp(buff, "branch:", 7) == 0)
	    {
		/* remove prefix "branch: " and LF from len */
		len -= 8;
		strzncpy(branchbuff, buff + 8, MIN(len, LOG_STR_MAX));
		state = CACHE_NEED_PS_BRANCH_ADD;
	    }
	    break;
	case CACHE_NEED_PS_BRANCH_ADD:
	    if (strncmp(buff, "branch_add:", 11) == 0)
	    {
		/* remove prefix "branch_add: " and LF from len */
		len -= 12;
		branch_add = atoi(buff + 12);
		state = CACHE_NEED_PS_DESCR;
	    }
	    break;
	case CACHE_NEED_PS_DESCR:
	    if (strncmp(buff, "descr:", 6) == 0)
		state = CACHE_NEED_PS_EOD;
	    break;
	case CACHE_NEED_PS_EOD:
	    if (strcmp(buff, CACHE_DESCR_BOUNDARY) == 0)
	    {
		debug(DEBUG_STATUS, "patch set %s %s %s %s", datebuff, authbuff, logbuff, branchbuff);
		ps = get_patch_set(datebuff, logbuff, authbuff, branchbuff, NULL);
		/* the tag and tag_flags will be assigned by the resolve_global_symbols code 
		 * ps->tag = (strlen(tagbuff)) ? get_string(tagbuff) : NULL;
		 * ps->tag_flags = tag_flags;
		 */
		ps->branch_add = branch_add;
		state = CACHE_NEED_PS_MEMBERS;
	    }
	    else
	    {
		/* Make sure we have enough in the buffer */
		if (strlen(logbuff)+strlen(buff)<LOG_STR_MAX)
		    strcat(logbuff, buff);
	    }
	    break;
	case CACHE_NEED_PS_MEMBERS:
	    if (strncmp(buff, "members:", 8) == 0)
		state = CACHE_NEED_PS_EOM;
	    break;
	case CACHE_NEED_PS_EOM:
	    if (buff[0] == '\n')
	    {
		datebuff[0] = 0;
		authbuff[0] = 0;
		tagbuff[0] = 0;
		tag_flags = 0;
		branchbuff[0] = 0;
		branch_add = 0;
		logbuff[0] = 0;
		state = CACHE_NEED_PS;
	    }
	    else
	    {
		PatchSetMember * psm = create_patch_set_member();
		parse_cache_revision(psm, buff);
		patch_set_add_member(ps, psm);
	    }
	    break;
	}
    }

 out_close:
    fclose(fp);
 out:
    return cache_date;
}

enum
{
    CR_FILENAME,
    CR_PRE_REV,
    CR_POST_REV,
    CR_DEAD,
    CR_BRANCH_POINT
};

static void parse_cache_revision(PatchSetMember * psm, const char * p_buff)
{
    /* The format used to generate is:
     * "file:%s; pre_rev:%s; post_rev:%s; dead:%d; branch_point:%d\n"
     */
    char filename[PATH_MAX];
    char pre[REV_STR_MAX];
    char post[REV_STR_MAX];
    int dead = 0;
    int bp = 0;
    char buff[BUFSIZ];
    int state = CR_FILENAME;
    const char *s;
    char * p = buff;

    strcpy(buff, p_buff);

    while ((s = strsep(&p, ";")))
    {
	char * c = strchr(s, ':');

	if (!c)
	{
	    debug(DEBUG_APPERROR, "invalid cache revision line '%s'|'%s'", p_buff, s);
	    exit(1);
	}

	*c++ = 0;

	switch(state)
	{
	case CR_FILENAME:
	    strcpy(filename, c);
	    break;
	case CR_PRE_REV:
	    strcpy(pre, c);
	    break;
	case CR_POST_REV:
	    strcpy(post, c);
	    break;
	case CR_DEAD:
	    dead = atoi(c);
	    break;
	case CR_BRANCH_POINT:
	    bp = atoi(c);
	    break;
	}
	state++;
    }

    psm->file = (CvsFile*)get_hash_object(file_hash, filename);

    if (!psm->file)
    {
	debug(DEBUG_APPERROR, "file '%s' not found in hash", filename);
	exit(1);
    }

    psm->pre_rev = file_get_revision(psm->file, pre);
    psm->post_rev = file_get_revision(psm->file, post);
    psm->post_rev->dead = dead;
    psm->post_rev->post_psm = psm;

    if (!bp)
    {
	if (psm->pre_rev)
	    psm->pre_rev->pre_psm = psm;
    }
    else
    {
	list_add(&psm->post_rev->link, &psm->pre_rev->branch_children);
    }
}

/************ Writing ************/

void write_cache(time_t cache_date)
{
    struct hash_entry * file_iter;

    ps_counter = 0;

    if ((cache_fp = cache_open("w")) == NULL)
    {
	debug(DEBUG_SYSERROR, "can't open cvsps.cache for write");
	return;
    }

    fprintf(cache_fp, "cache version: %d\n", cache_version);
    fprintf(cache_fp, "cache date: %d\n", (int)cache_date);

    reset_hash_iterator(file_hash);

    while ((file_iter = next_hash_entry(file_hash)))
    {
	CvsFile * file = (CvsFile*)file_iter->he_obj;
	struct hash_entry * rev_iter;

	fprintf(cache_fp, "file: %s\n", file->filename);

	reset_hash_iterator(file->branches);
	while ((rev_iter = next_hash_entry(file->branches)))
	{
	    char * rev = (char *)rev_iter->he_key;
	    char * tag = (char *)rev_iter->he_obj;
	    fprintf(cache_fp, "%s: %s\n", rev, tag);
	}

	fprintf(cache_fp, "\n");

	reset_hash_iterator(file->symbols);
	while ((rev_iter = next_hash_entry(file->symbols)))
	{
	    char * tag = (char *)rev_iter->he_key;
	    CvsFileRevision * rev = (CvsFileRevision*)rev_iter->he_obj;
	    
	    if (rev->present)
		fprintf(cache_fp, "%s: %s\n", tag, rev->rev);
	}

	fprintf(cache_fp, "\n");

	reset_hash_iterator(file->revisions);
	while ((rev_iter = next_hash_entry(file->revisions)))
	{
	    CvsFileRevision * rev = (CvsFileRevision*)rev_iter->he_obj;
	    if (rev->present)
		fprintf(cache_fp, "%s %s\n", rev->rev, rev->branch);
	}

	fprintf(cache_fp, "\n");
    }

    fprintf(cache_fp, "\n");
    walk_all_patch_sets(write_patch_set_to_cache);
    fclose(cache_fp);
    cache_fp = NULL;
}

static void write_patch_set_to_cache(PatchSet * ps)
{
    dump_patch_set(cache_fp, ps);
}

static void dump_patch_set(FILE * fp, PatchSet * ps)
{
    struct list_head * next = ps->members.next;

    ps_counter++;
    fprintf(fp, "patchset: %d\n", ps_counter);
    fprintf(fp, "date: %d\n", (int)ps->date);
    fprintf(fp, "author: %s\n", ps->author);
    fprintf(fp, "tag: %s\n", ps->tag ? ps->tag : "");
    fprintf(fp, "tag_flags: %d\n", ps->tag_flags);
    fprintf(fp, "branch: %s\n", ps->branch);
    fprintf(fp, "branch_add: %d\n", ps->branch_add);
    fprintf(fp, "descr:\n%s", ps->descr); /* descr is guaranteed to end with LF */
    fprintf(fp, CACHE_DESCR_BOUNDARY);
    fprintf(fp, "members:\n");

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	int bp = 1;
	
	/* this actually deduces if this revision is a branch point... */
	if (!psm->pre_rev || (psm->pre_rev->pre_psm && psm->pre_rev->pre_psm == psm))
	    bp = 0;

	fflush(fp);
    
	fprintf(fp, "file:%s; pre_rev:%s; post_rev:%s; dead:%d; branch_point:%d\n", 
		psm->file->filename, 
		psm->pre_rev ? psm->pre_rev->rev : "INITIAL", psm->post_rev->rev, 
		psm->post_rev->dead, bp);
	next = next->next;
    }

    fprintf(fp, "\n");
}

/* where's arithmetic?... */
