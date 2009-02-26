/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <search.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/wait.h> /* for WEXITSTATUS - see system(3) */

#include <cbtcommon/hash.h>
#include <cbtcommon/list.h>
#include <cbtcommon/text_util.h>
#include <cbtcommon/debug.h>
#include <cbtcommon/rcsid.h>

#include "cache.h"
#include "cvsps_types.h"
#include "cvsps.h"
#include "util.h"
#include "stats.h"
#include "cap.h"
#include "cvs_direct.h"
#include "list_sort.h"

RCSID("$Id: cvsps.c,v 4.106 2005/05/26 03:39:29 david Exp $");

#define CVS_LOG_BOUNDARY "----------------------------\n"
#define CVS_FILE_BOUNDARY "=============================================================================\n"

enum
{
    NEED_RCS_FILE,
    NEED_WORKING_FILE,
    NEED_SYMS,
    NEED_EOS,
    NEED_START_LOG,
    NEED_REVISION,
    NEED_DATE_AUTHOR_STATE,
    NEED_EOM
};

/* true globals */
struct hash_table * file_hash;
CvsServerCtx * cvs_direct_ctx;
char root_path[PATH_MAX];
char repository_path[PATH_MAX];

const char * tag_flag_descr[] = {
    "",
    "**FUNKY**",
    "**INVALID**",
    "**INVALID**"
};

const char * fnk_descr[] = {
    "",
    "FNK_SHOW_SOME",
    "FNK_SHOW_ALL",
    "FNK_HIDE_ALL",
    "FNK_HIDE_SOME"
};

/* static globals */
static int ps_counter;
static void * ps_tree;
static struct hash_table * global_symbols;
static char strip_path[PATH_MAX];
static int strip_path_len;
static time_t cache_date;
static int update_cache;
static int ignore_cache;
static int do_write_cache;
static int statistics;
static const char * test_log_file;
static struct hash_table * branch_heads;
static struct list_head all_patch_sets;
static struct list_head collisions;

/* settable via options */
static int timestamp_fuzz_factor = 300;
static int do_diff;
static const char * restrict_author;
static int have_restrict_log;
static regex_t restrict_log;
static int have_restrict_file;
static regex_t restrict_file;
static time_t restrict_date_start;
static time_t restrict_date_end;
static const char * restrict_branch;
static struct list_head show_patch_set_ranges;
static int summary_first;
static const char * norc = "";
static const char * patch_set_dir;
static const char * restrict_tag_start;
static const char * restrict_tag_end;
static int restrict_tag_ps_start;
static int restrict_tag_ps_end = INT_MAX;
static const char * diff_opts;
static int bkcvs;
static int no_rlog;
static int cvs_direct;
static int compress;
static char compress_arg[8];
static int track_branch_ancestry;

static void check_norc(int, char *[]);
static int parse_args(int, char *[]);
static int parse_rc();
static void load_from_cvs();
static void init_paths();
static CvsFile * build_file_by_name(const char *);
static CvsFile * parse_rcs_file(const char *);
static CvsFile * parse_working_file(const char *);
static CvsFileRevision * parse_revision(CvsFile * file, char * rev_str);
static void assign_pre_revision(PatchSetMember *, CvsFileRevision * rev);
static void check_print_patch_set(PatchSet *);
static void print_patch_set(PatchSet *);
static void assign_patchset_id(PatchSet *);
static int compare_rev_strings(const char *, const char *);
static int compare_patch_sets_by_members(const PatchSet * ps1, const PatchSet * ps2);
static int compare_patch_sets_bk(const void *, const void *);
static int compare_patch_sets(const void *, const void *);
static int compare_patch_sets_bytime_list(struct list_head *, struct list_head *);
static int compare_patch_sets_bytime(const PatchSet *, const PatchSet *);
static int is_revision_metadata(const char *);
static int patch_set_member_regex(PatchSet * ps, regex_t * reg);
static int patch_set_affects_branch(PatchSet *, const char *);
static void do_cvs_diff(PatchSet *);
static PatchSet * create_patch_set();
static PatchSetRange * create_patch_set_range();
static void parse_sym(CvsFile *, char *);
static void resolve_global_symbols();
static int revision_affects_branch(CvsFileRevision *, const char *);
static int is_vendor_branch(const char *);
static void set_psm_initial(PatchSetMember * psm);
static int check_rev_funk(PatchSet *, CvsFileRevision *);
static CvsFileRevision * rev_follow_branch(CvsFileRevision *, const char *);
static int before_tag(CvsFileRevision * rev, const char * tag);
static void determine_branch_ancestor(PatchSet * ps, PatchSet * head_ps);
static void handle_collisions();

int main(int argc, char *argv[])
{
    debuglvl = DEBUG_APPERROR|DEBUG_SYSERROR|DEBUG_APPMSG1;

    INIT_LIST_HEAD(&show_patch_set_ranges);

    /*
     * we want to parse the rc first, so command line can override it
     * but also, --norc should stop the rc from being processed, so
     * we look for --norc explicitly first.  Note: --norc in the rc 
     * file itself will prevent the cvs rc file from being used.
     */
    check_norc(argc, argv);

    if (strlen(norc) == 0 && parse_rc() < 0)
	exit(1);

    if (parse_args(argc, argv) < 0)
	exit(1);

    if (diff_opts && !cvs_direct && do_diff)
    {
	debug(DEBUG_APPMSG1, "\nWARNING: diff options are not supported by 'cvs rdiff'");
	debug(DEBUG_APPMSG1, "         which is usually used to create diffs.  'cvs diff'");
	debug(DEBUG_APPMSG1, "         will be used instead, but the resulting patches ");
	debug(DEBUG_APPMSG1, "         will need to be applied using the '-p0' option");
	debug(DEBUG_APPMSG1, "         to patch(1) (in the working directory), ");
	debug(DEBUG_APPMSG1, "         instead of '-p1'\n");
    }

    file_hash = create_hash_table(1023);
    global_symbols = create_hash_table(111);
    branch_heads = create_hash_table(1023);
    INIT_LIST_HEAD(&all_patch_sets);
    INIT_LIST_HEAD(&collisions);

    /* this parses some of the CVS/ files, and initializes
     * the repository_path and other variables 
     */
    init_paths();

    if (!ignore_cache)
    {
	int save_fuzz_factor = timestamp_fuzz_factor;

	/* the timestamp fuzz should only be in effect when loading from
	 * CVS, not re-fuzzed when loading from cache.  This is a hack
	 * working around bad use of global variables
	 */

	timestamp_fuzz_factor = 0;

	if ((cache_date = read_cache()) < 0)
	    update_cache = 1;

	timestamp_fuzz_factor = save_fuzz_factor;
    }

    if (cvs_direct && (do_diff || (update_cache && !test_log_file)))
	cvs_direct_ctx = open_cvs_server(root_path, compress);

    if (update_cache)
    {
	load_from_cvs();
	do_write_cache = 1;
    }

    //XXX
    //handle_collisions();

    list_sort(&all_patch_sets, compare_patch_sets_bytime_list);

    ps_counter = 0;
    walk_all_patch_sets(assign_patchset_id);

    handle_collisions();

    resolve_global_symbols();

    if (do_write_cache)
	write_cache(cache_date);

    if (statistics)
	print_statistics(ps_tree);

    /* check that the '-r' symbols (if specified) were resolved */
    if (restrict_tag_start && restrict_tag_ps_start == 0 && 
	strcmp(restrict_tag_start, "#CVSPS_EPOCH") != 0)
    {
	debug(DEBUG_APPERROR, "symbol given with -r: %s: not found", restrict_tag_start);
	exit(1);
    }

    if (restrict_tag_end && restrict_tag_ps_end == INT_MAX)
    {
	debug(DEBUG_APPERROR, "symbol given with second -r: %s: not found", restrict_tag_end);
	exit(1);
    }

    walk_all_patch_sets(check_print_patch_set);

    if (summary_first++)
	walk_all_patch_sets(check_print_patch_set);

    if (cvs_direct_ctx)
	close_cvs_server(cvs_direct_ctx);

    exit(0);
}

static void load_from_cvs()
{
    FILE * cvsfp;
    char buff[BUFSIZ];
    int state = NEED_RCS_FILE;
    CvsFile * file = NULL;
    PatchSetMember * psm = NULL;
    char datebuff[20];
    char authbuff[AUTH_STR_MAX];
    int logbufflen = LOG_STR_MAX + 1;
    char * logbuff = malloc(logbufflen);
    int loglen = 0;
    int have_log = 0;
    char cmd[BUFSIZ];
    char date_str[64];
    char use_rep_buff[PATH_MAX];
    char * ltype;

    if (logbuff == NULL)
    {
	debug(DEBUG_SYSERROR, "could not malloc %d bytes for logbuff in load_from_cvs", logbufflen);
	exit(1);
    }

    if (!no_rlog && !test_log_file && cvs_check_cap(CAP_HAVE_RLOG))
    {
	ltype = "rlog";
	snprintf(use_rep_buff, PATH_MAX, "%s", repository_path);
    }
    else
    {
	ltype = "log";
	use_rep_buff[0] = 0;
    }

    if (cache_date > 0)
    {
	struct tm * tm = gmtime(&cache_date);
	strftime(date_str, 64, "%d %b %Y %H:%M:%S %z", tm);

	/* this command asks for logs using two different date
	 * arguments, separated by ';' (see man rlog).  The first
	 * gets all revisions more recent than date, the second 
	 * gets a single revision no later than date, which combined
	 * get us all revisions that have occurred since last update
	 * and overlaps what we had before by exactly one revision,
	 * which is necessary to fill in the pre_rev stuff for a 
	 * PatchSetMember
	 */
	snprintf(cmd, BUFSIZ, "cvs %s %s -q %s -d '%s<;%s' %s", compress_arg, norc, ltype, date_str, date_str, use_rep_buff);
    }
    else
    {
	date_str[0] = 0;
	snprintf(cmd, BUFSIZ, "cvs %s %s -q %s %s", compress_arg, norc, ltype, use_rep_buff);
    }
    
    debug(DEBUG_STATUS, "******* USING CMD %s", cmd);

    cache_date = time(NULL);

    /* FIXME: this is ugly, need to virtualize the accesses away from here */
    if (test_log_file)
	cvsfp = fopen(test_log_file, "r");
    else if (cvs_direct_ctx)
	cvsfp = cvs_rlog_open(cvs_direct_ctx, repository_path, date_str);
    else
	cvsfp = popen(cmd, "r");

    if (!cvsfp)
    {
	debug(DEBUG_SYSERROR, "can't open cvs pipe using command %s", cmd);
	exit(1);
    }

    for (;;)
    {
	char * tst;
	if (cvs_direct_ctx)
	    tst = cvs_rlog_fgets(buff, BUFSIZ, cvs_direct_ctx);
	else
	    tst = fgets(buff, BUFSIZ, cvsfp);

	if (!tst)
	    break;

	debug(DEBUG_STATUS, "state: %d read line:%s", state, buff);

	switch(state)
	{
	case NEED_RCS_FILE:
	    if (strncmp(buff, "RCS file", 8) == 0) {
              if ((file = parse_rcs_file(buff)) != NULL)
		state = NEED_SYMS;
              else
                state = NEED_WORKING_FILE;
            }
	    break;
	case NEED_WORKING_FILE:
	    if (strncmp(buff, "Working file", 12) == 0) {
              if ((file = parse_working_file(buff)))
		state = NEED_SYMS;
              else
                state = NEED_RCS_FILE;
		break;
	    } else {
              // Working file come just after RCS file. So reset state if it was not found
              state = NEED_RCS_FILE;
            }
            break;
	case NEED_SYMS:
	    if (strncmp(buff, "symbolic names:", 15) == 0)
		state = NEED_EOS;
	    break;
	case NEED_EOS:
	    if (!isspace(buff[0]))
	    {
		/* see cvsps_types.h for commentary on have_branches */
		file->have_branches = 1;
		state = NEED_START_LOG;
	    }
	    else
		parse_sym(file, buff);
	    break;
	case NEED_START_LOG:
	    if (strcmp(buff, CVS_LOG_BOUNDARY) == 0)
		state = NEED_REVISION;
	    break;
	case NEED_REVISION:
	    if (strncmp(buff, "revision", 8) == 0)
	    {
		char new_rev[REV_STR_MAX];
		CvsFileRevision * rev;

		strcpy(new_rev, buff + 9);
		chop(new_rev);

		/* 
		 * rev may already exist (think cvsps -u), in which
		 * case parse_revision is a hash lookup
		 */
		rev = parse_revision(file, new_rev);

		/* 
		 * in the simple case, we are copying rev to psm->pre_rev
		 * (psm refers to last patch set processed at this point)
		 * since generally speaking the log is reverse chronological.
		 * This breaks down slightly when branches are introduced 
		 */

		assign_pre_revision(psm, rev);

		/*
		 * if this is a new revision, it will have no post_psm associated.
		 * otherwise we are (probably?) hitting the overlap in cvsps -u 
		 */
		if (!rev->post_psm)
		{
		    psm = rev->post_psm = create_patch_set_member();
		    psm->post_rev = rev;
		    psm->file = file;
		    state = NEED_DATE_AUTHOR_STATE;
		}
		else
		{
		    /* we hit this in cvsps -u mode, we are now up-to-date
		     * w.r.t this particular file. skip all of the rest 
		     * of the info (revs and logs) until we hit the next file
		     */
		    psm = NULL;
		    state = NEED_EOM;
		}
	    }
	    break;
	case NEED_DATE_AUTHOR_STATE:
	    if (strncmp(buff, "date:", 5) == 0)
	    {
		char * p;

		strncpy(datebuff, buff + 6, 19);
		datebuff[19] = 0;

		strcpy(authbuff, "unknown");
		p = strstr(buff, "author: ");
		if (p)
		{
		    char * op;
		    p += 8;
		    op = strchr(p, ';');
		    if (op)
		    {
			strzncpy(authbuff, p, op - p + 1);
		    }
		}
		
		/* read the 'state' tag to see if this is a dead revision */
		p = strstr(buff, "state: ");
		if (p)
		{
		    char * op;
		    p += 7;
		    op = strchr(p, ';');
		    if (op)
			if (strncmp(p, "dead", MIN(4, op - p)) == 0)
			    psm->post_rev->dead = 1;
		}

		state = NEED_EOM;
	    }
	    break;
	case NEED_EOM:
	    if (strcmp(buff, CVS_LOG_BOUNDARY) == 0)
	    {
		if (psm)
		{
		    PatchSet * ps = get_patch_set(datebuff, logbuff, authbuff, psm->post_rev->branch, psm);
		    patch_set_add_member(ps, psm);
		}

		logbuff[0] = 0;
		loglen = 0;
		have_log = 0;
		state = NEED_REVISION;
	    }
	    else if (strcmp(buff, CVS_FILE_BOUNDARY) == 0)
	    {
		if (psm)
		{
		    PatchSet * ps = get_patch_set(datebuff, logbuff, authbuff, psm->post_rev->branch, psm);
		    patch_set_add_member(ps, psm);
		    assign_pre_revision(psm, NULL);
		}

		logbuff[0] = 0;
		loglen = 0;
		have_log = 0;
		psm = NULL;
		file = NULL;
		state = NEED_RCS_FILE;
	    }
	    else
	    {
		/* other "blahblah: information;" messages can 
		 * follow the stuff we pay attention to
		 */
		if (have_log || !is_revision_metadata(buff))
		{
		    /* If the log buffer is full, try to reallocate more. */
		    if (loglen < logbufflen)
		    {
			int len = strlen(buff);
			
			if (len >= logbufflen - loglen)
			{
			    debug(DEBUG_STATUS, "reallocating logbufflen to %d bytes for file %s", logbufflen, file->filename);
			    logbufflen += (len >= LOG_STR_MAX ? (len+1) : LOG_STR_MAX);
			    char * newlogbuff = realloc(logbuff, logbufflen);
			    if (newlogbuff == NULL)
			    {
				debug(DEBUG_SYSERROR, "could not realloc %d bytes for logbuff in load_from_cvs", logbufflen);
				exit(1);
			    }
			    logbuff = newlogbuff;
			}

			debug(DEBUG_STATUS, "appending %s to log", buff);
			memcpy(logbuff + loglen, buff, len);
			loglen += len;
			logbuff[loglen] = 0;
			have_log = 1;
		    }
		}
		else 
		{
		    debug(DEBUG_STATUS, "ignoring unhandled info %s", buff);
		}
	    }

	    break;
	}
    }

    if (state == NEED_SYMS)
    {
	debug(DEBUG_APPERROR, "Error: 'symbolic names' not found in log output.");
	debug(DEBUG_APPERROR, "       Perhaps you should try running with --norc");
	exit(1);
    }

    if (state != NEED_RCS_FILE)
    {
	debug(DEBUG_APPERROR, "Error: Log file parsing error. (%d)  Use -v to debug", state);
	exit(1);
    }
    
    if (test_log_file)
    {
	fclose(cvsfp);
    }
    else if (cvs_direct_ctx)
    {
	cvs_rlog_close(cvs_direct_ctx);
    }
    else
    {
	if (pclose(cvsfp) < 0)
	{
	    debug(DEBUG_APPERROR, "cvs rlog command exited with error. aborting");
	    exit(1);
	}
    }
}

static int usage(const char * str1, const char * str2)
{
    if (str1)
	debug(DEBUG_APPERROR, "\nbad usage: %s %s\n", str1, str2);

    debug(DEBUG_APPERROR, "Usage: cvsps [-h] [-x] [-u] [-z <fuzz>] [-g] [-s <range>[,<range>]]  ");
    debug(DEBUG_APPERROR, "             [-a <author>] [-f <file>] [-d <date1> [-d <date2>]] ");
    debug(DEBUG_APPERROR, "             [-b <branch>]  [-l <regex>] [-r <tag> [-r <tag>]] ");
    debug(DEBUG_APPERROR, "             [-p <directory>] [-v] [-t] [--norc] [--summary-first]");
    debug(DEBUG_APPERROR, "             [--test-log <captured cvs log file>] [--bkcvs]");
    debug(DEBUG_APPERROR, "             [--no-rlog] [--diff-opts <option string>] [--cvs-direct]");
    debug(DEBUG_APPERROR, "             [--debuglvl <bitmask>] [-Z <compression>] [--root <cvsroot>]");
    debug(DEBUG_APPERROR, "             [-q] [-A] [<repository>]");
    debug(DEBUG_APPERROR, "");
    debug(DEBUG_APPERROR, "Where:");
    debug(DEBUG_APPERROR, "  -h display this informative message");
    debug(DEBUG_APPERROR, "  -x ignore (and rebuild) cvsps.cache file");
    debug(DEBUG_APPERROR, "  -u update cvsps.cache file");
    debug(DEBUG_APPERROR, "  -z <fuzz> set the timestamp fuzz factor for identifying patch sets");
    debug(DEBUG_APPERROR, "  -g generate diffs of the selected patch sets");
    debug(DEBUG_APPERROR, "  -s <patch set>[-[<patch set>]][,<patch set>...] restrict patch sets by id");
    debug(DEBUG_APPERROR, "  -a <author> restrict output to patch sets created by author");
    debug(DEBUG_APPERROR, "  -f <file> restrict output to patch sets involving file");
    debug(DEBUG_APPERROR, "  -d <date1> -d <date2> if just one date specified, show");
    debug(DEBUG_APPERROR, "     revisions newer than date1.  If two dates specified,");
    debug(DEBUG_APPERROR, "     show revisions between two dates.");
    debug(DEBUG_APPERROR, "  -b <branch> restrict output to patch sets affecting history of branch");
    debug(DEBUG_APPERROR, "  -l <regex> restrict output to patch sets matching <regex> in log message");
    debug(DEBUG_APPERROR, "  -r <tag1> -r <tag2> if just one tag specified, show");
    debug(DEBUG_APPERROR, "     revisions since tag1. If two tags specified, show");
    debug(DEBUG_APPERROR, "     revisions between the two tags.");
    debug(DEBUG_APPERROR, "  -p <directory> output patch sets to individual files in <directory>");
    debug(DEBUG_APPERROR, "  -v show very verbose parsing messages");
    debug(DEBUG_APPERROR, "  -t show some brief memory usage statistics");
    debug(DEBUG_APPERROR, "  --norc when invoking cvs, ignore the .cvsrc file");
    debug(DEBUG_APPERROR, "  --summary-first when multiple patch sets are shown, put all summaries first");
    debug(DEBUG_APPERROR, "  --test-log <captured cvs log> supply a captured cvs log for testing");
    debug(DEBUG_APPERROR, "  --diff-opts <option string> supply special set of options to diff");
    debug(DEBUG_APPERROR, "  --bkcvs special hack for parsing the BK -> CVS log format");
    debug(DEBUG_APPERROR, "  --no-rlog disable rlog (it's faulty in some setups)");
    debug(DEBUG_APPERROR, "  --cvs-direct (--no-cvs-direct) enable (disable) built-in cvs client code");
    debug(DEBUG_APPERROR, "  --debuglvl <bitmask> enable various debug channels.");
    debug(DEBUG_APPERROR, "  -Z <compression> A value 1-9 which specifies amount of compression");
    debug(DEBUG_APPERROR, "  --root <cvsroot> specify cvsroot.  overrides env. and working directory (cvs-direct only)");
    debug(DEBUG_APPERROR, "  -q be quiet about warnings");
    debug(DEBUG_APPERROR, "  -A track and report branch ancestry");
    debug(DEBUG_APPERROR, "  <repository> apply cvsps to repository.  overrides working directory");
    debug(DEBUG_APPERROR, "\ncvsps version %s\n", VERSION);

    return -1;
}

static int parse_args(int argc, char *argv[])
{
    int i = 1;
    while (i < argc)
    {
	if (strcmp(argv[i], "-z") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -z missing", "");

	    timestamp_fuzz_factor = atoi(argv[i++]);
	    continue;
	}
	
	if (strcmp(argv[i], "-g") == 0)
	{
	    do_diff = 1;
	    i++;
	    continue;
	}
	
	if (strcmp(argv[i], "-s") == 0)
	{
	    PatchSetRange * range;
	    char * min_str, * max_str;

	    if (++i >= argc)
		return usage("argument to -s missing", "");

	    min_str = strtok(argv[i++], ",");
	    do
	    {
		range = create_patch_set_range();

		max_str = strrchr(min_str, '-');
		if (max_str)
		    *max_str++ = '\0';
		else
		    max_str = min_str;

		range->min_counter = atoi(min_str);

		if (*max_str)
		    range->max_counter = atoi(max_str);
		else
		    range->max_counter = INT_MAX;

		list_add(&range->link, show_patch_set_ranges.prev);
	    }
	    while ((min_str = strtok(NULL, ",")));

	    continue;
	}
	
	if (strcmp(argv[i], "-a") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -a missing", "");

	    restrict_author = argv[i++];
	    continue;
	}

	if (strcmp(argv[i], "-l") == 0)
	{
	    int err;

	    if (++i >= argc)
		return usage("argument to -l missing", "");

	    if ((err = regcomp(&restrict_log, argv[i++], REG_EXTENDED|REG_NOSUB)) != 0)
	    {
		char errbuf[256];
		regerror(err, &restrict_log, errbuf, 256);
		return usage("bad regex to -l", errbuf);
	    }

	    have_restrict_log = 1;

	    continue;
	}

	if (strcmp(argv[i], "-f") == 0)
	{
	    int err;

	    if (++i >= argc)
		return usage("argument to -f missing", "");

	    if ((err = regcomp(&restrict_file, argv[i++], REG_EXTENDED|REG_NOSUB)) != 0)
	    {
		char errbuf[256];
		regerror(err, &restrict_file, errbuf, 256);
		return usage("bad regex to -f", errbuf);
	    }

	    have_restrict_file = 1;

	    continue;
	}
	
	if (strcmp(argv[i], "-d") == 0)
	{
	    time_t *pt;

	    if (++i >= argc)
		return usage("argument to -d missing", "");

	    pt = (restrict_date_start == 0) ? &restrict_date_start : &restrict_date_end;
	    convert_date(pt, argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-r") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -r missing", "");

	    if (restrict_tag_start)
		restrict_tag_end = argv[i];
	    else
		restrict_tag_start = argv[i];

	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-u") == 0)
	{
	    update_cache = 1;
	    i++;
	    continue;
	}
	
	if (strcmp(argv[i], "-x") == 0)
	{
	    ignore_cache = 1;
	    update_cache = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-b") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -b missing", "");

	    restrict_branch = argv[i++];
	    /* Warn if the user tries to use TRUNK. Should eventually
	     * go away as TRUNK may be a valid branch within CVS
	     */
	    if (strcmp(restrict_branch, "TRUNK") == 0)
		debug(DEBUG_APPMSG1, "WARNING: The HEAD branch of CVS is called HEAD, not TRUNK");
	    continue;
	}

	if (strcmp(argv[i], "-p") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -p missing", "");
	    
	    patch_set_dir = argv[i++];
	    continue;
	}

	if (strcmp(argv[i], "-v") == 0)
	{
	    debuglvl = ~0;
	    i++;
	    continue;
	}
	
	if (strcmp(argv[i], "-t") == 0)
	{
	    statistics = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--summary-first") == 0)
	{
	    summary_first = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-h") == 0)
	    return usage(NULL, NULL);

	/* see special handling of --norc in main */
	if (strcmp(argv[i], "--norc") == 0)
	{
	    norc = "-f";
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--test-log") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --test-log missing", "");

	    test_log_file = argv[i++];
	    continue;
	}

	if (strcmp(argv[i], "--diff-opts") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --diff-opts missing", "");

	    /* allow diff_opts to be turned off by making empty string
	     * into NULL
	     */
	    if (!strlen(argv[i]))
		diff_opts = NULL;
	    else
		diff_opts = argv[i];
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--bkcvs") == 0)
	{
	    bkcvs = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--no-rlog") == 0)
	{
	    no_rlog = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--cvs-direct") == 0)
	{
	    cvs_direct = 1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--no-cvs-direct") == 0)
	{
	    cvs_direct = 0;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "--debuglvl") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --debuglvl missing", "");

	    debuglvl = atoi(argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-Z") == 0)
	{
	    if (++i >= argc)
		return usage("argument to -Z", "");

	    compress = atoi(argv[i++]);

	    if (compress < 0 || compress > 9)
		return usage("-Z level must be between 1 and 9 inclusive (0 disables compression)", argv[i-1]);

	    if (compress == 0)
		compress_arg[0] = 0;
	    else
		snprintf(compress_arg, 8, "-z%d", compress);
	    continue;
	}
	
	if (strcmp(argv[i], "--root") == 0)
	{
	    if (++i >= argc)
		return usage("argument to --root missing", "");

	    strcpy(root_path, argv[i++]);
	    continue;
	}

	if (strcmp(argv[i], "-q") == 0)
	{
	    debuglvl &= ~DEBUG_APPMSG1;
	    i++;
	    continue;
	}

	if (strcmp(argv[i], "-A") == 0)
	{
	    track_branch_ancestry = 1;
	    i++;
	    continue;
	}

	if (argv[i][0] == '-')
	    return usage("invalid argument", argv[i]);
	
	strcpy(repository_path, argv[i++]);
    }

    return 0;
}

static int parse_rc()
{
    char rcfile[PATH_MAX];
    FILE * fp;
    snprintf(rcfile, PATH_MAX, "%s/cvspsrc", get_cvsps_dir());
    if ((fp = fopen(rcfile, "r")))
    {
	char buff[BUFSIZ];
	while (fgets(buff, BUFSIZ, fp))
	{
	    char * argv[3], *p;
	    int argc = 2;

	    chop(buff);

	    argv[0] = "garbage";

	    p = strchr(buff, ' ');
	    if (p)
	    {
		*p++ = '\0';
		argv[2] = xstrdup(p);
		argc = 3;
	    }

	    argv[1] = xstrdup(buff);

	    if (parse_args(argc, argv) < 0)
		return -1;
	}
	fclose(fp);
    }

    return 0;
}

static void init_paths()
{
    FILE * fp;
    char * p;
    int len;

    /* determine the CVSROOT. precedence:
     * 1) command line
     * 2) working directory (if present)
     * 3) environment variable CVSROOT
     */
    if (!root_path[0])
    {
	if (!(fp = fopen("CVS/Root", "r")))
	{
	    const char * e;

	    debug(DEBUG_STATUS, "Can't open CVS/Root");
	    e = getenv("CVSROOT");

	    if (!e)
	    {
		debug(DEBUG_APPERROR, "cannot determine CVSROOT");
		exit(1);
	    }
	    
	    strcpy(root_path, e);
	}
	else
	{
	    if (!fgets(root_path, PATH_MAX, fp))
	    {
		debug(DEBUG_APPERROR, "Error reading CVSROOT");
		exit(1);
	    }
	    
	    fclose(fp);
	    
	    /* chop the lf and optional trailing '/' */
	    len = strlen(root_path) - 1;
	    root_path[len] = 0;
	    if (root_path[len - 1] == '/')
		root_path[--len] = 0;
	}
    }

    /* Determine the repository path, precedence:
     * 1) command line
     * 2) working directory
     */
      
    if (!repository_path[0])
    {
	if (!(fp = fopen("CVS/Repository", "r")))
	{
	    debug(DEBUG_SYSERROR, "Can't open CVS/Repository");
	    exit(1);
	}
	
	if (!fgets(repository_path, PATH_MAX, fp))
	{
	    debug(DEBUG_APPERROR, "Error reading repository path");
	    exit(1);
	}
	
	chop(repository_path);
	fclose(fp);
    }

    /* get the path portion of the root */
    p = strrchr(root_path, ':');

    if (!p)
	p = root_path;
    else 
	p++;

    /* some CVS have the CVSROOT string as part of the repository
     * string (initial substring).  remove it.
     */
    len = strlen(p);

    if (strncmp(p, repository_path, len) == 0)
    {
	int rlen = strlen(repository_path + len + 1);
	memmove(repository_path, repository_path + len + 1, rlen + 1);
    }

    /* the 'strip_path' will be used whenever the CVS server gives us a
     * path to an 'rcs file'.  the strip_path portion of these paths is
     * stripped off, leaving us with the working file.
     *
     * NOTE: because of some bizarre 'feature' in cvs, when 'rlog' is used
     * (instead of log) it gives the 'real' RCS file path, which can be different
     * from the 'nominal' repository path because of symlinks in the server and
     * the like.  See also the 'parse_rcs_file' routine
     */
    strip_path_len = snprintf(strip_path, PATH_MAX, "%s/%s/", p, repository_path);

    if (strip_path_len < 0 || strip_path_len >= PATH_MAX)
    {
	debug(DEBUG_APPERROR, "strip_path overflow");
	exit(1);
    }

    debug(DEBUG_STATUS, "strip_path: %s", strip_path);
}

static CvsFile * parse_rcs_file(const char * buff)
{
    char fn[PATH_MAX];
    int len = strlen(buff + 10);
    char * p;

    /* once a single file has been parsed ok we set this */
    static int path_ok;
    
    /* chop the ",v" string and the "LF" */
    len -= 3;
    memcpy(fn, buff + 10, len);
    fn[len] = 0;
    
    if (strncmp(fn, strip_path, strip_path_len) != 0)
    {
	/* if the very first file fails the strip path,
	 * then maybe we need to try for an alternate.
	 * this will happen if symlinks are being used
	 * on the server.  our best guess is to look
	 * for the final occurance of the repository
	 * path in the filename and use that.  it should work
	 * except in the case where:
	 * 1) the project has no files in the top-level directory
	 * 2) the project has a directory with the same name as the project
	 * 3) that directory sorts alphabetically before any other directory
	 * in which case, you are scr**ed
	 */
	if (!path_ok)
	{
	    char * p = fn, *lastp = NULL;

	    while ((p = strstr(p, repository_path)))
		lastp = p++;
      
	    if (lastp)
	    {
		int len = strlen(repository_path);
		memcpy(strip_path, fn, lastp - fn + len + 1);
		strip_path_len = lastp - fn + len + 1;
		strip_path[strip_path_len] = 0;
		debug(DEBUG_APPMSG1, "NOTICE: used alternate strip path %s", strip_path);
		goto ok;
	    }
	}

	/* FIXME: a subdirectory may have a different Repository path
	 * than it's parent.  we'll fail the above test since strip_path
	 * is global for the entire checked out tree (recursively).
	 *
	 * For now just ignore such files
	 */
	debug(DEBUG_APPMSG1, "WARNING: file %s doesn't match strip_path %s. ignoring", 
	      fn, strip_path);
	return NULL;
    }

 ok:
    path_ok = 1;

    /* remove from beginning the 'strip_path' string */
    len -= strip_path_len;
    memmove(fn, fn + strip_path_len, len);
    fn[len] = 0;

    /* check if file is in the 'Attic/' and remove it */
    if ((p = strrchr(fn, '/')) &&
	p - fn >= 5 && strncmp(p - 5, "Attic", 5) == 0)
    {
	memmove(p - 5, p + 1, len - (p - fn + 1));
	len -= 6;
	fn[len] = 0;
    }

    debug(DEBUG_STATUS, "stripped filename %s", fn);

    return build_file_by_name(fn);
}

static CvsFile * parse_working_file(const char * buff)
{
    char fn[PATH_MAX];
    int len = strlen(buff + 14);

    /* chop the "LF" */
    len -= 1;
    memcpy(fn, buff + 14, len);
    fn[len] = 0;

    debug(DEBUG_STATUS, "working filename %s", fn);

    return build_file_by_name(fn);
}

static CvsFile * build_file_by_name(const char * fn)
{
    CvsFile * retval;

    retval = (CvsFile*)get_hash_object(file_hash, fn);

    if (!retval)
    {
	if ((retval = create_cvsfile()))
	{
	    retval->filename = xstrdup(fn);
	    put_hash_object_ex(file_hash, retval->filename, retval, HT_NO_KEYCOPY, NULL, NULL);
	}
	else
	{
	    debug(DEBUG_SYSERROR, "malloc failed");
	    exit(1);
	}

	debug(DEBUG_STATUS, "new file: %s", retval->filename);
    }
    else
    {
	debug(DEBUG_STATUS, "existing file: %s", retval->filename);
    }

    return retval;
}

PatchSet * get_patch_set(const char * dte, const char * log, const char * author, const char * branch, PatchSetMember * psm)
{
    PatchSet * retval = NULL, **find = NULL;
    int (*cmp1)(const void *,const void*) = (bkcvs) ? compare_patch_sets_bk : compare_patch_sets;

    if (!(retval = create_patch_set()))
    {
	debug(DEBUG_SYSERROR, "malloc failed for PatchSet");
	return NULL;
    }

    convert_date(&retval->date, dte);
    retval->author = get_string(author);
    retval->descr = xstrdup(log);
    retval->branch = get_string(branch);
    
    /* we are looking for a patchset suitable for holding this member.
     * this means two things:
     * 1) a patchset already containing an entry for the file is no good
     * 2) for two patchsets with same exact date/time, if they reference 
     *    the same file, we can properly order them.  this primarily solves
     *    the 'cvs import' problem and may not have general usefulness
     *    because it would only work if the first member we consider is
     *    present in the existing ps.
     */
    if (psm)
	list_add(&psm->link, retval->members.prev);

    find = (PatchSet**)tsearch(retval, &ps_tree, cmp1);

    if (psm)
	list_del(&psm->link);

    if (*find != retval)
    {
	debug(DEBUG_STATUS, "found existing patch set");

	if (bkcvs && strstr(retval->descr, "BKrev:"))
	{
	    free((*find)->descr);
	    (*find)->descr = retval->descr;
	}
	else
	{
	    free(retval->descr);
	}

	/* keep the minimum date of any member as the 'actual' date */
	if (retval->date < (*find)->date)
	    (*find)->date = retval->date;

	/* expand the min_date/max_date window to help finding other members .
	 * open the window by an extra margin determined by the fuzz factor 
	 */
	if (retval->date - timestamp_fuzz_factor < (*find)->min_date)
	{
	    (*find)->min_date = retval->date - timestamp_fuzz_factor;
	    //debug(DEBUG_APPMSG1, "WARNING: non-increasing dates in encountered patchset members");
	}
	else if (retval->date + timestamp_fuzz_factor > (*find)->max_date)
	    (*find)->max_date = retval->date + timestamp_fuzz_factor;

	free(retval);
	retval = *find;
    }
    else
    {
	debug(DEBUG_STATUS, "new patch set!");
	debug(DEBUG_STATUS, "%s %s %s", retval->author, retval->descr, dte);

	retval->min_date = retval->date - timestamp_fuzz_factor;
	retval->max_date = retval->date + timestamp_fuzz_factor;

	list_add(&retval->all_link, &all_patch_sets);
    }


    return retval;
}

static int get_branch_ext(char * buff, const char * rev, int * leaf)
{
    char * p;
    int len = strlen(rev);

    /* allow get_branch(buff, buff) without destroying contents */
    memmove(buff, rev, len);
    buff[len] = 0;

    p = strrchr(buff, '.');
    if (!p)
	return 0;
    *p++ = 0;

    if (leaf)
	*leaf = atoi(p);

    return 1;
}

static int get_branch(char * buff, const char * rev)
{
    return get_branch_ext(buff, rev, NULL);
}

/* 
 * the goal if this function is to determine what revision to assign to
 * the psm->pre_rev field.  usually, the log file is strictly 
 * reverse chronological, so rev is direct ancestor to psm, 
 * 
 * This all breaks down at branch points however
 */

static void assign_pre_revision(PatchSetMember * psm, CvsFileRevision * rev)
{
    char pre[REV_STR_MAX], post[REV_STR_MAX];

    if (!psm)
	return;
    
    if (!rev)
    {
	/* if psm was last rev. for file, it's either an 
	 * INITIAL, or first rev of a branch.  to test if it's 
	 * the first rev of a branch, do get_branch twice - 
	 * this should be the bp.
	 */
	if (get_branch(post, psm->post_rev->rev) && 
	    get_branch(pre, post))
	{
	    psm->pre_rev = file_get_revision(psm->file, pre);
	    list_add(&psm->post_rev->link, &psm->pre_rev->branch_children);
	}
	else
	{
	    set_psm_initial(psm);
	}
	return;
    }

    /* 
     * is this canditate for 'pre' on the same branch as our 'post'? 
     * this is the normal case
     */
    if (!get_branch(pre, rev->rev))
    {
	debug(DEBUG_APPERROR, "get_branch malformed input (1)");
	return;
    }

    if (!get_branch(post, psm->post_rev->rev))
    {
	debug(DEBUG_APPERROR, "get_branch malformed input (2)");
	return;
    }

    if (strcmp(pre, post) == 0)
    {
	psm->pre_rev = rev;
	rev->pre_psm = psm;
	return;
    }
    
    /* branches don't match. new_psm must be head of branch,
     * so psm is oldest rev. on branch. or oldest
     * revision overall.  if former, derive predecessor.  
     * use get_branch to chop another rev. off of string.
     *
     * FIXME:
     * There's also a weird case.  it's possible to just re-number
     * a revision to any future revision. i.e. rev 1.9 becomes 2.0
     * It's not widely used.  In those cases of discontinuity,
     * we end up stamping the predecessor as 'INITIAL' incorrectly
     *
     */
    if (!get_branch(pre, post))
    {
	set_psm_initial(psm);
	return;
    }
    
    psm->pre_rev = file_get_revision(psm->file, pre);
    list_add(&psm->post_rev->link, &psm->pre_rev->branch_children);
}

static void check_print_patch_set(PatchSet * ps)
{
    if (ps->psid < 0)
	return;

    /* the funk_factor overrides the restrict_tag_start and end */
    if (ps->funk_factor == FNK_SHOW_SOME || ps->funk_factor == FNK_SHOW_ALL)
	goto ok;

    if (ps->funk_factor == FNK_HIDE_ALL)
	return;

    if (ps->psid <= restrict_tag_ps_start)
    {
	if (ps->psid == restrict_tag_ps_start)
	    debug(DEBUG_STATUS, "PatchSet %d matches tag %s.", ps->psid, restrict_tag_start);
	
	return;
    }
    
    if (ps->psid > restrict_tag_ps_end)
	return;

 ok:
    if (restrict_date_start > 0 &&
	(ps->date < restrict_date_start ||
	 (restrict_date_end > 0 && ps->date > restrict_date_end)))
	return;

    if (restrict_author && strcmp(restrict_author, ps->author) != 0)
	return;

    if (have_restrict_log && regexec(&restrict_log, ps->descr, 0, NULL, 0) != 0)
	return;

    if (have_restrict_file && !patch_set_member_regex(ps, &restrict_file))
	return;

    if (restrict_branch && !patch_set_affects_branch(ps, restrict_branch))
	return;
    
    if (!list_empty(&show_patch_set_ranges))
    {
	struct list_head * next = show_patch_set_ranges.next;
	
	while (next != &show_patch_set_ranges)
	{
	    PatchSetRange *range = list_entry(next, PatchSetRange, link);
	    if (range->min_counter <= ps->psid &&
		ps->psid <= range->max_counter)
	    {
		break;
	    }
	    next = next->next;
	}
	
	if (next == &show_patch_set_ranges)
	    return;
    }

    if (patch_set_dir)
    {
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%d.patch", patch_set_dir, ps->psid);

	fflush(stdout);
	close(1);
	if (open(path, O_WRONLY|O_TRUNC|O_CREAT, 0666) < 0)
	{
	    debug(DEBUG_SYSERROR, "can't open patch file %s", path);
	    exit(1);
	}

	fprintf(stderr, "Directing PatchSet %d to file %s\n", ps->psid, path);
    }

    /*
     * If the summary_first option is in effect, there will be 
     * two passes through the tree.  the first with summary_first == 1
     * the second with summary_first == 2.  if the option is not
     * in effect, there will be one pass with summary_first == 0
     *
     * When the -s option is in effect, the show_patch_set_ranges
     * list will be non-empty.
     */
    if (summary_first <= 1)
	print_patch_set(ps);
    if (do_diff && summary_first != 1)
	do_cvs_diff(ps);

    fflush(stdout);
}

static void print_patch_set(PatchSet * ps)
{
    struct tm *tm;
    struct list_head * next;
    const char * funk = "";

    tm = localtime(&ps->date);
    next = ps->members.next;
    
    funk = fnk_descr[ps->funk_factor];
    
    /* this '---...' is different from the 28 hyphens that separate cvs log output */
    printf("---------------------\n");
    printf("PatchSet %d %s\n", ps->psid, funk);
    printf("Date: %d/%02d/%02d %02d:%02d:%02d\n", 
	   1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday, 
	   tm->tm_hour, tm->tm_min, tm->tm_sec);
    printf("Author: %s\n", ps->author);
    printf("Branch: %s\n", ps->branch);
    if (ps->ancestor_branch)
	printf("Ancestor branch: %s\n", ps->ancestor_branch);
    printf("Tag: %s %s\n", ps->tag ? ps->tag : "(none)", tag_flag_descr[ps->tag_flags]);
    printf("Log:\n%s\n", ps->descr);
    printf("Members: \n");

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	if (ps->funk_factor == FNK_SHOW_SOME && psm->bad_funk)
	    funk = "(BEFORE START TAG)";
	else if (ps->funk_factor == FNK_HIDE_SOME && !psm->bad_funk)
	    funk = "(AFTER END TAG)";
	else
	    funk = "";

	printf("\t%s:%s->%s%s %s\n", 
	       psm->file->filename, 
	       psm->pre_rev ? psm->pre_rev->rev : "INITIAL", 
	       psm->post_rev->rev, 
	       psm->post_rev->dead ? "(DEAD)": "",
	       funk);

	next = next->next;
    }
    
    printf("\n");
}

/* walk all the patchsets to assign monotonic psid, 
 * and to establish  branch ancestry
 */
static void assign_patchset_id(PatchSet * ps)
{
    /*
     * Ignore the 'BRANCH ADD' patchsets 
     */
    if (!ps->branch_add)
    {
	ps_counter++;
	ps->psid = ps_counter;
	
	if (track_branch_ancestry && strcmp(ps->branch, "HEAD") != 0)
	{
	    PatchSet * head_ps = (PatchSet*)get_hash_object(branch_heads, ps->branch);
	    if (!head_ps) 
	    {
		head_ps = ps;
		put_hash_object(branch_heads, ps->branch, head_ps);
	    }
	    
	    determine_branch_ancestor(ps, head_ps);
	}
    }
    else
    {
	ps->psid = -1;
    }
}

static int compare_rev_strings(const char * cr1, const char * cr2)
{
    char r1[REV_STR_MAX];
    char r2[REV_STR_MAX];
    char *s1 = r1, *s2 = r2;
    char *p1, *p2;
    int n1, n2;

    strcpy(s1, cr1);
    strcpy(s2, cr2);

    for (;;) 
    {
	p1 = strchr(s1, '.');
	p2 = strchr(s2, '.');

	if (p1) *p1++ = 0;
	if (p2) *p2++ = 0;
	
	n1 = atoi(s1);
	n2 = atoi(s2);
	
	if (n1 < n2)
	    return -1;
	if (n1 > n2)
	    return 1;

	if (!p1 && p2)
	    return -1;
	if (p1 && !p2)
	    return 1;
	if (!p1 && !p2)
	    return 0;

	s1 = p1;
	s2 = p2;
    }
}

static int compare_patch_sets_by_members(const PatchSet * ps1, const PatchSet * ps2)
{
    struct list_head * i;

    for (i = ps1->members.next; i != &ps1->members; i = i->next)
    {
	PatchSetMember * psm1 = list_entry(i, PatchSetMember, link);
	struct list_head * j;

	for (j = ps2->members.next; j != &ps2->members; j = j->next)
	{
	    PatchSetMember * psm2 = list_entry(j, PatchSetMember, link);
	    if (psm1->file == psm2->file) 
	    {
		int ret = compare_rev_strings(psm1->post_rev->rev, psm2->post_rev->rev);
		//debug(DEBUG_APPMSG1, "file: %s comparing %s %s = %d", psm1->file->filename, psm1->post_rev->rev, psm2->post_rev->rev, ret);
		return ret;
	    }
	}
    }
    
    return 0;
}

static int compare_patch_sets_bk(const void * v_ps1, const void * v_ps2)
{
    const PatchSet * ps1 = (const PatchSet *)v_ps1;
    const PatchSet * ps2 = (const PatchSet *)v_ps2;
    long diff;

    diff = ps1->date - ps2->date;

    return (diff < 0) ? -1 : ((diff > 0) ? 1 : 0);
}

static int compare_patch_sets(const void * v_ps1, const void * v_ps2)
{
    const PatchSet * ps1 = (const PatchSet *)v_ps1;
    const PatchSet * ps2 = (const PatchSet *)v_ps2;
    long diff;
    int ret;
    time_t d, min, max;

    /* We order by (author, descr, branch, members, date), but because of the fuzz factor
     * we treat times within a certain distance as equal IFF the author
     * and descr match.
     */

    ret = strcmp(ps1->author, ps2->author);
    if (ret)
	    return ret;

    ret = strcmp(ps1->descr, ps2->descr);
    if (ret)
	    return ret;

    ret = strcmp(ps1->branch, ps2->branch);
    if (ret)
	return ret;

    ret = compare_patch_sets_by_members(ps1, ps2);
    if (ret)
	return ret;

    /* 
     * one of ps1 or ps2 is new.  the other should have the min_date
     * and max_date set to a window opened by the fuzz_factor
     */
    if (ps1->min_date == 0)
    {
	d = ps1->date;
	min = ps2->min_date;
	max = ps2->max_date;
    } 
    else if (ps2->min_date == 0)
    {
	d = ps2->date;
	min = ps1->min_date;
	max = ps1->max_date;
    }
    else
    {
	debug(DEBUG_APPERROR, "how can we have both patchsets pre-existing?");
	exit(1);
    }

    if (min < d && d < max)
	return 0;

    diff = ps1->date - ps2->date;

    return (diff < 0) ? -1 : 1;
}

static int compare_patch_sets_bytime_list(struct list_head * l1, struct list_head * l2)
{
    const PatchSet *ps1 = list_entry(l1, PatchSet, all_link);
    const PatchSet *ps2 = list_entry(l2, PatchSet, all_link);
    return compare_patch_sets_bytime(ps1, ps2);
}

static int compare_patch_sets_bytime(const PatchSet * ps1, const PatchSet * ps2)
{
    long diff;
    int ret;

    /* When doing a time-ordering of patchsets, we don't need to
     * fuzzy-match the time.  We've already done fuzzy-matching so we
     * know that insertions are unique at this point.
     */

    diff = ps1->date - ps2->date;
    if (diff)
	return (diff < 0) ? -1 : 1;

    ret = compare_patch_sets_by_members(ps1, ps2);
    if (ret)
	return ret;

    ret = strcmp(ps1->author, ps2->author);
    if (ret)
	return ret;

    ret = strcmp(ps1->descr, ps2->descr);
    if (ret)
	return ret;

    ret = strcmp(ps1->branch, ps2->branch);
    return ret;
}


static int is_revision_metadata(const char * buff)
{
    char * p1, *p2;
    int len;

    if (!(p1 = strchr(buff, ':')))
	return 0;

    p2 = strchr(buff, ' ');
    
    if (p2 && p2 < p1)
	return 0;

    len = strlen(buff);

    /* lines have LF at end */
    if (len > 1 && buff[len - 2] == ';')
	return 1;

    return 0;
}

static int patch_set_member_regex(PatchSet * ps, regex_t * reg)
{
    struct list_head * next = ps->members.next;

    while (next != &ps->members)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	
	if (regexec(&restrict_file, psm->file->filename, 0, NULL, 0) == 0)
	    return 1;

	next = next->next;
    }

    return 0;
}

static int patch_set_affects_branch(PatchSet * ps, const char * branch)
{
    struct list_head * next;

    for (next = ps->members.next; next != &ps->members; next = next->next)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);

	/*
	 * slight hack. if -r is specified, and this patchset
	 * is 'before' the tag, but is FNK_SHOW_SOME, only
	 * check if the 'after tag' revisions affect
	 * the branch.  this is especially important when
	 * the tag is a branch point.
	 */
	if (ps->funk_factor == FNK_SHOW_SOME && psm->bad_funk)
	    continue;

	if (revision_affects_branch(psm->post_rev, branch))
	    return 1;
    }

    return 0;
}

static void do_cvs_diff(PatchSet * ps)
{
    struct list_head * next;
    const char * dtype;
    const char * dopts;
    const char * utype;
    char use_rep_path[PATH_MAX];
    char esc_use_rep_path[PATH_MAX];

    fflush(stdout);
    fflush(stderr);

    /* 
     * if cvs_direct is not in effect, and diff options are specified,
     * then we have to use diff instead of rdiff and we'll get a -p0 
     * diff (instead of -p1) [in a manner of speaking].  So to make sure
     * that the add/remove diffs get generated likewise, we need to use
     * 'update' instead of 'co' 
     *
     * cvs_direct will always use diff (not rdiff), but will also always
     * generate -p1 diffs.
     */
    if (diff_opts == NULL) 
    {
	dopts = "-u";
	dtype = "rdiff";
	utype = "co";
	sprintf(use_rep_path, "%s/", repository_path);
	/* the rep_path may contain characters that the shell will barf on */
	escape_filename(esc_use_rep_path, PATH_MAX, use_rep_path);
    }
    else
    {
	dopts = diff_opts;
	dtype = "diff";
	utype = "update";
	use_rep_path[0] = 0;
	esc_use_rep_path[0] = 0;
    }

    for (next = ps->members.next; next != &ps->members; next = next->next)
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	char cmdbuff[PATH_MAX * 2+1];
	char esc_file[PATH_MAX];
	int ret, check_ret = 0;

	cmdbuff[0] = 0;
	cmdbuff[PATH_MAX*2] = 0;

	/* the filename may contain characters that the shell will barf on */
	escape_filename(esc_file, PATH_MAX, psm->file->filename);

	/*
	 * Check the patchset funk. we may not want to diff this particular file 
	 */
	if (ps->funk_factor == FNK_SHOW_SOME && psm->bad_funk)
	{
	    printf("Index: %s\n", psm->file->filename);
	    printf("===================================================================\n");
	    printf("*** Member not diffed, before start tag\n");
	    continue;
	}
	else if (ps->funk_factor == FNK_HIDE_SOME && !psm->bad_funk)
	{
	    printf("Index: %s\n", psm->file->filename);
	    printf("===================================================================\n");
	    printf("*** Member not diffed, after end tag\n");
	    continue;
	}

	/* 
	 * When creating diffs for INITIAL or DEAD revisions, we have to use 'cvs co'
	 * or 'cvs update' to get the file, because cvs won't generate these diffs.
	 * The problem is that this must be piped to diff, and so the resulting
	 * diff doesn't contain the filename anywhere! (diff between - and /dev/null).
	 * sed is used to replace the '-' with the filename. 
	 *
	 * It's possible for pre_rev to be a 'dead' revision. This happens when a file 
	 * is added on a branch. post_rev will be dead dead for remove
	 */
	if (!psm->pre_rev || psm->pre_rev->dead || psm->post_rev->dead)
	{
	    int cr;
	    const char * rev;

	    if (!psm->pre_rev || psm->pre_rev->dead)
	    {
		cr = 1;
		rev = psm->post_rev->rev;
	    }
	    else
	    {
		cr = 0;
		rev = psm->pre_rev->rev;
	    }

	    if (cvs_direct_ctx)
	    {
		/* cvs_rupdate does the pipe through diff thing internally */
		cvs_rupdate(cvs_direct_ctx, repository_path, psm->file->filename, rev, cr, dopts);
	    }
	    else
	    {
		snprintf(cmdbuff, PATH_MAX * 2, "cvs %s %s %s -p -r %s %s%s | diff %s %s /dev/null %s | sed -e '%s s|^\\([+-][+-][+-]\\) -|\\1 %s%s|g'",
			 compress_arg, norc, utype, rev, esc_use_rep_path, esc_file, dopts,
			 cr?"":"-",cr?"-":"", cr?"2":"1",
			 use_rep_path, psm->file->filename);
	    }
	}
	else
	{
	    /* a regular diff */
	    if (cvs_direct_ctx)
	    {
		cvs_diff(cvs_direct_ctx, repository_path, psm->file->filename, psm->pre_rev->rev, psm->post_rev->rev, dopts);
	    }
	    else
	    {
		/* 'cvs diff' exit status '1' is ok, just means files are different */
		if (strcmp(dtype, "diff") == 0)
		    check_ret = 1;

		snprintf(cmdbuff, PATH_MAX * 2, "cvs %s %s %s %s -r %s -r %s %s%s",
			 compress_arg, norc, dtype, dopts, psm->pre_rev->rev, psm->post_rev->rev, 
			 esc_use_rep_path, esc_file);
	    }
	}

	/*
	 * my_system doesn't block signals the way system does.
	 * if ctrl-c is pressed while in there, we probably exit
	 * immediately and hope the shell has sent the signal
	 * to all of the process group members
	 */
	if (cmdbuff[0] && (ret = my_system(cmdbuff)))
	{
	    int stat = WEXITSTATUS(ret);
	    
	    /* 
	     * cvs diff returns 1 in exit status for 'files are different'
	     * so use a better method to check for failure
	     */
	    if (stat < 0 || stat > check_ret || WIFSIGNALED(ret))
	    {
		debug(DEBUG_APPERROR, "system command returned non-zero exit status: %d: aborting", stat);
		exit(1);
	    }
	}
    }
}

static CvsFileRevision * parse_revision(CvsFile * file, char * rev_str)
{
    char * p;

    /* The "revision" log line can include extra information 
     * including who is locking the file --- strip that out.
     */
    
    p = rev_str;
    while (isdigit(*p) || *p == '.')
	    p++;
    *p = 0;

    return cvs_file_add_revision(file, rev_str);
}

CvsFileRevision * cvs_file_add_revision(CvsFile * file, const char * rev_str)
{
    CvsFileRevision * rev;

    if (!(rev = (CvsFileRevision*)get_hash_object(file->revisions, rev_str)))
    {
	rev = (CvsFileRevision*)calloc(1, sizeof(*rev));
	rev->rev = get_string(rev_str);
	rev->file = file;
	rev->branch = NULL;
	rev->present = 0;
	rev->pre_psm = NULL;
	rev->post_psm = NULL;
	INIT_LIST_HEAD(&rev->branch_children);
	INIT_LIST_HEAD(&rev->tags);
	
	put_hash_object_ex(file->revisions, rev->rev, rev, HT_NO_KEYCOPY, NULL, NULL);

	debug(DEBUG_STATUS, "added revision %s to file %s", rev_str, file->filename);
    }
    else
    {
	debug(DEBUG_STATUS, "found revision %s to file %s", rev_str, file->filename);
    }

    /* 
     * note: we are guaranteed to get here at least once with 'have_branches' == 1.
     * we may pass through once before this, because of symbolic tags, then once
     * always when processing the actual revision logs
     *
     * rev->branch will always be set to something, maybe "HEAD"
     */
    if (!rev->branch && file->have_branches)
    {
	char branch_str[REV_STR_MAX];

	/* in the cvs cvs repository (ccvs) there are tagged versions
	 * that don't exist.  let's mark every 'known to exist' 
	 * version
	 */
	rev->present = 1;

	/* determine the branch this revision was committed on */
	if (!get_branch(branch_str, rev->rev))
	{
	    debug(DEBUG_APPERROR, "invalid rev format %s", rev->rev);
	    exit(1);
	}
	
	rev->branch = (char*)get_hash_object(file->branches, branch_str);
	
	/* if there's no branch and it's not on the trunk, blab */
	if (!rev->branch)
	{
	    if (get_branch(branch_str, branch_str))
	    {
		debug(DEBUG_APPMSG1, "WARNING: revision %s of file %s on unnamed branch", rev->rev, rev->file->filename);
		rev->branch = "#CVSPS_NO_BRANCH";
	    }
	    else
	    {
		rev->branch = "HEAD";
	    }
	}

	debug(DEBUG_STATUS, "revision %s of file %s on branch %s", rev->rev, rev->file->filename, rev->branch);
    }

    return rev;
}

CvsFile * create_cvsfile()
{
    CvsFile * f = (CvsFile*)calloc(1, sizeof(*f));
    if (!f)
	return NULL;

    f->revisions = create_hash_table(53);
    f->branches = create_hash_table(13);
    f->branches_sym = create_hash_table(13);
    f->symbols = create_hash_table(253);
    f->have_branches = 0;

    if (!f->revisions || !f->branches || !f->branches_sym)
    {
	if (f->branches)
	    destroy_hash_table(f->branches, NULL);
	if (f->revisions)
	    destroy_hash_table(f->revisions, NULL);
	free(f);
	return NULL;
    }
   
    return f;
}

static PatchSet * create_patch_set()
{
    PatchSet * ps = (PatchSet*)calloc(1, sizeof(*ps));;
    
    if (ps)
    {
	INIT_LIST_HEAD(&ps->members);
	ps->psid = -1;
	ps->date = 0;
	ps->min_date = 0;
	ps->max_date = 0;
	ps->descr = NULL;
	ps->author = NULL;
	ps->tag = NULL;
	ps->tag_flags = 0;
	ps->branch_add = 0;
	ps->funk_factor = 0;
	ps->ancestor_branch = NULL;
	CLEAR_LIST_NODE(&ps->collision_link);
    }

    return ps;
}

PatchSetMember * create_patch_set_member()
{
    PatchSetMember * psm = (PatchSetMember*)calloc(1, sizeof(*psm));
    psm->pre_rev = NULL;
    psm->post_rev = NULL;
    psm->ps = NULL;
    psm->file = NULL;
    psm->bad_funk = 0;
    return psm;
}

static PatchSetRange * create_patch_set_range()
{
    PatchSetRange * psr = (PatchSetRange*)calloc(1, sizeof(*psr));
    return psr;
}

CvsFileRevision * file_get_revision(CvsFile * file, const char * r)
{
    CvsFileRevision * rev;

    if (strcmp(r, "INITIAL") == 0)
	return NULL;

    rev = (CvsFileRevision*)get_hash_object(file->revisions, r);
    
    if (!rev)
    {
	debug(DEBUG_APPERROR, "request for non-existent rev %s in file %s", r, file->filename);
	exit(1);
    }

    return rev;
}

/*
 * Parse lines in the format:
 * 
 * <white space>tag_name: <rev>;
 *
 * Handles both regular tags (these go into the symbols hash)
 * and magic-branch-tags (second to last node of revision is 0)
 * which go into branches and branches_sym hashes.  Magic-branch
 * format is hidden in CVS everwhere except the 'cvs log' output.
 */

static void parse_sym(CvsFile * file, char * sym)
{
    char * tag = sym, *eot;
    int leaf, final_branch = -1;
    char rev[REV_STR_MAX];
    char rev2[REV_STR_MAX];
    
    while (*tag && isspace(*tag))
	tag++;

    if (!*tag)
	return;

    eot = strchr(tag, ':');
    
    if (!eot)
	return;

    *eot = 0;
    eot += 2;
    
    if (!get_branch_ext(rev, eot, &leaf))
    {
	if (strcmp(tag, "TRUNK") == 0)
	{
	    debug(DEBUG_STATUS, "ignoring the TRUNK branch/tag");
	    return;
	}
	debug(DEBUG_APPERROR, "malformed revision");
	exit(1);
    }

    /* 
     * get_branch_ext will leave final_branch alone
     * if there aren't enough '.' in string 
     */
    get_branch_ext(rev2, rev, &final_branch);

    if (final_branch == 0)
    {
	snprintf(rev, REV_STR_MAX, "%s.%d", rev2, leaf);
	debug(DEBUG_STATUS, "got sym: %s for %s", tag, rev);
	
	cvs_file_add_branch(file, rev, tag);
    }
    else
    {
	strcpy(rev, eot);
	chop(rev);

	/* see cvs manual: what is this vendor tag? */
	if (is_vendor_branch(rev))
	    cvs_file_add_branch(file, rev, tag);
	else
	    cvs_file_add_symbol(file, rev, tag);
    }
}

void cvs_file_add_symbol(CvsFile * file, const char * rev_str, const char * p_tag_str)
{
    CvsFileRevision * rev;
    GlobalSymbol * sym;
    Tag * tag;

    /* get a permanent storage string */
    char * tag_str = get_string(p_tag_str);

    debug(DEBUG_STATUS, "adding symbol to file: %s %s->%s", file->filename, tag_str, rev_str);
    rev = cvs_file_add_revision(file, rev_str);
    put_hash_object_ex(file->symbols, tag_str, rev, HT_NO_KEYCOPY, NULL, NULL);
    
    /*
     * check the global_symbols
     */
    sym = (GlobalSymbol*)get_hash_object(global_symbols, tag_str);
    if (!sym)
    {
	sym = (GlobalSymbol*)malloc(sizeof(*sym));
	sym->tag = tag_str;
	sym->ps = NULL;
	INIT_LIST_HEAD(&sym->tags);

	put_hash_object_ex(global_symbols, sym->tag, sym, HT_NO_KEYCOPY, NULL, NULL);
    }

    tag = (Tag*)malloc(sizeof(*tag));
    tag->tag = tag_str;
    tag->rev = rev;
    tag->sym = sym;
    list_add(&tag->global_link, &sym->tags);
    list_add(&tag->rev_link, &rev->tags);
}

char * cvs_file_add_branch(CvsFile * file, const char * rev, const char * tag)
{
    char * new_tag;
    char * new_rev;

    if (get_hash_object(file->branches, rev))
    {
	debug(DEBUG_STATUS, "attempt to add existing branch %s:%s to %s", 
	      rev, tag, file->filename);
	return NULL;
    }

    /* get permanent storage for the strings */
    new_tag = get_string(tag);
    new_rev = get_string(rev); 

    put_hash_object_ex(file->branches, new_rev, new_tag, HT_NO_KEYCOPY, NULL, NULL);
    put_hash_object_ex(file->branches_sym, new_tag, new_rev, HT_NO_KEYCOPY, NULL, NULL);
    
    return new_tag;
}

/*
 * Resolve each global symbol to a PatchSet.  This is
 * not necessarily doable, because tagging isn't 
 * necessarily done to the project as a whole, and
 * it's possible that no tag is valid for all files 
 * at a single point in time.  We check for that
 * case though.
 *
 * Implementation: the most recent PatchSet containing
 * a revision (post_rev) tagged by the symbol is considered
 * the 'tagged' PatchSet.
 */

static void resolve_global_symbols()
{
    struct hash_entry * he_sym;
    reset_hash_iterator(global_symbols);
    while ((he_sym = next_hash_entry(global_symbols)))
    {
	GlobalSymbol * sym = (GlobalSymbol*)he_sym->he_obj;
	PatchSet * ps;
	struct list_head * next;

	debug(DEBUG_STATUS, "resolving global symbol %s", sym->tag);

	/*
	 * First pass, determine the most recent PatchSet with a 
	 * revision tagged with the symbolic tag.  This is 'the'
	 * patchset with the tag
	 */

	for (next = sym->tags.next; next != &sym->tags; next = next->next)
	{
	    Tag * tag = list_entry(next, Tag, global_link);
	    CvsFileRevision * rev = tag->rev;

	    /* FIXME:test for rev->post_psm from DEBIAN. not sure how this could happen */
	    if (!rev->present || !rev->post_psm)
	    {
		struct list_head *tmp = next->prev;
		debug(DEBUG_APPERROR, "revision %s of file %s is tagged but not present",
		      rev->rev, rev->file->filename);
		/* FIXME: memleak */
		list_del(next);
		next = tmp;
		continue;
	    }

	    ps = rev->post_psm->ps;

	    if (!sym->ps || ps->date > sym->ps->date)
		sym->ps = ps;
	}
	
	/* convenience variable */
	ps = sym->ps;

	if (!ps)
	{
	    debug(DEBUG_APPERROR, "no patchset for tag %s", sym->tag);
	    return;
	}

	ps->tag = sym->tag;

	/* check if this ps is one of the '-r' patchsets */
	if (restrict_tag_start && strcmp(restrict_tag_start, ps->tag) == 0)
	    restrict_tag_ps_start = ps->psid;

	/* the second -r implies -b */
	if (restrict_tag_end && strcmp(restrict_tag_end, ps->tag) == 0)
	{
	    restrict_tag_ps_end = ps->psid;

	    if (restrict_branch)
	    {
		if (strcmp(ps->branch, restrict_branch) != 0)
		{
		    debug(DEBUG_APPMSG1, 
			  "WARNING: -b option and second -r have conflicting branches: %s %s", 
			  restrict_branch, ps->branch);
		}
	    }
	    else
	    {
		debug(DEBUG_APPMSG1, "NOTICE: implicit branch restriction set to %s", ps->branch);
		restrict_branch = ps->branch;
	    }
	}

	/* 
	 * Second pass. 
	 * check if this is an invalid patchset, 
	 * check which members are invalid.  determine
	 * the funk factor etc.
	 */
	for (next = sym->tags.next; next != &sym->tags; next = next->next)
	{
	    Tag * tag = list_entry(next, Tag, global_link);
	    CvsFileRevision * rev = tag->rev;
	    CvsFileRevision * next_rev = rev_follow_branch(rev, ps->branch);
	    
	    if (!next_rev)
		continue;
		
	    /*
	     * we want the 'tagged revision' to be valid until after
	     * the date of the 'tagged patchset' or else there's something
	     * funky going on
	     */
	    if (next_rev->post_psm->ps->date < ps->date)
	    {
		int flag = check_rev_funk(ps, next_rev);
		debug(DEBUG_STATUS, "file %s revision %s tag %s: TAG VIOLATION %s",
		      rev->file->filename, rev->rev, sym->tag, tag_flag_descr[flag]);
		ps->tag_flags |= flag;
	    }
	}
    }
}

static int revision_affects_branch(CvsFileRevision * rev, const char * branch)
{
    /* special case the branch called 'HEAD' */
    if (strcmp(branch, "HEAD") == 0)
    {
	/* look for only one '.' in rev */
	char * p = strchr(rev->rev, '.');
	if (p && !strchr(p + 1, '.'))
	    return 1;
    }
    else
    {
	char * branch_rev = (char*)get_hash_object(rev->file->branches_sym, branch);
	
	if (branch_rev)
	{
	    char post_rev[REV_STR_MAX];
	    char branch[REV_STR_MAX];
	    int file_leaf, branch_leaf;
	    
	    strcpy(branch, branch_rev);
	    
	    /* first get the branch the file rev is on */
	    if (get_branch_ext(post_rev, rev->rev, &file_leaf))
	    {
		branch_leaf = file_leaf;
		
		/* check against branch and all branch ancestor branches */
		do 
		{
		    debug(DEBUG_STATUS, "check %s against %s for %s", branch, post_rev, rev->file->filename);
		    if (strcmp(branch, post_rev) == 0)
			return (file_leaf <= branch_leaf);
		}
		while(get_branch_ext(branch, branch, &branch_leaf));
	    }
	}
    }

    return 0;
}

static int count_dots(const char * p)
{
    int dots = 0;

    while (*p)
	if (*p++ == '.')
	    dots++;

    return dots;
}

/*
 * When importing vendor sources, (apparently people do this)
 * the code is added on a 'vendor' branch, which, for some reason
 * doesn't use the magic-branch-tag format.  Try to detect that now
 */
static int is_vendor_branch(const char * rev)
{
    return !(count_dots(rev)&1);
}

void patch_set_add_member(PatchSet * ps, PatchSetMember * psm)
{
    /* check if a member for the same file already exists, if so
     * put this PatchSet on the collisions list 
     */
    struct list_head * next;
    for (next = ps->members.next; next != &ps->members; next = next->next) 
    {
	PatchSetMember * m = list_entry(next, PatchSetMember, link);
	if (m->file == psm->file) {
		int order = compare_rev_strings(psm->post_rev->rev, m->post_rev->rev);

		/*
		 * Same revision too? Add it to the collision list
		 * if it isn't already.
		 */
		if (!order) {
			if (ps->collision_link.next == NULL)
				list_add(&ps->collision_link, &collisions);
			return;
		}

		/*
		 * If this is an older revision than the one we already have
		 * in this patchset, just ignore it
		 */
		if (order < 0)
			return;

		/*
		 * This is a newer one, remove the old one
		 */
		list_del(&m->link);
	}
    }

    psm->ps = ps;
    list_add(&psm->link, ps->members.prev);
}

static void set_psm_initial(PatchSetMember * psm)
{
    psm->pre_rev = NULL;
    if (psm->post_rev->dead)
    {
	/* 
	 * we expect a 'file xyz initially added on branch abc' here
	 * but there can only be one such member in a given patchset
	 */
	if (psm->ps->branch_add)
	    debug(DEBUG_APPMSG1, "WARNING: branch_add already set!");
	psm->ps->branch_add = 1;
    }
}

/* 
 * look at all revisions starting at rev and going forward until 
 * ps->date and see whether they are invalid or just funky.
 */
static int check_rev_funk(PatchSet * ps, CvsFileRevision * rev)
{
    int retval = TAG_FUNKY;

    while (rev)
    {
	PatchSet * next_ps = rev->post_psm->ps;
	struct list_head * next;

	if (next_ps->date > ps->date)
	    break;

	debug(DEBUG_STATUS, "ps->date %d next_ps->date %d rev->rev %s rev->branch %s", 
	      ps->date, next_ps->date, rev->rev, rev->branch);

	/*
	 * If the ps->tag is one of the two possible '-r' tags
	 * then the funkyness is even more important.
	 *
	 * In the restrict_tag_start case, this next_ps is chronologically
	 * before ps, but tagwise after, so set the funk_factor so it will
	 * be included.
	 *
	 * The restrict_tag_end case is similar, but backwards.
	 *
	 * Start assuming the HIDE/SHOW_ALL case, we will determine
	 * below if we have a split ps case 
	 */
	if (restrict_tag_start && strcmp(ps->tag, restrict_tag_start) == 0)
	    next_ps->funk_factor = FNK_SHOW_ALL;
	if (restrict_tag_end && strcmp(ps->tag, restrict_tag_end) == 0)
	    next_ps->funk_factor = FNK_HIDE_ALL;

	/*
	 * if all of the other members of this patchset are also 'after' the tag
	 * then this is a 'funky' patchset w.r.t. the tag.  however, if some are
	 * before then the patchset is 'invalid' w.r.t. the tag, and we mark
	 * the members individually with 'bad_funk' ,if this tag is the
	 * '-r' tag.  Then we can actually split the diff on this patchset
	 */
	for (next = next_ps->members.next; next != &next_ps->members; next = next->next)
	{
	    PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	    if (before_tag(psm->post_rev, ps->tag))
	    {
		retval = TAG_INVALID;
		/* only set bad_funk for one of the -r tags */
		if (next_ps->funk_factor)
		{
		    psm->bad_funk = 1;
		    next_ps->funk_factor = 
			(next_ps->funk_factor == FNK_SHOW_ALL) ? FNK_SHOW_SOME : FNK_HIDE_SOME;
		}
		debug(DEBUG_APPMSG1, 
		      "WARNING: Invalid PatchSet %d, Tag %s:\n"
		      "    %s:%s=after, %s:%s=before. Treated as 'before'", 
		      next_ps->psid, ps->tag, 
		      rev->file->filename, rev->rev, 
		      psm->post_rev->file->filename, psm->post_rev->rev);
	    }
	}

	rev = rev_follow_branch(rev, ps->branch);
    }

    return retval;
}

/* determine if the revision is before the tag */
static int before_tag(CvsFileRevision * rev, const char * tag)
{
    CvsFileRevision * tagged_rev = (CvsFileRevision*)get_hash_object(rev->file->symbols, tag);
    int retval = 0;

    if (tagged_rev && tagged_rev->branch == NULL)
        debug(DEBUG_APPMSG1, "WARNING: Branch == NULL for: %s %s %s %s %d",
    	  rev->file->filename, tag, rev->rev, tagged_rev ? tagged_rev->rev : "N/A", retval);

    if (tagged_rev && tagged_rev->branch &&
	revision_affects_branch(rev, tagged_rev->branch) && 
	rev->post_psm->ps->date <= tagged_rev->post_psm->ps->date)
	retval = 1;

    debug(DEBUG_STATUS, "before_tag: %s %s %s %s %d", 
	  rev->file->filename, tag, rev->rev, tagged_rev ? tagged_rev->rev : "N/A", retval);

    return retval;
}

/* get the next revision from this one following branch if possible */
/* FIXME: not sure if this needs to follow branches leading up to branches? */
static CvsFileRevision * rev_follow_branch(CvsFileRevision * rev, const char * branch)
{
    struct list_head * next;

    /* check for 'main line of inheritance' */
    if (strcmp(rev->branch, branch) == 0)
	return rev->pre_psm ? rev->pre_psm->post_rev : NULL;

    /* look down branches */
    for (next = rev->branch_children.next; next != &rev->branch_children; next = next->next)
    {
	CvsFileRevision * next_rev = list_entry(next, CvsFileRevision, link);
	//debug(DEBUG_STATUS, "SCANNING BRANCH CHILDREN: %s %s", next_rev->branch, branch);
	if (strcmp(next_rev->branch, branch) == 0)
	    return next_rev;
    }
    
    return NULL;
}

static void check_norc(int argc, char * argv[])
{
    int i = 1; 
    while (i < argc)
    {
	if (strcmp(argv[i], "--norc") == 0)
	{
	    norc = "-f";
	    break;
	}
	i++;
    }
}

static void determine_branch_ancestor(PatchSet * ps, PatchSet * head_ps)
{
    struct list_head * next;
    CvsFileRevision * rev;

    /* PatchSet 1 has no ancestor */
    if (ps->psid == 1)
	return;

    /* HEAD branch patchsets have no ancestry, but callers should know that */
    if (strcmp(ps->branch, "HEAD") == 0)
    {
	debug(DEBUG_APPMSG1, "WARNING: no branch ancestry for HEAD");
	return;
    }

    for (next = ps->members.next; next != &ps->members; next = next->next) 
    {
	PatchSetMember * psm = list_entry(next, PatchSetMember, link);
	rev = psm->pre_rev;
	int d1, d2;

	/* the reason this is at all complicated has to do with a 
	 * branch off of a branch.  it is possible (and indeed 
	 * likely) that some file would not have been modified 
	 * from the initial branch point to the branch-off-branch 
	 * point, and therefore the branch-off-branch point is 
	 * really branch-off-HEAD for that specific member (file).  
	 * in that case, rev->branch will say HEAD but we want 
	 * to know the symbolic name of the first branch
	 * so we continue to look member after member until we find
	 * the 'deepest' branching.  deepest can actually be determined
	 * by considering the revision currently indicated by 
	 * ps->ancestor_branch (by symbolic lookup) and rev->rev. the 
	 * one with more dots wins
	 *
	 * also, the first commit in which a branch-off-branch is 
	 * mentioned may ONLY modify files never committed since
	 * original branch-off-HEAD was created, so we have to keep
	 * checking, ps after ps to be sure to get the deepest ancestor
	 *
	 * note: rev is the pre-commit revision, not the post-commit
	 */
	if (!head_ps->ancestor_branch)
	    d1 = -1;
	else if (strcmp(ps->branch, rev->branch) == 0)
	    continue;
	else if (strcmp(head_ps->ancestor_branch, "HEAD") == 0)
	    d1 = 1;
	else {
	    /* branch_rev may not exist if the file was added on this branch for example */
	    const char * branch_rev = (char *)get_hash_object(rev->file->branches_sym, head_ps->ancestor_branch);
	    d1 = branch_rev ? count_dots(branch_rev) : 1;
	}
	
	/* HACK: we sometimes pretend to derive from the import branch.  
	 * just don't do that.  this is the easiest way to prevent... 
	 */
	d2 = (strcmp(rev->rev, "1.1.1.1") == 0) ? 0 : count_dots(rev->rev);
	
	if (d2 > d1)
	    head_ps->ancestor_branch = rev->branch;

 	//printf("-----> %d ancestry %s %s %s\n", ps->psid, ps->branch, head_ps->ancestor_branch, rev->file->filename);
    }
}

static void handle_collisions()
{
    struct list_head *next;
    for (next = collisions.next; next != &collisions; next = next->next) 
    {
	PatchSet * ps = list_entry(next, PatchSet, collision_link);
	printf("PatchSet %d has collisions\n", ps->psid);
    }
}

void walk_all_patch_sets(void (*action)(PatchSet *))
{
    struct list_head * next;;
    for (next = all_patch_sets.next; next != &all_patch_sets; next = next->next) {
	PatchSet * ps = list_entry(next, PatchSet, all_link);
	action(ps);
    }
}
