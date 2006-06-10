/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cbtcommon/debug.h>
#include <cbtcommon/text_util.h>

#include "cap.h"
#include "cvs_direct.h"

extern CvsServerCtx * cvs_direct_ctx;

static char client_version[BUFSIZ];
static char server_version[BUFSIZ];

static int check_cvs_version(int, int, int);
static int check_version_string(const char *, int, int, int);

int cvs_check_cap(int cap)
{
    int ret;

    switch(cap)
    {
    case CAP_HAVE_RLOG:
	if (!(ret = check_cvs_version(1,11,1)))
	{
	    debug(DEBUG_APPERROR, 
		  "WARNING: Your CVS client version:\n[%s]\n"
		  "and/or server version:\n[%s]\n"
		  "are too old to properly support the rlog command. \n"
		  "This command was introduced in 1.11.1.  Cvsps\n"
		  "will use log instead, but PatchSet numbering\n"
		  "may become unstable due to pruned empty\n"
		  "directories.\n", client_version, server_version);
	}
	break;
		  
    default:
	debug(DEBUG_APPERROR, "unknown cvs capability check %d", cap);
	exit(1);
    }

    return ret;
}

static void get_version_external()
{
    FILE * cvsfp;
    
    strcpy(client_version, "(UNKNOWN CLIENT)");
    strcpy(server_version, "(UNKNOWN SERVER)");

    if (!(cvsfp = popen("cvs version 2>/dev/null", "r")))
    {
	debug(DEBUG_APPERROR, "cannot popen cvs version. exiting");
	exit(1);
    }
    
    if (!fgets(client_version, BUFSIZ, cvsfp))
    {
	debug(DEBUG_APPMSG1, "WARNING: malformed CVS version: no data");
	goto out;
    }
    
    chop(client_version);
    
    if (strncmp(client_version, "Client", 6) == 0)
    {
	if (!fgets(server_version, BUFSIZ, cvsfp))
	{
	    debug(DEBUG_APPMSG1, "WARNING: malformed CVS version: no server data");
	    goto out;
	}
	chop(server_version);
    }
    else
    {
	server_version[0] = 0;
    }
    
 out:
    pclose(cvsfp);
}

int check_cvs_version(int req_major, int req_minor, int req_extra)
{
    if (!client_version[0])
    {
	if (cvs_direct_ctx)
	    cvs_version(cvs_direct_ctx, client_version, server_version);
	else
	    get_version_external();
    }

    return (check_version_string(client_version, req_major, req_minor, req_extra) &&
	    (!server_version[0] || check_version_string(server_version, req_major, req_minor, req_extra)));
}

int check_version_string(const char * str, int req_major, int req_minor, int req_extra)
{
    char * p;
    int major, minor, extra;
    int skip = 6;

    p = strstr(str, "(CVS) ");

    if (!p) {
	p = strstr(str, "(CVSNT)");
	skip = 8;
    }

    if (!p)
    {
	debug(DEBUG_APPMSG1, "WARNING: malformed CVS version str: %s", str);
	return 0;
    }

    /* We might have encountered a FreeBSD system which
     * has a mucked up version string of:
     *  Concurrent Versions System (CVS) '1.11.17'-FreeBSD (client/server)
     * so re-test just in case
     */
    p += skip;
    if (sscanf(p, "%d.%d.%d", &major, &minor, &extra) != 3)
    {	
        if (sscanf(p, "'%d.%d.%d'", &major, &minor, &extra) != 3)
	{
		debug(DEBUG_APPMSG1, "WARNING: malformed CVS version: %s", str);
		return 0;
	}
    }

    return (major > req_major || 
	    (major == req_major && minor > req_minor) ||
	    (major == req_major && minor == req_minor && extra >= req_extra));
}

