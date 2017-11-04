/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef CVS_DIRECT_H
#define CVS_DIRECT_H

#ifndef HAVE_CVSSERVERCTX_DEF
#define HAVE_CVSSERVERCTX_DEF
typedef struct _CvsServerCtx CvsServerCtx;
#endif

struct _CvsRlog
{
    unsigned int flags;
    #define CRLOGF_CAP_LOGM	0x01U	/* set on first LOGM read */
    #define CRLOGF_READ_LOGM	0x02U	/* flags current read as LOGM */
    #define CRLOGF_CVSDIRECT	0x04U

    /* if CVSDIRECT */
    CvsServerCtx * csctx;
    /* else application FILE used and application managed */
    FILE * fp;
};
/* private */
#define CRLOG_SET_LOGM(x)	((x)->flags |= CRLOGF_CAP_LOGM|CRLOGF_READ_LOGM)
#define CRLOG_CLR_LOGM(x)	((x)->flags &= ~CRLOGF_READ_LOGM)
/* public */
#define CRLOG_HAS_LOGM(x)	((x)->flags & CRLOGF_CAP_LOGM)
#define CRLOG_IS_LOGM(x)	((x)->flags & CRLOGF_READ_LOGM)

typedef struct _CvsRlog CvsRlog;

CvsServerCtx * open_cvs_server(char * root, int);
void close_cvs_server(CvsServerCtx*);
void cvs_rdiff(CvsServerCtx *, const char *, const char *, const char *, const char *);
void cvs_rupdate(CvsServerCtx *, const char *, const char *, const char *, int, const char *);
void cvs_diff(CvsServerCtx *, const char *, const char *, const char *, const char *, const char *);
/* Must call cvs_rlog_close to free CvsRlog object */
CvsRlog * cvs_rlog_open(CvsServerCtx *, const char *, const char *);
char * cvs_rlog_fgets(char *, int, CvsRlog *);
/* frees CvsRlog object */
void cvs_rlog_close(CvsRlog *);
void cvs_version(CvsServerCtx *, char *, char *);

#endif /* CVS_DIRECT_H */
