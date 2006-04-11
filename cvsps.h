/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#ifndef CVSPS_H
#define CVSPS_H

#ifndef HAVE_CVSSERVERCTX_DEF
#define HAVE_CVSSERVERCTX_DEF
typedef struct _CvsServerCtx CvsServerCtx;
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern struct hash_table * file_hash;
extern const char * tag_flag_descr[];
extern CvsServerCtx * cvs_direct_ctx;
extern char root_path[];
extern char repository_path[];

CvsFile * create_cvsfile();
CvsFileRevision * cvs_file_add_revision(CvsFile *, const char *);
void cvs_file_add_symbol(CvsFile * file, const char * rev, const char * tag);
char * cvs_file_add_branch(CvsFile *, const char *, const char *);
PatchSet * get_patch_set(const char *, const char *, const char *, const char *, PatchSetMember *);
PatchSetMember * create_patch_set_member();
CvsFileRevision * file_get_revision(CvsFile *, const char *);
void patch_set_add_member(PatchSet * ps, PatchSetMember * psm);
void walk_all_patch_sets(void (*action)(PatchSet *));

#endif /* CVSPS_H */
