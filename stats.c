/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <string.h>
#include <search.h>
#include <cbtcommon/hash.h>

#include "cvsps_types.h"
#include "cvsps.h"

static unsigned int num_patch_sets = 0;
static unsigned int num_ps_member = 0, max_ps_member_in_ps = 0;
static unsigned int num_authors = 0, max_author_len = 0, total_author_len = 0;
static unsigned int max_descr_len = 0, total_descr_len = 0;
struct hash_table *author_hash;

static void count_hash(struct hash_table *hash, unsigned int *total, 
	unsigned int *max_val)
{
    int counter = 0;
    struct hash_entry *fh;
    
    reset_hash_iterator(hash);
    while ((fh = next_hash_entry(hash)))
	counter++;

    *total += counter;
    *max_val= MAX(*max_val, counter);
}

static void stat_ps_tree_node(const void * nodep, const VISIT which, const int depth)
{
    int desc_len;
    PatchSet * ps;
    struct list_head * next;
    int counter;
    void * old;

    /* Make sure we have it if we do statistics */
    if (!author_hash)
	author_hash = create_hash_table(1023);

    switch(which)
    {
    case postorder:
    case leaf:
	ps = *(PatchSet**)nodep;
	num_patch_sets++;

	old = NULL;

	/* Author statistics */
	if (put_hash_object_ex(author_hash, ps->author, ps->author, HT_NO_KEYCOPY, NULL, &old) >= 0 && !old)
	{
	    int len = strlen(ps->author);
	    num_authors++;
	    max_author_len = MAX(max_author_len, len);
	    total_author_len += len;
	}

	/* Log message statistics */
	desc_len = strlen(ps->descr);
	max_descr_len = MAX(max_descr_len, desc_len);
	total_descr_len += desc_len;
	
	/* PatchSet member statistics */
	counter = 0;
	next = ps->members.next;
	while (next != &ps->members)
	{
	    counter++;
	    next = next->next;
	}

	num_ps_member += counter;
	max_ps_member_in_ps = MAX(max_ps_member_in_ps, counter);
	break;

    default:
	break;
    }
}

void print_statistics(void * ps_tree)
{
    /* Statistics data */
    unsigned int num_files = 0, max_file_len = 0, total_file_len = 0;
    unsigned int total_revisions = 0, max_revisions_for_file = 0;
    unsigned int total_branches = 0, max_branches_for_file = 0;
    unsigned int total_branches_sym = 0, max_branches_sym_for_file = 0;

    /* Other vars */
    struct hash_entry *he;
   
    printf("Statistics:\n");
    fflush(stdout);

    /* Gather file statistics */
    reset_hash_iterator(file_hash);
    while ((he=next_hash_entry(file_hash)))
    {
	int len = strlen(he->he_key);
	CvsFile *file = (CvsFile *)he->he_obj;
	
	num_files++;
	max_file_len = MAX(max_file_len, len);
	total_file_len += len;

	count_hash(file->revisions, &total_revisions, &max_revisions_for_file);
	count_hash(file->branches, &total_branches, &max_branches_for_file);
	count_hash(file->branches_sym, &total_branches_sym,
	    &max_branches_sym_for_file);
    }

    /* Print file statistics */
    printf("Num files: %d\nMax filename len: %d, Average filename len: %.2f\n",
	    num_files, max_file_len, (float)total_file_len/num_files);

    printf("Max revisions for file: %d, Average revisions for file: %.2f\n",
	  max_revisions_for_file, (float)total_revisions/num_files);
    printf("Max branches for file: %d, Average branches for file: %.2f\n",
	  max_branches_for_file, (float)total_branches/num_files);
    printf("Max branches_sym for file: %d, Average branches_sym for file: %.2f\n",
	  max_branches_sym_for_file, (float)total_branches_sym/num_files);

    /* Gather patchset statistics */
    twalk(ps_tree, stat_ps_tree_node);

    /* Print patchset statistics */
    printf("Num patchsets: %d\n", num_patch_sets);
    printf("Max PS members in PS: %d\nAverage PS members in PS: %.2f\n",
	    max_ps_member_in_ps, (float)num_ps_member/num_patch_sets);
    printf("Num authors: %d, Max author len: %d, Avg. author len: %.2f\n", 
	    num_authors, max_author_len, (float)total_author_len/num_authors);
    printf("Max desc len: %d, Avg. desc len: %.2f\n",
	    max_descr_len, (float)total_descr_len/num_patch_sets);
}

