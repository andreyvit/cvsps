/*
 * Copyright 2001, 2002, 2003 David Mansfield and Cobite, Inc.
 * See COPYING file for license information 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "hash.h"
#include "rcsid.h"

RCSID("$Id: hash.c,v 1.6 2003/05/07 15:42:38 david Exp $");

#define HASH_CONST 37

static unsigned int hash_string(const char *);
static struct hash_entry *scan_list(struct list_head *, const char *); 
static struct hash_entry *get_hash_entry(struct hash_table *tbl, const char *key);

struct hash_table *create_hash_table(unsigned int sz)
{
    struct hash_table *tbl;
    unsigned int i;

    tbl = (struct hash_table *)malloc(sizeof(*tbl) + sz*sizeof(struct list_head));

    if (!tbl)
    {
	debug(DEBUG_APPERROR, "malloc for hash_table failed");
	return NULL;
    }
	
    tbl->ht_size  = sz;
    tbl->ht_lists = (struct list_head *)(tbl + 1);
    tbl->iterator = 0;

    for (i = 0; i < sz; i++)
	INIT_LIST_HEAD(&tbl->ht_lists[i]);

    return tbl;
}

void destroy_hash_table(struct hash_table *tbl, void (*delete_obj)(void *))
{
    struct list_head  *head, *next, *tmp;
    struct hash_entry *entry;
    int i;

    for (i = 0; i < tbl->ht_size; i++)
    {
	head = &tbl->ht_lists[i];
	next = head->next;

	while (next != head)
	{
	    tmp = next->next;
	    entry = list_entry(next, struct hash_entry, he_list);
	    if (delete_obj)
		delete_obj(entry->he_obj);
	    free(entry);

	    next = tmp;
	}
    }

    free(tbl);
}

/* FIXME: there is no way for the user of this to determine the difference
 *        between a put to a new key value and a malloc failure
 */
void *put_hash_object(struct hash_table *tbl, const char *key, void *obj)
{
    void * retval;
    put_hash_object_ex(tbl, key, obj, HT_KEYCOPY, NULL, &retval);
    return retval;
}

static struct hash_entry *get_hash_entry(struct hash_table *tbl, const char *key)
{
    struct list_head  *head;
    struct hash_entry *entry;
    unsigned int hash;

    hash  = hash_string(key) % tbl->ht_size;
    head  = &tbl->ht_lists[hash];
    entry = scan_list(head, key);

    return entry;
}

void *get_hash_object(struct hash_table *tbl, const char *key)
{
    struct hash_entry *entry = get_hash_entry(tbl, key);
    return (entry) ? entry->he_obj : NULL;
}

void *remove_hash_object(struct hash_table *tbl, const char *key)
{
    struct hash_entry *entry = get_hash_entry(tbl, key);
    void *retval = NULL;

    if (entry)
    {
	list_del(&entry->he_list);
	retval = entry->he_obj;
	free(entry);
    }

    return retval;
}

static unsigned int hash_string(register const char *key)
{
    register unsigned int hash = 0;
    
    while(*key)
	hash = hash * HASH_CONST + *key++; 
    
    return hash;
}

static struct hash_entry *scan_list(struct list_head *head, const char *key)
{
    struct list_head  *next = head->next;
    struct hash_entry *entry;

    while (next != head)
    {
	entry = list_entry(next, struct hash_entry, he_list);
	if (strcmp(entry->he_key, key) == 0)
	    return entry;

	next = next->next;
    }

    return NULL;
}

void reset_hash_iterator(struct hash_table *tbl)
{
    tbl->iterator = 0;
    tbl->iterator_ptr = NULL;
}

struct hash_entry *next_hash_entry(struct hash_table *tbl)
{
    while( tbl->iterator < tbl->ht_size )
    {
	struct list_head *head = &tbl->ht_lists[ tbl->iterator ];

	if( tbl->iterator_ptr == NULL )
	    tbl->iterator_ptr = head->next;

	if( tbl->iterator_ptr != head )
	{
	    struct list_head *tmp = tbl->iterator_ptr;
	    tbl->iterator_ptr = tbl->iterator_ptr->next;
	    return( list_entry( tmp, struct hash_entry, he_list ) );
	}

	else
	{
	    tbl->iterator++;
	    tbl->iterator_ptr = NULL;
	}
    }

    return( NULL );
}

int put_hash_object_ex(struct hash_table *tbl, const char *key, void *obj, int copy, 
		       char ** oldkey, void ** oldobj)
{
    struct list_head *head;
    struct hash_entry *entry;
    unsigned int hash;
    int retval = 0;

    /* FIXME: how can get_hash_entry be changed to be usable here? 
     * we need the value of head later if the entry is not found...
     */
    hash  = hash_string(key) % tbl->ht_size;
    head  = &tbl->ht_lists[hash];
    entry = scan_list(head, key);

    if (entry)
    {
	if (oldkey)
	    *oldkey = entry->he_key;
	if (oldobj)
	    *oldobj = entry->he_obj;

	/* if 'copy' is set, then we already have an exact
	 * private copy of the key (by definition of having
	 * found the match in scan_list) so we do nothing.
	 * if !copy, then we can simply assign the new
	 * key
	 */
	if (!copy)
	    entry->he_key = (char*)key; /* discard the const */
	entry->he_obj = obj;
    }
    else
    {
	size_t s = sizeof(*entry);

	if (oldkey)
	    *oldkey = NULL;
	if (oldobj)
	    *oldobj = NULL;

	if (copy)
	    s +=  strlen(key) + 1;

	entry = (struct hash_entry *)malloc(s);
	
	if (!entry)
	{
	    debug(DEBUG_APPERROR,"malloc failed put_hash_object key='%s'",key);
	    retval = -1;
	}
	else
	{
	    if (copy)
	    {
		entry->he_key = (char *)(entry + 1);
		strcpy(entry->he_key, key);
	    }
	    else
	    {
		entry->he_key = (char*)key; /* discard the const */
	    }

	    entry->he_obj = obj;

	    list_add(&entry->he_list, head);
	}
    }

    return retval;
}

void destroy_hash_table_ex(struct hash_table *tbl, 
			   void (*delete_entry)(const void *, char *, void *), 
			   const void * cookie)
{
    struct list_head  *head, *next, *tmp;
    struct hash_entry *entry;
    int i;
    
    for (i = 0; i < tbl->ht_size; i++)
    {
	head = &tbl->ht_lists[i];
	next = head->next;
	
	while (next != head)
	{
	    tmp = next->next;
	    entry = list_entry(next, struct hash_entry, he_list);
	    if (delete_entry)
		delete_entry(cookie, entry->he_key, entry->he_obj);
	    free(entry);

	    next = tmp;
	}
    }

    free(tbl);
}
