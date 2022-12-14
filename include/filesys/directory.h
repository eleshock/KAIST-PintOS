#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/disk.h"

/* Maximum length of a file name component.
 * This is the traditional UNIX maximum length.
 * After directories are implemented, this maximum length may be
 * retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct dir; // Jack
struct inode;

/* eleshock */
enum file_type {
	F_ORD = 0,
	F_DIR = 1,
	F_LINK = 2,
};

/* Opening and closing directories. */
bool dir_create (disk_sector_t sector, size_t entry_cnt);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);

/* Reading and writing. */
bool dir_lookup (const struct dir *, const char *name, struct inode **);

#ifdef EFILESYS
bool dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector, enum file_type type);
#else
bool dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector);
#endif
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);

/* Jack */
disk_sector_t dir_get_inumber (struct dir *dir);
struct dir * find_dir_from_path (char *path_, char buffer[15]);

#endif /* filesys/directory.h */
