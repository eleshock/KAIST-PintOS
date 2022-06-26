#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/fat.h"

/* eleshock */
#include "threads/vaddr.h"
#include "threads/palloc.h"


/* A directory. */
struct dir
{
	struct inode *inode; /* Backing store. */
	off_t pos;			 /* Current position. */
};

/* A single directory entry. */
struct dir_entry
{
	disk_sector_t inode_sector; /* Sector number of header. */
	char name[NAME_MAX + 1];	/* Null terminated file name. */
	bool in_use;				/* In use or free? */
								// #ifdef EFILESYS
	// eleshock
	enum file_type type;
	// Jack
	// 32byte로 align 해서 섹터 안에 16개가 꽉차도록 -> 여러 섹터로 된 디렉토리 고려
	uint8_t unused[8]; /* not used */
					   // #endif
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
#ifndef FILESYS
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
#else
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry), F_DIR);
#endif
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open(struct inode *inode)
{
	struct dir *dir = calloc(1, sizeof *dir);
	if (inode != NULL && dir != NULL)
	{
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	}
	else
	{
		inode_close(inode);
		free(dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root(void)
{
#ifdef EFILESYS
	return dir_open(inode_open(cluster_to_sector(ROOT_DIR_CLUSTER))); // Jack
#else
	return dir_open(inode_open(ROOT_DIR_SECTOR));
#endif
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen(struct dir *dir)
{
	return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir *dir)
{
	if (dir != NULL)
	{
		inode_close(dir->inode);
		free(dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode(struct dir *dir)
{
	return dir->inode;
}

/* Jack */
/* Returns the inode number of dir inode */
disk_sector_t
dir_get_inumber (struct dir *dir) {
	return inode_get_inumber(dir->inode);
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup(const struct dir *dir, const char *name,
	   struct dir_entry *ep, off_t *ofsp)
{
	struct dir_entry e;
	size_t ofs;

	ASSERT(dir != NULL);
	ASSERT(name != NULL);


#ifndef FILESYS
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
#else
	bool success = false;

	off_t length = inode_length(dir->inode);
	off_t entry_count = length / (sizeof e);

	size_t pages = length % PGSIZE == 0? length / PGSIZE: length / PGSIZE + 1;
	struct dir_entry *entries = palloc_get_multiple(PAL_ZERO, pages);
	inode_read_at (dir->inode, entries, length, 0);
	
	for (ofs = 0; ofs != entry_count; ++ofs) {
		e = entries[ofs];
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs * (sizeof e);
			success = true;
			break;
		}
	}
	palloc_free_multiple(entries, pages);
	return success;
#endif
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir *dir, const char *name,
				struct inode **inode)
{
	struct dir_entry e;

	ASSERT(dir != NULL);
	ASSERT(name != NULL);

	if (lookup(dir, name, &e, NULL))
		*inode = inode_open(e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

#ifdef EFILESYS
/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool dir_add(struct dir *dir, const char *name, disk_sector_t inode_sector, enum file_type type)
{
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT(dir != NULL);
	ASSERT(name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen(name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup(dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
		 ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy(e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	e.type = type; // eleshock
	success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}
#else

bool dir_add(struct dir *dir, const char *name, disk_sector_t inode_sector)
{
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT(dir != NULL);
	ASSERT(name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen(name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup(dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
#ifndef FILESYS
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;
#else // Jack - 속도개선
	off_t length = inode_length(dir->inode);
	off_t entry_count = length / (sizeof e);

	size_t pages = length % PGSIZE == 0? length / PGSIZE: length / PGSIZE + 1;
	struct dir_entry *entries = palloc_get_multiple(PAL_ZERO, pages);
	if (entries == NULL)
		goto done;
	inode_read_at (dir->inode, entries, length, 0);
	
	for (ofs = 0; ofs != entry_count; ++ofs) {
		e = entries[ofs];
		if (!e.in_use)
			break;
	}
	ofs = ofs * (sizeof e);
	palloc_free_multiple(entries, pages);
#endif

	/* Write slot. */
	e.in_use = true;
	strlcpy(e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}
#endif

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir *dir, const char *name)
{
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT(dir != NULL);
	ASSERT(name != NULL);

	/* Find directory entry. */
	if (!lookup(dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	/* Jack */
	if (e.type == F_DIR) {
		struct dir_entry ee;
		off_t length = inode_length(inode);
		off_t entry_count = length / (sizeof ee);

		size_t pages = length % PGSIZE == 0? length / PGSIZE: length / PGSIZE + 1;
		struct dir_entry *entries = palloc_get_multiple(PAL_ZERO, pages);
		if (entries == NULL)
			goto done;
		inode_read_at (inode, entries, length, 0);
		
		for (ofs = 2; ofs != entry_count; ++ofs) {
			ee = entries[ofs];
			if (ee.in_use){
				palloc_free_multiple(entries, pages);
				goto done;
			}
		}
		palloc_free_multiple(entries, pages);
	}

	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool dir_readdir(struct dir *dir, char name[NAME_MAX + 1])
{
	struct dir_entry e;

	/* eleshock */

	while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e)
	{
		dir->pos += sizeof e;
		if (e.in_use && (strchr(".", *e.name) == NULL))
		{
			strlcpy(name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}

/* Jack */
/* Parse directory of PATH and return last opened directory.
 * If BUFFER is not NULL, last file name will be saved at BUFFER. 
 * After using dir which is returned, caller has to free dir. */
struct dir *
find_dir_from_path (char *path_, char buffer[15]) {
	if (path_ == NULL)
		return NULL;
	
	// 사용자 영역의 path_ 유지 위해 path 새로 복제
	char *path = calloc(1, strlen(path_)+1);
	ASSERT (path != NULL);
	strlcpy(path, path_, strlen(path_)+1);

	struct dir *curr_dir = NULL;
	char *curr_path;
	char *remain_path;

	curr_path = strtok_r(path, "/", &remain_path);
	// 첫번째 파싱 후 절대경로 / . / .. 에 따라 디렉토리 이동
	// 만약 첫번째가 파싱된게 path의 전부라면 이동안하고 그냥 반환
	bool is_root = (strchr("/", *path) != NULL);

	if (!strcmp("..", curr_path) && !is_root) {
		struct inode *dir_inode = NULL;
		ASSERT ((curr_dir = dir_reopen(thread_current()->working_dir)) != NULL);
		if (*remain_path == '\0'){
			if (buffer != NULL)
				strlcpy(buffer, "..", strlen("..") + 1);
			goto done;
		}
		if (dir_lookup(curr_dir, "..", &dir_inode) && inode_get_type(dir_inode) == F_DIR) {
			dir_close(curr_dir);
			ASSERT ((curr_dir = dir_open(dir_inode)) != NULL);
		} else {
			if (dir_inode != NULL)
				inode_close(dir_inode);
			dir_close(curr_dir);
			curr_dir = NULL;
			goto done;
		}
	} else if (!strcmp(".", curr_path) && !is_root) {
		ASSERT ((curr_dir = dir_reopen(thread_current()->working_dir)) != NULL);
		if (*remain_path == '\0'){
			if (buffer != NULL)
				strlcpy(buffer, ".", strlen(".") + 1);
			goto done;
		}
	} else {
		struct inode *dir_inode = NULL;
		ASSERT ((curr_dir = dir_open_root()) != NULL);
		if (*remain_path == '\0'){
			if (buffer != NULL)
				strlcpy(buffer, curr_path, strlen(curr_path) + 1);
			goto done;
		}
		if (dir_lookup(curr_dir, curr_path, &dir_inode) && inode_get_type(dir_inode) == F_DIR) {
			dir_close(curr_dir);
			ASSERT ((curr_dir = dir_open(dir_inode)) != NULL);
		} else {
			if (dir_inode != NULL)
				inode_close(dir_inode);
			dir_close(curr_dir);
			curr_dir = NULL;
			goto done;
		}
	}
	
	// 마지막 디렉토리에 도착하기 전까지 디렉토리를 계속 들어감
	for (curr_path = strtok_r(NULL, " ", &remain_path); *remain_path != '\0'; curr_path = strtok_r(NULL, " ", &remain_path))
	{
		struct inode *dir_inode = NULL;
		if (dir_lookup(curr_dir, curr_path, &dir_inode) && inode_get_type(dir_inode) == F_DIR) {
			dir_close(curr_dir);
			ASSERT ((curr_dir = dir_open(dir_inode)) != NULL);
		} else {
			if (dir_inode != NULL)
				inode_close(dir_inode);
			dir_close(curr_dir);
			curr_dir = NULL;
			goto done;
		}
	}

	// 마지막 디렉토리 도착 후 마지막 파일 name을 저장
	if (buffer != NULL)
		strlcpy(buffer, curr_path, strlen(curr_path) + 1);

done:
	free(path);
	return curr_dir;
}
