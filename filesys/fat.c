#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
	unsigned int magic;
	unsigned int sectors_per_cluster; /* Fixed to 1 */
	unsigned int total_sectors;
	unsigned int fat_start;
	unsigned int fat_sectors; /* Size of FAT in sectors. */
	unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs {
	struct fat_boot bs;
	unsigned int *fat;
	unsigned int fat_length;
	disk_sector_t data_start;
	cluster_t last_clst;
	struct lock write_lock;
	struct lock read_lock; // Jack
	unsigned int read_count; // Jack
};

static struct fat_fs *fat_fs;

void fat_boot_create (void);
void fat_fs_init (void);

void
fat_init (void) {
	fat_fs = calloc (1, sizeof (struct fat_fs));
	if (fat_fs == NULL)
		PANIC ("FAT init failed");

	// Read boot sector from the disk
	unsigned int *bounce = malloc (DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT init failed");
	disk_read (filesys_disk, FAT_BOOT_SECTOR, bounce);
	memcpy (&fat_fs->bs, bounce, sizeof (fat_fs->bs));
	free (bounce);

	// Extract FAT info
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create ();
	fat_fs_init ();
}

void
fat_open (void) {
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT load failed");

	// Load FAT directly from the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_read = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_read;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_read (filesys_disk, fat_fs->bs.fat_start + i,
			           buffer + bytes_read);
			bytes_read += DISK_SECTOR_SIZE;
		} else {
			uint8_t *bounce = malloc (DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT load failed");
			disk_read (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			memcpy (buffer + bytes_read, bounce, bytes_left);
			bytes_read += bytes_left;
			free (bounce);
		}
	}
}

void
fat_close (void) {
	// Write FAT boot sector
	uint8_t *bounce = calloc (1, DISK_SECTOR_SIZE);
	if (bounce == NULL)
		PANIC ("FAT close failed");
	memcpy (bounce, &fat_fs->bs, sizeof (fat_fs->bs));
	disk_write (filesys_disk, FAT_BOOT_SECTOR, bounce);
	free (bounce);

	// Write FAT directly to the disk
	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	off_t bytes_wrote = 0;
	off_t bytes_left = sizeof (fat_fs->fat);
	const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		bytes_left = fat_size_in_bytes - bytes_wrote;
		if (bytes_left >= DISK_SECTOR_SIZE) {
			disk_write (filesys_disk, fat_fs->bs.fat_start + i,
			            buffer + bytes_wrote);
			bytes_wrote += DISK_SECTOR_SIZE;
		} else {
			bounce = calloc (1, DISK_SECTOR_SIZE);
			if (bounce == NULL)
				PANIC ("FAT close failed");
			memcpy (bounce, buffer + bytes_wrote, bytes_left);
			disk_write (filesys_disk, fat_fs->bs.fat_start + i, bounce);
			bytes_wrote += bytes_left;
			free (bounce);
		}
	}
}

void
fat_create (void) {
	// Create FAT boot
	fat_boot_create ();
	fat_fs_init ();

	// Create FAT table
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT creation failed");

	// Set up ROOT_DIR_CLST
	/* prj4 filesys - yeopto */
	lock_acquire(&fat_fs->write_lock);
	fat_put (ROOT_DIR_CLUSTER, EOChain);
	lock_release(&fat_fs->write_lock);

	// Jack
	// root dir 위치에 inode 없이 directory로 쓴다? 어쩌자는거지? 그냥 inode만드는 방식으로 바꿀래...
	if (!dir_create (cluster_to_sector (ROOT_DIR_CLUSTER), 16))
		PANIC ("root directory creation failed");

	// Fill up ROOT_DIR_CLUSTER region with 0
	// uint8_t *buf = calloc (1, DISK_SECTOR_SIZE);
	// if (buf == NULL)
	// 	PANIC ("FAT create failed due to OOM");
	// disk_write (filesys_disk, cluster_to_sector (ROOT_DIR_CLUSTER), buf);
	// free (buf);
}

void
fat_boot_create (void) {
	unsigned int fat_sectors =
	    (disk_size (filesys_disk) - 1)
	    / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
	    .magic = FAT_MAGIC,
	    .sectors_per_cluster = SECTORS_PER_CLUSTER,
	    .total_sectors = disk_size (filesys_disk),
	    .fat_start = 1,
	    .fat_sectors = fat_sectors,
	    .root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

/* prj4 filesys - yeopto */
void
fat_fs_init (void) {
	/* TODO: Your code goes here. */
	fat_fs->fat_length = fat_fs->bs.total_sectors - fat_fs->bs.fat_sectors - 1;
	fat_fs->data_start = fat_fs->bs.fat_start + fat_fs->bs.fat_sectors;
	fat_fs->read_count = 0;
	lock_init(&fat_fs->write_lock);
	lock_init(&fat_fs->read_lock);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
cluster_t
fat_create_chain (cluster_t clst) {
	/* TODO: Your code goes here. */

	/* eleshock */
	lock_acquire(&fat_fs->write_lock);
	cluster_t i = 2;
	while (fat_fs->fat[i] != 0 && i < fat_fs->fat_length) {
		++i;
	}
	
	if (i == fat_fs->fat_length) {
		i = 0;
		goto done;
	}
	
	fat_put(i, EOChain);
	
	if (clst == 0) {
		goto done;
	}

	ASSERT(fat_fs->fat[clst] == EOChain);
	
	fat_put(clst, i);
done:
	lock_release(&fat_fs->write_lock);
	return i;
}

/* Jack */
/* Add clusters to the chain.
 * If CLST is 0, start a new chain.
 * If CLSTP is not NULL, save first cluster number to it
 * Returns false if fails to allocate a new cluster */
bool
fat_create_multi_chain (cluster_t clst, cluster_t size, cluster_t *clstp) {
	cluster_t first_clst = clst == 0? fat_create_chain(0) : fat_create_chain(clst);
	if (first_clst == 0) return false;

	cluster_t next_clst = first_clst;
	for (int i = 0; i < size - 1; i++)
	{
		next_clst = fat_create_chain(next_clst);
		if (next_clst == 0)
		{
			fat_remove_chain(first_clst, clst);
			return false;
		}
	}
	if (clstp != NULL)
		*clstp = first_clst;

	return true;
}


/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
	/* TODO: Your code goes here. */
	/* prj4 filesys - yeopto */
	cluster_t tmp_clst = clst;
	
	lock_acquire(&fat_fs->write_lock);
	
	while (fat_fs->fat[tmp_clst] != EOChain) {
		cluster_t temp = fat_fs->fat[tmp_clst];
		fat_put(tmp_clst, 0);
		tmp_clst = temp;
	}
	if (fat_fs->fat[tmp_clst] == EOChain)
		fat_put(tmp_clst, 0);

	if (pclst != 0)
		fat_put(pclst, EOChain);

	lock_release(&fat_fs->write_lock);
	fat_close();
}

/* Update a value in the FAT table. */
void
fat_put (cluster_t clst, cluster_t val) {
	/* TODO: Your code goes here. */
	/* prj4 filesys - yeopto */
	fat_fs->fat[clst] = val;
}

/* Jack */
/* Fetch a value in the FAT table. */
cluster_t
fat_get (cluster_t clst) {
	/* TODO: Your code goes here. */
	cluster_t ret;

	lock_acquire(&fat_fs->read_lock);
	fat_fs->read_count++;
	if (fat_fs->read_count == 1)
		lock_acquire(&fat_fs->write_lock);
	lock_release(&fat_fs->read_lock);

	ret = fat_fs->fat[clst];

	lock_acquire(&fat_fs->read_lock);
	fat_fs->read_count--;
	if (fat_fs->read_count == 0)
		lock_release(&fat_fs->write_lock);
	lock_release(&fat_fs->read_lock);

	return ret;
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector (cluster_t clst) {
	/* TODO: Your code goes here. */
	/* prj4 filesys - yeopto */
	disk_sector_t sector_num = fat_fs->data_start + clst;

	return sector_num;
}

/* Jack */
/* Convert a sector # to a cluster number */
cluster_t
sector_to_cluster (disk_sector_t sector) {
	return sector - fat_fs->data_start;
}
