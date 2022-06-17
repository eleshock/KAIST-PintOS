#include "vm/swapdisk.h"

/* Jack */

/* Global disk, bitmap, lock */
static struct disk *swap_disk;
static struct bitmap *swap_table;
static struct lock swap_table_lock;
static struct lock *st_lock = &swap_table_lock;

/* Initialize swapdisk and swaptable */
void swapdisk_init(void)
{
#ifndef FILESYS
    disk_init();
#endif
    swap_disk = disk_get(1, 1);
    disk_sector_t total_sector = disk_size(swap_disk);
    swap_slot_t total_slot = SLOT_COUNT(total_sector);
    swap_table = bitmap_create(total_slot);
    lock_init(st_lock);
}

/* 
Scan swaptable for allocating swapslot and flip it.
Return swap slot found.
If allocation is unavailable, raise kernel panic.
*/
swap_slot_t swapdisk_get_swap_slot(void)
{
    swap_slot_t slot;
    lock_acquire(st_lock);
    if ((slot = bitmap_scan_and_flip(swap_table, 0, 1, false)) == BITMAP_ERROR)
        PANIC("NO MORE SWAPSLOT AVAILABLE");
    lock_release(st_lock);
    return slot;
}

/* Set SLOT of swaptable to false */
void swapdisk_free_swap_slot(swap_slot_t slot)
{
    ASSERT (bitmap_test(swap_table, slot) == true);
    lock_acquire(st_lock);
    bitmap_set(swap_table, slot, false);
    lock_release(st_lock);
}

/*
By using SLOT, calculate sector no. and
read pagesize data from that sector of disk to physical memory _KVA.
If COPY is true, SLOT will not be freed.
Otherwise SLOT will be freed.
*/
bool swapdisk_swap_in(swap_slot_t slot, void *_kva, bool copy)
{
    if (_kva == NULL || bitmap_test(swap_table, slot) == false)
        return false;

    void *kva = _kva;
    disk_sector_t sector = SECTOR(slot);
    ASSERT (sector < disk_size(swap_disk));

    for (int i = 0; i < SECTOR_PER_SLOT; i++)
        disk_read(swap_disk, sector + i, kva + i * DISK_SECTOR_SIZE);
    if (copy == false)
        swapdisk_free_swap_slot(slot);
    return true;
}

/*
Find available swap slot from swapdisk and
write pagesize data from physical memory _KVA to disk.
Return swap slot written.
*/
swap_slot_t swapdisk_swap_out(void *_kva)
{
    if (_kva == NULL)
        return -1;

    void *kva = _kva;
    swap_slot_t slot = swapdisk_get_swap_slot();
    disk_sector_t sector = SECTOR(slot);
    ASSERT (sector < disk_size(swap_disk));

    for (int i = 0; i < SECTOR_PER_SLOT; i++)
        disk_write(swap_disk, sector + i, kva + i * DISK_SECTOR_SIZE);
    
    return slot;
}