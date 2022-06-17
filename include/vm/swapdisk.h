#include <stdbool.h>
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "lib/debug.h"

typedef int swap_slot_t;

#define SECTOR_PER_SLOT 8
#define SECTOR(slot) (disk_sector_t)(slot * SECTOR_PER_SLOT)
#define SLOT_COUNT(size) (swap_slot_t)(size / SECTOR_PER_SLOT)

void swapdisk_init(void);
bool swapdisk_swap_in(swap_slot_t slot, void *_kva, bool copy);
swap_slot_t swapdisk_swap_out(void *_kva);
void swapdisk_free_swap_slot(swap_slot_t slot);
