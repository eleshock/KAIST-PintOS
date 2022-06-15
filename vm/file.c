/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

/* eleshock */
#include "string.h" // for memcpy

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	if (page == NULL || kva == NULL)
		return false;
	
	ASSERT(VM_TYPE(type) == VM_FILE);

	/* Set up the handler */
	page->operations = &file_ops;
	if (VM_SUBTYPE(type) == 0){
		/* eleshock */
		struct file_page *aux = &page->uninit.aux;
		struct file_page *file_page = &page->file;
		memcpy(file_page, aux, sizeof(struct file_page));
	} else {
		struct file_page *parent_fpage;
		if (VM_SUBTYPE(type) == VM_FCOPY){
			struct page *parent_page = page->uninit.aux;
			parent_fpage = &(parent_page->file);
		} else if (VM_SUBTYPE(type) == VM_FINIT){
			parent_fpage = page->uninit.aux;
		}
		if (memcpy(&page->file, parent_fpage, sizeof(struct file_page)) == NULL)
			return false;

		uint32_t now_page = parent_fpage->now_page;
		uint32_t open_count = *(parent_fpage->open_count);
		struct page *found_page = NULL;
		uint32_t count = 0;
		void *first_page = page->va - (now_page-1) * PGSIZE;
		
		while ((count < open_count) && (found_page == NULL))
			found_page = spt_find_page(&thread_current()->spt, first_page + PGSIZE * count++); // debugging sanori - 후위연산 ㅎㄷㄷ

		if (found_page != NULL) {
			page->file.m_file = found_page->file.m_file;
			page->file.open_count = found_page->file.open_count;
		} else {
			page->file.m_file = file_duplicate(parent_fpage->m_file);
			page->file.open_count = malloc(sizeof(uint32_t));
			*(page->file.open_count) = open_count;
		}
	}

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
