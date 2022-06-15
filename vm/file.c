/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

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
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
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

/* prj 3 memery mapped files - yeopto */
static bool
lazy_load_file (struct page *page, void *aux) {
	struct file_page *load_src = &(page->file);
	struct file *file = load_src->m_file;
	off_t ofs = load_src->ofs;
	uint32_t read_bytes = load_src->read_bytes;
	uint32_t zero_bytes = load_src->zero_bytes;
	void *kva = page->frame->kva;

	if(file_read_at(file, kva, read_bytes, ofs) != (int) read_bytes)
		return false;
	memset(kva + read_bytes, 0, zero_bytes);

	free(aux);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file_, off_t offset) {
	/* prj 3 memory mapped files - yeopto */
	if (length != 0 || pg_ofs(addr) == 0) return NULL;

	size_t read_bytes = length;
	size_t zero_bytes = PGSIZE - pg_ofs(addr);
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	
	void *addr_temp = addr;
	off_t offset_temp = offset;
	uint32_t count;
	uint32_t now_page = 1;
	struct file *file = file_reopen(file_);
	
	if (spt_find_page(&thread_current->spt, addr) == NULL) {
		return NULL;
	}

	count = (read_bytes + zero_bytes) / PGSIZE;
	
	while (read_bytes > 0 || zero_bytes > 0) {

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct file_page *file_page = calloc(1, sizeof(struct file_page));
		file_page->m_file = file;
		file_page->ofs = offset_temp;
		file_page->read_bytes = page_read_bytes;
		file_page->zero_bytes = page_zero_bytes;
		file_page->open_count = malloc(sizeof(uint32_t));
		*(file_page->open_count) = count;
		file_page->now_page = now_page++;
		
		void *aux = file_page;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_file, aux))
			return false;
		
		offset_temp += page_read_bytes;
		
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr_temp += PGSIZE;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}