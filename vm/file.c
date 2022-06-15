/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

static void file_backed_link(struct page *prev, struct page *curr);
static struct page *file_backed_next(struct page *page);

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

/* Jack */
/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	ASSERT(page != NULL);

	struct file_page *file_page = &page->file;

	struct file *file = file_page->m_file;
	off_t ofs = file_page->ofs;
	uint32_t write_bytes = file_page->read_bytes;

	// frame이 있고 (메모리에 올려져 있는 상태이고) dirty비트가 켜져있으면 파일에 덮어쓰고 dirty bit는 0으로 바꿈 (어차피 지우긴 하겠지만)
	if (page->frame != NULL)
	{
		if (pml4_is_dirty(page->pml4, page->va))
		{
			void *kva = page->frame->kva;
			ASSERT(file_write_at(file, kva, write_bytes, ofs) == (int) write_bytes);
			pml4_set_dirty(page->pml4, page->va, false);
		}
		ft_delete(page->frame);
		free(page->frame);
	}

	if ((--(*(file_page->open_count))) == 0) // debugging sanori - 한줄로 넣느라 연산자 남발해서 제대로 안되면 확인 필요함
	{
		file_close(file_page->m_file);
		free(file_page->open_count);
	}
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
}

/* Jack */
/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *curr_page;
	if ((curr_page = spt_find_page(spt, addr)) == NULL)
		return;
	
	ASSERT((curr_page->operations->type == VM_FILE) || (curr_page->operations->type == VM_UNINIT && curr_page->uninit.type == VM_FILE));
	uint32_t total_count = curr_page->operations->type == VM_FILE? *(curr_page->file.open_count): *(curr_page->uninit.aux->open_count); // debugging sanori - copy때문에 aux에 page가 들어가있는 일은 없겠지...?
	uint32_t curr_count = 1;
	
	do
	{
		// spt remove시 page가 지워지므로 unmap 및 free 위해 임시 저장함
		uint64_t *curr_pml4 = curr_page->pml4;
		void *curr_uva = curr_page->va;
		void *curr_kva = curr_page->frame->kva;

		// spt에서 해당 page를 제거하면서 type별 destroy를 실행하고, page를 free함
		spt_remove_page(spt, curr_page);

		// pml4에서 매핑 해제해주고 kva를 free해줌
		pml4_clear_page(curr_pml4, curr_uva);
		palloc_free_page(curr_kva);

		curr_page = spt_find_page(spt, addr + PGSIZE * curr_count++); // debugging sanori - 후위연산으로 증가시켜줬는데, 문제 없는지 확인필요함
		
	} while (curr_count < total_count);
}
