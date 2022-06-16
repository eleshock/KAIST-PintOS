/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

/* eleshock */
#include "string.h" // for memcpy

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* prj 3 Swap In/Out - yeopto */
struct lock file_lock;

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
/* prj 3 Swap In/Out - yeopto */
void
vm_file_init (void) {
	lock_init(&file_lock);
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	if (page == NULL || kva == NULL)
		return false;
	
	ASSERT(VM_TYPE(type) == VM_FILE);

	/* Set up the handler */
	page->operations = &file_ops;
	// printf("\ncurrent subtype %d\n", VM_SUBTYPE(type)); // debug
	if (VM_SUBTYPE(type) == 0){
		/* eleshock */
		struct file_page *aux = page->uninit.aux;
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
		struct file_page *found_fpage = NULL;
		uint32_t count = 0;
		void *first_page = page->va - (now_page-1) * PGSIZE;
		
		// 왜 돌아갔지???????????
		while ((count < open_count) && (found_fpage == NULL))
		{
			struct page *found_page = spt_find_page(&thread_current()->spt, first_page + PGSIZE * count++); // debugging sanori - 후위연산 ㅎㄷㄷ
			if (found_page == page || VM_TYPE(found_page->operations->type) == VM_UNINIT) continue;
			ASSERT(VM_TYPE(found_page->operations->type) == VM_FILE);
			found_fpage = &found_page->file;
			break;
		}
		if (found_fpage != NULL) {
			page->file.m_file = found_fpage->m_file;
			page->file.open_count = found_fpage->open_count;
		} else {
			page->file.m_file = file_duplicate(parent_fpage->m_file);
			page->file.open_count = malloc(sizeof(uint32_t));
			*(page->file.open_count) = open_count;
		}
	}

	return true;
}

/* Swap in the page by read contents from the file. */
/* prj 3 Swap In/Out - yeopto */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *swap_src = &page->file;
	struct file *file = swap_src->m_file;
	off_t ofs = swap_src->ofs;
	uint32_t read_bytes = swap_src->read_bytes;
	uint32_t zero_bytes = swap_src->zero_bytes;

	lock_acquire(&file_lock);
	file_read_at(file, kva, read_bytes, ofs);
	lock_release(&file_lock);

	memset(kva + read_bytes, 0, zero_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
/* prj 3 Swap In/Out - yeopto */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *swap_src = &page->file;
	struct file *file = swap_src->m_file;
	off_t ofs = swap_src->ofs;
	uint32_t read_bytes = swap_src->read_bytes;
	void *kva = page->frame->kva;

	if (pml4_is_dirty(page->pml4, page->va)) {
		lock_acquire(&file_lock);
		file_write_at(file, kva, read_bytes, ofs);
		lock_release(&file_lock);
		
		pml4_set_dirty(page->pml4, page, 0);
		return true;
	} else {
		pml4_set_dirty(page->pml4, page, 0);
		return false;
	} 
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
			/* prj 3 Swap In/Out - yeopto */
			lock_acquire(&file_lock);
			file_write_at(file, kva, write_bytes, ofs);
			lock_release(&file_lock);
			// ASSERT(file_write_at(file, kva, write_bytes, ofs) == (int) write_bytes); // debug
			pml4_set_dirty(page->pml4, page->va, false);
		}
		ft_delete(page->frame);
		free(page->frame);
	}

	if ((--(*(file_page->open_count))) == 0) // debugging sanori - 한줄로 넣느라 연산자 남발해서 제대로 안되면 확인 필요함
	{	
		/* prj 3 Swap In/Out - yeopto */
		lock_acquire(&file_lock);
		file_close(file_page->m_file);
		lock_release(&file_lock);

		free(file_page->open_count);
	}
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
	file_read_at(file, kva, read_bytes, ofs);

	// debug
	// printf("\nin lazy_load curr uva %p\n", page->va);
	// printf("\ninput read_bytes? %d\n", read_bytes);
	// printf("\nofs : %d, zero_bytes : %d\n", ofs, zero_bytes);
	// printf("\nactual read_bytes? %d\n", file_read_at(file, kva, read_bytes, ofs));
	memset(kva + read_bytes, 0, zero_bytes);

	free(aux);
	return true;
}

/* prj 3 memory mapped files - yeopto */
/* Do the mmap */
void *
do_mmap (void *_addr, size_t length, int writable,
		struct file *_file, off_t _offset) {
	if ((int)length <= 0 || pg_ofs(_addr) != 0 || pg_ofs(_offset) != 0 || file_length(_file) <= _offset) return NULL; // debug
	size_t read_bytes = length;
	size_t zero_bytes = pg_ofs(read_bytes) == 0? 0: PGSIZE - pg_ofs(read_bytes); // debug
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);

	struct file *file = file_reopen(_file);
	void *addr = _addr;
	off_t offset = _offset;
	uint32_t page_count = (read_bytes + zero_bytes) / PGSIZE;
	uint32_t now_page = 1;
	uint32_t *open_count = malloc(sizeof(uint32_t));
	*open_count = page_count;
	for (int i = 0; i < page_count; i++)
		if (spt_find_page(&thread_current()->spt, addr + i * PGSIZE) != NULL)
			return NULL;
	
	while (read_bytes > 0 || zero_bytes > 0) {

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct file_page *file_page = calloc(1, sizeof(struct file_page));
		file_page->m_file = file;
		file_page->ofs = offset;
		file_page->read_bytes = page_read_bytes;
		file_page->zero_bytes = page_zero_bytes;
		file_page->open_count = open_count;
		file_page->now_page = now_page++;
		void *aux = file_page;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_file, aux))
			return NULL;

		offset += page_read_bytes;
		
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
	}
	return _addr;
}

/* Jack */
/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *curr_page;
	if ((curr_page = spt_find_page(spt, addr)) == NULL)
		return;
	// printf("\n input addr : %p\n", addr);
	ASSERT((curr_page->operations->type == VM_FILE) || (curr_page->operations->type == VM_UNINIT && curr_page->uninit.type == VM_FILE));
	uint32_t total_count = curr_page->operations->type == VM_FILE? *(curr_page->file.open_count): *(((struct file_page *)curr_page->uninit.aux)->open_count); // debugging sanori - copy때문에 aux에 page가 들어가있는 일은 없겠지...?
	uint32_t curr_count = 1;
	
	do
	{
		// printf("\ntotal page %d, \n", total_count);
		// printf("\ncurrent page %d, \n", curr_count);
		// spt remove시 page가 지워지므로 unmap 및 free 위해 임시 저장함
		uint64_t *curr_pml4 = curr_page->pml4;
		void *curr_uva = curr_page->va;
		void *curr_kva = curr_page->frame != NULL? curr_page->frame->kva: NULL; // debug

		// debug
		// printf("\ncurrent va %p, \n", curr_uva);
		// printf("\nexist before removing? %d\n", spt_find_page(spt, curr_uva)!=NULL? 1:0);

		// spt에서 해당 page를 제거하면서 type별 destroy를 실행하고, page를 free함
		spt_remove_page(spt, curr_page);

		// debug
		// printf("\nremove page complete? %d\n", spt_find_page(spt, curr_uva)==NULL? 1:0);

		// pml4에서 매핑 해제해주고 kva를 free해줌
		if (curr_kva != NULL)
		{
			pml4_clear_page(curr_pml4, curr_uva);
			palloc_free_page(curr_kva);
		}

		curr_page = spt_find_page(spt, addr + PGSIZE * curr_count); // debugging sanori - 후위연산으로 증가시켜줬는데, 문제 없는지 확인필요함
		
		// debug
		// printf("\ncurr page %p\n", curr_page);
		// printf("\ncurr addr %p\n", curr_page->va);
		// printf("\nnext page %d\n", ((struct file_page *)(curr_page->uninit.aux))->now_page);

	} while (curr_count++ < total_count);
}
