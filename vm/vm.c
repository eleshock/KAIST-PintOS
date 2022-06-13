/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/string.h"



/* Jack */
/* Global Frame table */
static struct frame_table ft;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

	ft_init();
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		bool (*initializer)(struct page *, enum vm_type, void *);
		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initializer = anon_initializer;
			break;
		case VM_FILE:
			initializer = file_backed_initializer;
			break;
		default:
			goto err;
		}
		struct page *new_page = malloc(sizeof(struct page));
		upage = pg_round_down(upage);
		uninit_new(new_page, upage, init, type, aux, initializer);
		new_page->writable = writable;

		/* TODO: Insert the page into the spt. */
		spt_insert_page(spt, new_page);
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	if (spt == NULL || va == NULL) return NULL;

	/* prj3-memory management, yeopto */
	struct page local_page;
	struct hash_elem *found_elem;
	local_page.va = pg_round_down(va);
	
	found_elem = hash_find(&spt->ht, &local_page.hash_elem);
	
	if (found_elem == NULL) {
		return NULL;
	}

	page = hash_entry(found_elem, struct page, hash_elem);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	if (spt == NULL || page == NULL) return false;

	int succ = false;
	/* TODO: Fill this function. */

	/* Jack */
	page->va = pg_round_down(page->va);						// page의 va를 page 첫주소로 갱신
	succ = hash_insert(&spt->ht, &page->hash_elem)? false: true;		// spt의 hash table에 page hash_elem삽입 후 성공여부 저장

	return succ;
}

/* eleshock */
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	ASSERT(spt != NULL);
	ASSERT(page != NULL);

	struct hash *h = &spt->ht;
	struct hash_elem *e = &page->hash_elem;

	hash_delete(h, e);
	vm_dealloc_page (page);

	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* Jack */
/* Initialize global frame table */
void ft_init(void)
{
	list_init(&ft.table);
	lock_init(&ft.lock);
}

/* Insert FR to global frame table */
void ft_insert(struct frame *fr)
{
	ASSERT(fr != NULL);
	lock_acquire(&ft.lock);
	list_push_back(&ft.table, &fr->f_elem);
	lock_release(&ft.lock);
}

/* Delete FR from global frame table and return next frame */
struct frame *ft_delete(struct frame *fr)
{
	ASSERT(fr != NULL);

	lock_acquire(&ft.lock);
	struct list_elem *next = list_remove(&fr->f_elem);
	lock_release(&ft.lock);

	return next != list_tail(&ft.table)? list_entry(next, struct frame, f_elem) : NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;

	/* eleshock */
	void *pp = palloc_get_page(PAL_USER);
	frame = malloc(sizeof(struct frame));
	if (frame == NULL)
		PANIC("todo");
	frame->kva = pp;
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	/* eleshock */
	ft_insert(frame);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	/* Jack */
	// if (!not_present || !is_user_vaddr(addr) || addr == NULL) return false; // debugging sanori - read/write 확인할 일이 있을까?
	if (!not_present) return false; // debugging sanori - 어차피 kernel addr 들어왔거나 NULL 들어오면 spt_find_page에서 걸러지지 않을까?

	return ((page = spt_find_page(spt, addr)) == NULL)? false : vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) { // debugging sanori - va가 유효한지 확인 필요하지 않을까? - 일단 page fault 핸들러에서 걸러준다고 가정하면 문제 없을듯
	if (va == NULL) return false;

	struct page *page = NULL;
	struct supplemental_page_table *spt = &thread_current()->spt;

	/* TODO: Fill this function */
	page = spt_find_page(spt, va);

	return page != NULL? vm_do_claim_page (page): false;
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	if (page == NULL) return false;

	struct frame *frame = vm_get_frame ();
	uint64_t *pml4 = thread_current()->pml4;

	/* prj3 - Anonymous Page, yeopto */
	if (page->operations->type == VM_UNINIT && VM_SUBTYPE(page->uninit.type) == VM_STACK)
		memset(frame->kva, 0, PGSIZE);

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(pml4, page->va, frame->kva, page->writable)) // Jack // debugging sanori - 쓰기를 1로 두어야할지? 이 함수가 언제 쓰일때 다시 고민해볼 수 있을듯 - page에 write 관련 필드가 필요할까?
		return false;
	
	return swap_in (page, frame->kva);
}

/* prj3-memory management, yeopto */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry (p_, struct page, hash_elem);
	return hash_bytes (&p->va, sizeof p->va);
}

/* prj3-memory management, yeopto */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry (a_, struct page, hash_elem);
	const struct page *b = hash_entry (b_, struct page, hash_elem);

	return a->va < b->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* prj3-memory management, yeopto */
	ASSERT(spt != NULL);
	
	hash_init(&spt->ht, page_hash, page_less, NULL);
	return;
}

/* Jack */
/* Copy page function for spt copy */
bool 
page_copy (struct page *page, void *aux)
{
	struct page *parent_page = aux;
	void *parent_kva = parent_page->frame->kva;
	void *child_kva = page->frame->kva;
	
	return memcpy(child_kva, parent_kva, PGSIZE)!=NULL? true: false; // debugging sanori - kva로 접근해야할까 uva로 접근해야할까?
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	/* Jack */
	struct hash_iterator i;
	hash_first(&i, &src->ht);
	while (hash_next(&i))
	{
		struct page *src_p = hash_entry(hash_cur(&i), struct page, hash_elem);
		switch (src_p->operations->type)
		{
		case VM_UNINIT:
			if (!vm_alloc_page_with_initializer(src_p->uninit.type, src_p->va, src_p->writable, src_p->uninit.init, src_p->uninit.aux))
				return false;
			break;
		case VM_ANON:
			if (!vm_alloc_page_with_initializer(src_p->operations->type | src_p->anon.sub_type, src_p->va, src_p->writable, page_copy, src_p) || !vm_claim_page(src_p->va))
				return false;
			break;
		case VM_FILE:
			break;
		default:
			break;
		}
	}
	return true; // debug success - true return 누가 안했냐... jack
}

/* eleshock */
void
spt_destructor (struct hash_elem *e, void *aux UNUSED) {
	struct page *page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	/* eleshock */
	hash_destroy(&spt->ht, spt_destructor);
}
