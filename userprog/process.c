#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h" // Jack
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
    char *token, *save_ptr, *fn_for_tok; /*** hyeRexx ***/

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = malloc(strlen(file_name)+2); // 메모리 효율성 위해 malloc으로 변경
	// fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, strlen(file_name)+2); /*** debugging genie : PGSIZE ***/

    /*** hyeRexx ***/
    fn_for_tok = malloc(strlen(file_name)+2); // 메모리 효율성 위해 malloc으로 변경
    // fn_for_tok = palloc_get_page(0); 
    ASSERT(fn_for_tok != NULL); // allocation check
    strlcpy(fn_for_tok, file_name, strlen(file_name)+2);
    token = strtok_r(fn_for_tok, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
    /*** hyeRexx : first arg : file_name -> token ***/
	tid = thread_create (token, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR) {
		free(fn_copy);
		free(fn_for_tok);
    }
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
  
	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
    /*** hyeRexx ***/
    /* replace 4th argument : thread_current() to if_ */
	tid_t child = thread_create (name, PRI_DEFAULT, __do_fork, if_);
    if(child == TID_ERROR) return TID_ERROR;
    struct thread *child_t = get_child_process(child);

    sema_down(&child_t->fork_sema);
    
    /*** error check ***/    
    if(child_t->fork_flag == TID_ERROR) return TID_ERROR;
    return child;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kern_pte(pte)) {
		return true; /*** debugging genie ***/
	}

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER); // debugging sanori - 이거 get frame으로 나중에 바꿔줘야할듯

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/*** hyeRexx ***/
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *curr_thread = thread_current ();
    /*** hyeRexx ***/
	struct thread *parent = curr_thread->parent; // perent thread implecated
	struct intr_frame *parent_if = aux; // parent aux implecated
	// bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	curr_thread->pml4 = pml4_create();
	if (curr_thread->pml4 == NULL)
		goto error;

	process_activate (curr_thread);
#ifdef VM
	supplemental_page_table_init (&curr_thread->spt);
	if (!supplemental_page_table_copy (&curr_thread->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

    /*** hyeRexx : duplicate files ***/
    for(int fd = curr_thread->fd_edge; fd < parent->fd_edge; fd = ++(curr_thread->fd_edge)) 
    {
        if(parent->fdt[fd] == NULL) continue;
        curr_thread->fdt[fd] = file_duplicate(parent->fdt[fd]);
        if(curr_thread->fdt[fd] == NULL) goto error;
    }

    /*** debugging genie : fork_flag 순서!! ***/
    ASSERT(curr_thread->fd_edge == parent->fd_edge);
    curr_thread->fork_flag = 0;
    sema_up(&curr_thread->fork_sema);

	process_init ();
    if_.R.rax = 0; // return to child's fork

    do_iret (&if_);

error:
    curr_thread->fork_flag = -1;
    curr_thread->exit_status = -1;
    sema_up(&curr_thread->fork_sema);
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	char **args_parsed = calloc(64, sizeof(char *));
	// char **args_parsed = palloc_get_page(0);
	char *save_ptr;
	char *arg;
	int arg_count;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/*** Jack ***/
	/* Parsing file_name */ 
	arg_count = 0;
	for (arg = strtok_r(f_name, " ", &save_ptr); arg != NULL; arg = strtok_r(NULL, " ", &save_ptr))
		args_parsed[arg_count++] = arg;

	/* We first kill the current context */
	process_cleanup ();
	/* And then load the binary */
	success = load (args_parsed[0], &_if);

	/* If load failed, quit. */
	if (!success)
    {
		free(file_name);
		free(args_parsed);
	    // palloc_free_page(file_name);
	    // palloc_free_page(args_parsed);
		return -1;
    }

	/*** Jack ***/
	/* Set arguments to interrupt frame */
	argument_stack(args_parsed, arg_count, &_if);
	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

/*** GrilledSalmon ***/
/* parse된 string(arg) 정보를 user_stack에 쌓아주는 함수 */
void argument_stack (char **parse, int count, struct intr_frame *_if)
{	
	char *now_loc = _if->rsp;			// 스택에 넣어줄 위치
	char **now_loc_casted;
	int now_arg = count;
	size_t now_str_len;
	char *argp_arr[count];				// arg가 저장된 스택의 포인터 array

	/* argv 값 넣어주기 */
	while (now_arg-- > 0) {				// debugging할 때 참고
		now_str_len = strlen(parse[now_arg]);
		now_loc -= now_str_len + 1;
		argp_arr[now_arg] = now_loc;
		strlcpy(now_loc, parse[now_arg], now_str_len + 1);
	}
	memset((char *)((uint64_t)now_loc & (~7)), 0, (uint64_t)now_loc - (uint64_t)now_loc & (~7));
	now_loc = (uint64_t)now_loc & (~7);					// word align
	now_loc_casted = (char **)now_loc;			// 이후 연산(포인터 저장)을 위해 type casting - 새 변수로 casting

	/* arg의 마지막 NULL로 */
	now_loc_casted--;
	*now_loc_casted = NULL;

	now_arg = count;
	while (now_arg-- > 0){
		now_loc_casted--;
		*now_loc_casted = argp_arr[now_arg];
	}
	
	/* _if rdi, rsi 갱신 */
	_if->R.rdi = (uint64_t)count;		// argc
	_if->R.rsi = (uint64_t)now_loc_casted;		// argv

	/* retrun address */
	now_loc_casted--;
	*now_loc_casted = NULL;

	/* _if rsp 갱신 */
	_if->rsp = (uint64_t)now_loc_casted;
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/*** Jack ***/
	struct thread *child = get_child_process(child_tid);
	int ret_exit_status=NULL;
	if (child == NULL)
		return -1;

	// debugging genie : 사실, 이미 자식이 죽어있다면 exit_sema를 1로 올려주었을거라 확인문 없이 sema down만 해도 문제는 없을듯함.
	while (!child->is_exit)		
		sema_down(&(child->exit_sema));
	
	ret_exit_status = child->exit_status;
	remove_child_process(child);

	return ret_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();

/*** debugging genie ***/

	/*** debugging genie : project IV :: msg ***/
    /*** check whether curr is user or kernel, print msg when it is user. ***/
    if(curr->pml4 != NULL)
	    printf("%s: exit(%d)\n", curr->name, curr->exit_status); 

	/*** Jack ***/
	/*** Cleanup resources related to file system ***/
	int curr_fd_edge;
	struct file *curr_f;
	for (curr_fd_edge = thread_current()->fd_edge - 1; curr_fd_edge >= 2; curr_fd_edge--)
		process_close_file(curr_fd_edge);
	palloc_free_page(thread_current()->fdt);	// 할당받은 fdt page 반납
	thread_current()->fdt = NULL;				// 명시적 NULL

	/* Cleanup resources releated to virtual memory */
	process_cleanup ();

	/* Close running file of current thread */
	if (curr->running_file)
	{
		file_lock_acquire(curr->running_file);
		file_close(curr->running_file);
		file_lock_release(curr->running_file);
	}
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	// /* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {  
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/*** Jack ***/
	/* renew running file of current thread */
	if (t->running_file)
	{
		file_lock_acquire(t->running_file);
		file_close(t->running_file);
		file_lock_release(t->running_file);
	}
	file_lock_acquire(file);
	t->running_file = file;
	file_deny_write(file);
	file_lock_release(file);
	
	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file); -> 실행 중에 파일 수정 방지 위해 file_deny_write후 프로그램 종료시 파일 close위해 현재 라인 주석처리
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

/* prj3 - Anonymous Page, yeopto */
struct segment {
	struct file *file;
	off_t ofs;
	uint32_t read_bytes;
	uint32_t zero_bytes;
};

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	/* Jack */
	struct segment *load_src = aux;
	struct file *file = load_src->file;
	off_t ofs = load_src->ofs;
	uint32_t read_bytes = load_src->read_bytes;
	uint32_t zero_bytes = load_src->zero_bytes;
	void *kva = page->frame->kva;
	
	if (file_read_at(file, kva, read_bytes, ofs) != (int) read_bytes)
		return false;
	memset (kva + read_bytes, 0, zero_bytes);
	
	free(load_src);
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		/* prj3 - Anonymous Page, yeopto */
		struct segment *segment = malloc(sizeof(struct segment));
		segment->file = file;
		segment->ofs = ofs;
		segment->read_bytes = page_read_bytes;
		segment->zero_bytes = page_zero_bytes;
		
		/* prj3 - Anonymous Page, yeopto */
		void *aux = segment;

		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* prj3 - Anonymous Page, yeopto */
		ofs += page_read_bytes;
		
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	
	/* prj3 - Anonymous Page, yeopto */
	vm_alloc_page_with_initializer(VM_ANON | VM_STACK, stack_bottom, 1, NULL, NULL);
	success = vm_claim_page(stack_bottom);
	/* prj3 - Anonymous Page, yeopto */
	if (success) {
		if_->rsp = USER_STACK; 
	}
	
	return success;
}
#endif /* VM */

#ifdef USERPROG
/*** Jack ***/
/*** Return file table pointer matched by fd in file descriptor table of current thread  ***/
struct file *process_get_file(int fd)
{
	// ASSERT (fd >= 0); // debugging genie : fd이 음수일 경우 종료시킬건지 NULL 리턴해줄건지
    if(fd > 128 || fd < 0) return NULL; /*** DEBUGGINT GENIE PHASE 2 ***/

	return thread_current()->fdt[fd];
}

/*** Close file ***/
void process_close_file (int fd)
{
	// ASSERT (fd >= 0); // debugging genie : fd이 음수일 경우 종료시킬건지 NULL 리턴해줄건지
	if(fd > 128 || fd < 0) return; /*** DEBUGGINT GENIE PHASE 2 ***/

	struct file *f = thread_current()->fdt[fd];
	if (f == NULL)
		return;

	file_close(f);
	thread_current()->fdt[fd] = NULL;
}

/*** hyeRexx ***/
int process_add_file(struct file *f)
{
    struct thread *curr_thread = thread_current(); // current thread
    int new_fd = curr_thread->fd_edge++;    // get fd_edge and ++
    ASSERT(new_fd > 1);
	if (new_fd > 128)
		return -1;
    curr_thread->fdt[new_fd] = f;    // set *new_fd = new_file

    return new_fd;
}

/*** Jack ***/
/* Return child process pointer who is having 'tid' in child list */
struct thread *get_child_process (int pid)
{
	struct list *child_list = &(thread_current()->child_list);
	struct thread *curr_thread;
	struct list_elem *curr_elem;
	struct thread *ret_thread = NULL;

	for (curr_elem = list_begin(child_list); curr_elem != list_tail(child_list); curr_elem = list_next(curr_elem))
	{
		curr_thread = list_entry(curr_elem, struct thread, c_elem);
		if (curr_thread->tid == pid)
		{
			ret_thread = curr_thread;
			break;
		}
	}
	return ret_thread;
}

/*** Jack ***/
/* Remove child process from child list of its parent and Free its memory */
void remove_child_process(struct thread *cp)
{
	ASSERT (cp != NULL);
	ASSERT (cp->parent == thread_current());
	ASSERT (!list_empty(&(thread_current()->child_list)))
	ASSERT (cp->c_elem.next != NULL || cp->c_elem.prev != NULL)
	
	list_remove(&(cp->c_elem));
	palloc_free_page(cp);
	return;
}

#endif // USERPROG