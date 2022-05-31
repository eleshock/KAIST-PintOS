#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

/*** Jack ***/
#include <filesys/filesys.h>
#include <filesys/file.h>
#include <userprog/process.h>

/*** GrilledSalmon ***/
#include "threads/init.h"				

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);						/*** GrilledSalmon ***/
void exit (int status);					/*** GrilledSalmon ***/

/*** Phase 1 ***/
/*** Jack ***/
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int filesize (int fd);
void seek (int fd, unsigned position);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/*** hyeRexx ***/
/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) 
{
    int64_t syscall_case = f->R.rax;
    ASSERT(is_user_vaddr(f->rsp)); // rsp 유저 영역에 있는지 확인
    
	switch (syscall_case)
    {
        case SYS_HALT :
            halt();
            break;
        
        case SYS_EXIT :
            exit(f->R.rdi);
            break;
        
        case SYS_FORK : 
            break;
        
        case SYS_EXEC :
            break;
        
        case SYS_WAIT :
            break;
        
        case SYS_CREATE : 
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;

        case SYS_REMOVE :
            f->R.rax = remove(f->R.rdi);
            break;
        
        case SYS_OPEN :
            break;

        case SYS_FILESIZE : /*** debugging genie : phase 2 ***/
            f->R.rax = filesize(f->R.rdi);
            break;

        case SYS_READ :
            break;
        
        case SYS_WRITE : 
            break;
        
        case SYS_SEEK : // Jack
            seek(f->R.rdi, f->R.rsi);
            break;
        
        case SYS_TELL :
            break;
        
        case SYS_CLOSE :
            break;        
    }
	printf ("system call!\n");
    
	do_iret(f);
	NOT_REACHED();
}

/*** debugging genie ***/
void 
check_address(void *vaddr) 
{
	if (is_kernel_vaddr(vaddr) || vaddr == NULL || pml4_get_page (thread_current()->pml4, vaddr) == NULL)
    {
	    exit(-1); // terminated
    }
}

/*** Jack ***/
bool create (const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

/*** Jack ***/
bool remove (const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

/*** Jack ***/
int filesize (int fd)
{
    ASSERT(fd >= 0);

	struct file *f = thread_current()->fdt[fd]; // debugging genie
    ASSERT(f != NULL);

	return file_length(f); 
}

/*** GrilledSalmon ***/
/* Power off the Pintos system.
 * The user will barely use this syscall function. */
void halt (void)
{
	power_off();			/* Power off */
}

/*** GrilledSalmon ***/
/* Process exit */
void exit (int status)
{	
	struct thread *curr_thread = thread_current();
	
	/*** debugging genie : project IV :: msg ***/
	printf("나 %s... 썩 좋은 삶이었다... (exit_status : %d)\n", curr_thread->name, status); 

	/*** Develope Genie ***/
	/* 자신을 기다리는 부모가 있는 경우 status와 함께 신호 보내줘야 함!! */

	thread_exit();			/* 현재 쓰레드의 상태를 DYING 으로 바꾸고 schedule(다음 쓰레드에게 넘겨줌) */
}

/*** Jack ***/
/* Change offset from origin to 'position' */
void seek (int fd, unsigned position)
{
    ASSERT(fd >= 0);
    ASSERT (position >= 0);

    struct file* f = process_get_file(fd);
    ASSERT (f != NULL);
    
    file_seek(f, position);
    return;
}