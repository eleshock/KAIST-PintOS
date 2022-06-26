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
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "lib/string.h"
#include "filesys/directory.h"
#include "filesys/fat.h"

/*** GrilledSalmon ***/
#include "threads/init.h"	
#include "userprog/process.h"
#include "devices/input.h"			// for 'input_getc()'
#include "kernel/stdio.h"

/* eleshock */
#include "vm/file.h"
#include "vm/vm.h"
#include "filesys/directory.h"
#include "filesys/inode.h"

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

int read (int fd, void *buffer, unsigned size); 	/*** GrilledSalmon ***/
int write (int fd, void *buffer, unsigned size);    /*** GrilledSalmon ***/
unsigned tell (int fd);                             /*** GrilledSalmon ***/

typedef int pid_t;
int wait (pid_t pid);                               /*** Jack ***/
int exec (const char *cmd_line);                    /*** Jack ***/

/*** hyeRexx : phase 3 ***/
pid_t fork(const char *thread_name, struct intr_frame *intr_f);

static struct lock filesys_lock;                    /*** GrilledSalmon ***/

/* eleshock */
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

/* eleshock */
bool readdir (int fd, char *name);
int inumber (int fd);

/* Jack */
bool mkdir (const char *dir);
int symlink (const char *target, const char *linkpath);

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
syscall_init (void)
{
    lock_init(&filesys_lock);       /*** GrilledSalmon ***/

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

    /* eleshock */
    thread_current()->if_rsp = f->rsp;

	switch (syscall_case)
    {
        case SYS_HALT :
            halt();
            break;
        
        case SYS_EXIT :
            exit(f->R.rdi);
            break;
        
        case SYS_FORK : 
            f->R.rax = fork(f->R.rdi, f);
            break;
        
        case SYS_EXEC :
            f->R.rax = exec(f->R.rdi);
            break;
        
        case SYS_WAIT :
            f->R.rax = wait(f->R.rdi);
            break;
        
        case SYS_CREATE : 
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;

        case SYS_REMOVE :
            f->R.rax = remove(f->R.rdi);
            break;
        
        case SYS_OPEN :
            f->R.rax = open(f->R.rdi); // returns new file descriptor
            break;

        case SYS_FILESIZE : /*** debugging genie : phase 2 ***/
            f->R.rax = filesize(f->R.rdi);
            break;

        case SYS_READ :
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        
        case SYS_WRITE :
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        
        case SYS_SEEK : // Jack
            seek(f->R.rdi, f->R.rsi);
            break;
        
        case SYS_TELL :
            f->R.rax = tell(f->R.rdi);
            break;
        
        case SYS_CLOSE :
            close(f->R.rdi);
            break;  

        case SYS_MMAP : // eleshock
            f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8); // debugging sanori - 인자 이거 맞음..?
            break;

        case SYS_MUNMAP : // eleshock
            munmap(f->R.rdi);
            break;

        case SYS_READDIR : // eleshock
            f->R.rax = readdir(f->R.rdi, f->R.rsi);
            break;

        case SYS_INUMBER : // eleshock
            f->R.rax = inumber(f->R.rdi);
            break;
      
        case SYS_ISDIR : // yeopto
            f->R.rax = isdir(f->R.rdi);
            break;
        
        case SYS_CHDIR : // yeopto
            f->R.rax = chdir(f->R.rdi);
            break;

        case SYS_MKDIR : // Jack
            f->R.rax = mkdir(f->R.rdi);
            break;

        case SYS_SYMLINK : // Jack
            f->R.rax = symlink(f->R.rdi, f->R.rsi);
            break;
    }
}

void 
check_address(void *vaddr) 
{
	// if (is_kernel_vaddr(vaddr) || vaddr == NULL || pml4_get_page (thread_current()->pml4, vaddr) == NULL)
    if (!is_user_vaddr(vaddr) || vaddr == NULL)
        exit(-1);
}

/*** Jack ***/
bool create (const char *file, unsigned initial_size)
{
	check_address(file);
#ifndef FILESYS
    return filesys_create(file, initial_size);
#else
    char file_name[15];
    struct dir *dir;

    if ((dir = find_dir_from_path(file, file_name)) == NULL)
        return false;

    bool success = true;
    struct dir *dir_bu = thread_current()->working_dir;
    thread_current()->working_dir = dir;
    success = filesys_create(file_name, initial_size);
    thread_current()->working_dir = dir_bu;
	return success;
#endif
}

/*** Jack ***/
bool remove (const char *file)
{
	check_address(file);
    
    char file_name[15];
    struct dir *dir;
    if ((dir = find_dir_from_path(file, file_name)) == NULL) return false;

    bool success;
    struct dir *bu_dir = thread_current()->working_dir;
    thread_current()->working_dir = dir;
    success = filesys_remove(file_name);
    thread_current()->working_dir = bu_dir;
	return success;
}

/*** Jack ***/
int filesize (int fd)
{
	struct file *f = process_get_file(fd);
    if (f == NULL)
        return -1;

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

#ifdef USERPROG
    curr_thread->exit_status = status;                  /*** Jack ***/
#endif

	/*** Develope Genie ***/
	/* 자신을 기다리는 부모가 있는 경우 status와 함께 신호 보내줘야 함!! */
    /* thread_exit -> process_exit 에서 sema up 해주도록 조치함 */

	thread_exit();			/* 현재 쓰레드의 상태를 DYING 으로 바꾸고 schedule(다음 쓰레드에게 넘겨줌) */
}

/*** hyeRexx ***/
/*** debugging genie : do we need to check sysout, sysin? ***/
int open(const char *file)
{
    check_address(file);                           // check validity of file ptr
    /* prj4 filesys - yeopto */
    char file_name[15];

    struct dir *found_dir;
    if ((found_dir = find_dir_from_path(file, file_name)) == NULL)
        return -1;

    struct dir *bu_dir = thread_current()->working_dir;
    thread_current()->working_dir = found_dir;
    struct file *now_file = filesys_open(file_name);    // file open, and get file ptr
    thread_current()->working_dir = bu_dir;

    if (!now_file) {
        return -1;
    }

    switch (inode_get_type(file_get_inode(now_file)))
    {
    case F_ORD:
        int fd = process_add_file(now_file);
        if (fd == -1)
            file_close(now_file);
        
        return fd; // return file descriptor for 'file'
        break;
    case F_DIR:
        struct dir *now_dir = dir_open(file_get_inode(now_file));
        file_set_dir(now_file, now_dir, true);

        int fd = process_add_file(now_file);
        if (fd == -1)
            file_close(now_file);
        
        return fd;
        break;
    case F_LINK:
        off_t length = file_length(now_file);
        char *real_path = calloc(1, length + 1);
        file_read(now_file, real_path, length);
        file_close(now_file);

        int ret = open(real_path);
        free(real_path);
        return ret;
        break;
    }
}

/*** hyeRexx ***/
void close(int fd)
{
    process_close_file(fd);
    return;
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

/*** GrilledSalmon ***/
int read (int fd, void *buffer, unsigned size)
{
    check_address(buffer);

    // buffer가 read only 인 경우에는 종료시키도록 확인 - Jack Debug
    struct page *p = spt_find_page(&thread_current()->spt, buffer);
    if (p != NULL && !p->writable)
        exit(-1);

    uint64_t read_len = 0;              // 읽어낸 길이

	if (fd == 0) { 			            /* fd로 stdin이 들어온 경우 */
        
        /*** extra할 때 수정된대유 ***/

        char *buffer_cursor = buffer;
        lock_acquire(&filesys_lock);    // debugging genie
        while (read_len < size)
        {
            *buffer_cursor++ = input_getc();
            read_len++;
        }
        *buffer_cursor = '\0';
        lock_release(&filesys_lock);
        return read_len;
	}

	struct file *now_file = process_get_file(fd);

    if (now_file == NULL || fd == 1){   // fd로 stdout이 들어왔거나 file이 없는 경우
        return -1;
    }

    lock_acquire(&filesys_lock);
    read_len = file_read(now_file, buffer, size);
    lock_release(&filesys_lock);
    return read_len;
}

/*** GrilledSalmon ***/
int write (int fd, void *buffer, unsigned size)
{
    check_address(buffer);

    if (fd == 1) {                      // fd == stdout인 경우
        lock_acquire(&filesys_lock);
        putbuf(buffer, size);
        lock_release(&filesys_lock);
        return size;
    }

    struct file *now_file = process_get_file(fd);

    if (now_file == NULL || fd == 0){   // fd로 stdin이 들어왔거나 file이 없는 경우
        return -1;
    }

    lock_acquire(&filesys_lock);
    uint64_t read_len = file_write(now_file, buffer, size);
    lock_release(&filesys_lock);

    return read_len;
}

/*** GrilledSalmon ***/
unsigned tell (int fd)
{
    struct file *now_file = process_get_file(fd);
    if (now_file == NULL) {
        return -1;
    }
    return file_tell(now_file);
}

/*** Jack ***/
int wait (pid_t pid)
{
    return process_wait(pid);
}

/*** Jack ***/
int exec (const char *cmd_line)
{
    check_address(cmd_line);

    char *cmd_copy = malloc(strlen(cmd_line)+2); // 메모리 효율성 위해 malloc으로 변경
    strlcpy(cmd_copy, cmd_line, strlen(cmd_line)+2);

    return process_exec(cmd_copy);
}

/*** hyeRexx ***/
pid_t fork (const char *thread_name, struct intr_frame *intr_f) // 파라미터 추가함
{
    check_address(thread_name);

    tid_t child = process_fork(thread_name, intr_f);
    return (child == TID_ERROR) ? TID_ERROR : child; 
}


/* eleshock */
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset)
{
    struct file *now_file = process_get_file(fd);
    bool chk_addr = (addr != NULL) && is_user_vaddr(addr); // debug
    return now_file && chk_addr? do_mmap(addr, length, writable, now_file, offset): NULL;
}

/* eleshock */
void munmap (void *addr)
{
    check_address(addr);
    do_munmap(addr);
}

/* eleshock */
bool readdir (int fd, char *name)
{
    if (!isdir(fd)) return false;
    
    struct file *now_file = process_get_file(fd);
    struct dir *dir = file_dir(now_file);
    return dir_readdir(dir, name);
}

/* eleshock */
int inumber (int fd)
{

    ASSERT(fd >= 0)

    struct file *now_file = process_get_file(fd);
    struct inode *inode = file_get_inode(now_file);
    
    ASSERT(inode != NULL)

    return inode_get_inumber(inode);
}

/* prj4 filesys - yeopto */
bool isdir (int fd) {
    struct file *now_file = process_get_file(fd);
    if (now_file == NULL) return false;    
    return file_isdir(now_file);
}

/* prj4 filesys - yeopto */
bool chdir (const char *dir) {
    char buffer[15];

    struct dir *new_dir = find_dir_from_path(dir, buffer);
    struct inode *inode;
    
    if (!dir_lookup(new_dir, buffer, &inode)) {
        dir_close(new_dir);
        return false;
    }
    if (inode_get_type(inode) == F_DIR) {
        struct dir *real_dir = dir_open(inode);
        dir_close(thread_current()->working_dir);
        thread_current()->working_dir = real_dir;
        dir_close(new_dir);
    } else {
        dir_close(new_dir);
        inode_close(inode);
        return false;
    }
    return true;
}

/* Jack */
bool mkdir (const char *dir)
{
    check_address(dir);
    bool success;
    
    char dir_name[15];
    struct dir *dir;
    
    if ((success = ((dir = find_dir_from_path(dir, dir_name)) != NULL)) == false)
        goto done;

    struct inode *chk_inode;
    if ((success = !dir_lookup(dir, dir_name, &chk_inode)) == false) {
        inode_close(chk_inode);
        dir_close(dir);
        goto done;
    }

    cluster_t inode_clst;
    if ((success = ((inode_clst = fat_create_chain(0)) != 0)) == false) {
        dir_close(dir);
        goto done;
    }

    success = dir_create(cluster_to_sector(inode_clst), 16) && dir_add(dir, dir_name, cluster_to_sector(inode_clst), F_DIR);
    if (!success) {
        dir_close(dir);
        fat_remove_chain(inode_clst, 0);
        goto done;
    }

    struct inode *dir_inode;
    struct dir *new_dir;
    dir_inode = inode_open(cluster_to_sector(inode_clst));
    new_dir =  dir_open(dir_inode);
    success = dir_add(new_dir, "..", dir_get_inumber(dir), F_DIR) && dir_add(new_dir, ".", dir_get_inumber(new_dir), F_DIR);
    if (!success) {
        dir_remove(dir, dir_name);
    }
	dir_close(dir);
        dir_close(new_dir);

done:
    return success;
}

/* Jack */
int symlink (const char *target, const char *linkpath)
{
    check_address(target);
    check_address(linkpath);

    int success = -1;

    struct dir *link_dir;
    char link_name[15];

    if ((link_dir = find_dir_from_path(linkpath, link_name)) == NULL)
        goto done;

    cluster_t link_clst;
    if ((link_clst = fat_create_chain(0)) == 0) {
        dir_close(link_dir);
        goto done;
    }

    if (!(inode_create(cluster_to_sector(link_clst), strlen(target) + 1) && dir_add(link_dir, link_name, cluster_to_sector(link_clst)))) {
        dir_close(link_dir);
        fat_remove_chain(link_clst, 0);
        goto done;
    }

    struct inode *link_inode = inode_open(cluster_to_sector(link_clst));
    if (link_inode != NULL) {
        inode_write_at(link_inode, target, strlen(target), 0);
        inode_close(link_inode);
        success = 0;
    } else {
        dir_remove(link_dir, link_name);
    }
    dir_close(link_dir);

done:
    return success;
}
