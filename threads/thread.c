#include "threads/thread.h"
#include "threads/fixed_point.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
// #include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "list.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* for MLFQS */					/*** GrilledSalmon ***/
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

static int load_avg;					/*** GrilledSalmon ***/

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/*** Jack ***/
/* List of threads in THREAD_BLOCK state because they called "timer_sleep" */
static struct list sleep_list;

/*** hyeRexx ***/
/* List contains ALL threads */
struct list integrated_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/*** Jack ***/
int64_t next_tick_to_awake = INT64_MAX;

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the global thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&sleep_list); /*** Jack ***/
    list_init(&integrated_list); /*** hyeRexx ***/
	list_init(&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();

    /*** hyeRexx ***/
    initial_thread->nice = NICE_DEFAULT;
    initial_thread->recent_cpu = RECENT_CPU_DEFAULT;
}

/*** hyeRexx ***/
void thread_awake(int64_t ticks)
{
	struct list_elem *curr;
	struct list_elem *temp;
	struct thread *curr_thread;
	int64_t min_ticks = INT64_MAX;

	for (curr = list_begin(&sleep_list); curr != list_tail(&sleep_list); curr = list_next(curr))
	{
		curr_thread = list_entry(curr, struct thread, elem);
		if (curr_thread->wakeup_tick <= ticks)
		{
			curr_thread->status = THREAD_READY; // 참조중인 스레드 상태 변경 (READY)
			temp = list_remove(curr);			// 참조중인 스레드를 포함된 리스트에서 제거, temp = curr->next(sleep_list)
			list_insert_ordered(&ready_list, curr, cmp_priority, NULL);	// 참조중인 스레드를 ready_list에 push
			// list_push_back(&ready_list, curr);	// 참조중인 스레드를 ready_list에 push
			curr = list_prev(temp);				// curr = temp->prev
		}
		else // min_ticks update
		{
			if ((curr_thread->wakeup_tick) <= min_ticks)
			{
				min_ticks = curr_thread->wakeup_tick;
			}
		}
	}
	update_next_tick_to_awake(min_ticks);
	return;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	thread_create("idle", PRI_MIN, idle, &idle_started);
	load_avg = LOAD_AVG_DEFAULT;			/*** GrilledSalmon ***/

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current(); // thread

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else{
		kernel_ticks++;
		if (thread_mlfqs) {
			mlfqs_increment();
		}
	}
		
	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
        /*** hyeRexx ***/
        // Update curr thread priority
        if (thread_mlfqs && !(thread_ticks % 4))
        { 
            mlfqs_priority(t);
        }
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */

/*** hyeRexx ***/
tid_t thread_create(const char *name, int priority, thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR; // 할당 실패

	/* Initialize thread. */
	init_thread(t, name, priority); // 들어온 priority로 초기화
	tid = t->tid = allocate_tid();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument.

     *** hyeRexx ***
     * RSI(Extended Source Index) / RDI(Extended Destination Index)
     * 각 메모리 출발지와 목적지를 나타냄. 고속 메모리 전송 명령어에서 사용
     * 이 부분은 인터럽트 초기화인듯..? */
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

    /* Add to run queue. */
	thread_unblock(t);

    /*** hyeRexx ***/
    ASSERT(t->status == THREAD_READY); // 언블락 잘 되었는지 확인
    /* 만약 priority가 실행중인 priority보다 높다면 바로 cpu 점유하기 */
    test_max_priority();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t)
{
	enum intr_level old_level;

	ASSERT(is_thread(t));

	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);
    
    /*** hyeRexx ***/
    // pushback >>>> insertOredered로 수정, cmp_priority 전달 확인 필요
    list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
	t->status = THREAD_READY;
	intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread(); // 

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void)
{
	struct thread *curr = thread_current();
	enum intr_level old_level;

	ASSERT(!intr_context());

	old_level = intr_disable();
	if (curr != idle_thread)
		list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL); // JACK
	do_schedule(THREAD_READY);
	intr_set_level(old_level);
}

/*** GrilledSalmon ***/
/* 현재 스레드 재우기
 * input - awake_ticks : 깨울 시간 */
void thread_sleep(int64_t awake_ticks)
{
	enum intr_level old_level;
	struct thread *curr = thread_current(); // 현재 run 상태인 thread 받아 오기

	ASSERT(curr != idle_thread); // 재워질 스레드는 idle_thread가 아니어야 한다?

	old_level = intr_disable(); // interrupt 못들어오게 막아주기

	// ready_list에서 빼주기. <- 이미 실행된 쓰레드는 readylist에 없어서 추출 불필요함
	// list_remove(&curr->elem);
	list_push_back(&sleep_list, &curr->elem); // 현재 thread를 sleep_list의 끝에 추가

	curr->wakeup_tick = awake_ticks; // 깨울 시간 저장

	if (next_tick_to_awake > awake_ticks)
	{
		update_next_tick_to_awake(awake_ticks); // 최소 시간 업데이트
	}

	thread_block(); // 현재 thread block으로 바꾸고 schedule 진행

	intr_set_level(old_level); // interrupt 활성화
}

/*** GrilledSalmon ***/
/* 현재 실행중인 thread의 우선순위가 ready_list의 최우선순위 thread보다 높은지 확인하고
 * 자신이 더 낮다면 yield */
void test_max_priority(void)
{
	
	if (list_empty(&ready_list)) { // ready_list가 비어있을 땐 그냥 리턴
		return;
	}

	struct thread *curr = thread_current();
	struct thread *first_thread = list_entry(list_begin(&ready_list), struct thread, elem); // ready_list에서 우선순위가 가장 높은 thread
	
	if (curr->priority < first_thread->priority)   // 현재 thread의 우선순위가 더 낮다면
	{
		thread_yield(); 						   // 양보!
	}
}

/*** GrilledSalmon ***/
/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority)
{	
	/* MLFQS로 실행되는 상황엔 작동하지 않도록 */
	if (thread_mlfqs){  /*** GrilledSalmon ***/
		return ;
	}

	ASSERT((PRI_MIN <= new_priority) && (new_priority <= PRI_MAX) ); // 갱신해줄 우선순위가 범위 안에 있는지 확인

	// Jack _ original만 갱신하기 위해 기존 priority 갱신부분 삭제
	thread_current()->original_priority = new_priority; // Jack _ original만 갱신한 뒤
	refresh_priority(); // Jack _ donation 여부 확인하여 priority 갱신함

	test_max_priority(); 			// 우선순위가 갱신됐으니, 현재 thread가 가장 높은 우선순위인지 확인
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) // JACK
{
	// ASSERT(nice != NULL);

	enum intr_level old_level;

	old_level = intr_disable();
	thread_current()->nice = nice;
	intr_set_level(old_level);
	
	return;
}


/* Returns the current thread's nice value. */
int thread_get_nice(void) // JACK
{
	enum intr_level old_level;
	int curr_nice;

	old_level = intr_disable();
	curr_nice = thread_current()->nice;
	intr_set_level(old_level);
	
	return curr_nice;
}

/*** GrilledSalomn ***/
/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
	enum intr_level old_level = intr_disable();
	int thread_load_avg = fp_to_int(mult_mixed(load_avg, 100));
	intr_set_level(old_level);
	
	return thread_load_avg;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) // JACK
{
	enum intr_level old_level;
	int curr_recent_cpu;
    int return_val;

	old_level = intr_disable();
	curr_recent_cpu = thread_current()->recent_cpu;
	intr_set_level(old_level);
    return_val = fp_to_int(mult_mixed(curr_recent_cpu, 100));

	return return_val;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt"
					 :
					 :
					 : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
}

/*** GrilledSalmon ***/
/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);
 
	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->original_priority = priority;	/*** GrilledSalmon ***/
	t->magic = THREAD_MAGIC;
	t->wait_on_lock = NULL;				/*** GrilledSalmon ***/
	t->nice = running_thread()->nice; // Jack - thread가 맨 처음에 만들어질때 nice값이 0으로 되어있고, 그 이후는 쓰레드를 만드는 쓰레드의 nice값을 따라가야함
	t->recent_cpu = running_thread()->recent_cpu; // Jack  - 이 또한 맨 처음 만들어지는 thread는 0 이나 이후에는 생성시키는 쓰레드의 값을 따라감
	list_push_back(&integrated_list, &t->i_elem); // Jack - 총괄 리스트에 추가
	// ASSERT(t->nice != NULL); // Jack - nice값이 계속 쓰레드를 만드는 쓰레드의 nice값을 잘 따라가고 있다면 NULL이면 안됨.
	// ASSERT(t->recent_cpu != NULL); // Jack - 동일 근거.
	list_init(&t->donator_list);			/*** GrilledSalmon ***/
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n"
		"iretq"
		:
		: "g"((uint64_t)tf)
		: "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		"pop %%rbx\n" // Saved rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // read the current rip.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		:
		: "g"(tf_cur), "g"(tf)
		: "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status)
{
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(thread_current()->status == THREAD_RUNNING);
	while (!list_empty(&destruction_req))
	{
		struct thread *victim =
			list_entry(list_pop_front(&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule();
}

static void
schedule(void)
{
	struct thread *curr = running_thread();
	struct thread *next = next_thread_to_run();

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(curr->status != THREAD_RUNNING);
	ASSERT(is_thread(next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next);
#endif

	if (curr != next)
	{
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_remove(&curr->i_elem); // Jack : 쓰레드 루틴 끝나면 총괄 리스트에서도 빼줌.
			list_push_back(&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}

/* Update next tick to awake */
void update_next_tick_to_awake(int64_t ticks)
{
	next_tick_to_awake = ticks;
}

/* Returns tick to awake next */
int64_t get_next_tick_to_awake(void)
{
	return next_tick_to_awake;
}

/*** JACK ***/
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	return thread_a->priority > thread_b->priority;
}

/*** hyeRexx ***/
void refresh_priority(void) {
    struct thread *curr = thread_current(); // check curr thread
    ASSERT(curr != NULL); 

    curr->priority = curr->original_priority; // 우선 원복

    if(!list_empty(&curr->donator_list)) // empty로 수정
    {   // 대기열 중 맨 앞 thread의 priority 추출 : donator_list
        struct thread *best = list_entry(list_begin(&curr->donator_list), struct thread, d_elem);
        ASSERT(best != NULL); // added
        curr->priority = best->priority;      
    }
    return;
}

/*** Jack ***/
/*** Lock Acquire 요청하였으나 다른 쓰레드가 홀드하고 있는 경우
 * 해당 holder부터 시작해서 순회하면서 priority를 기부해줌 ***/
void donate_priority(void)
{
	// donate한다는건 누군가 락을 쥐고있어서 기다려야하므로 이전에 입력되어있어야 함
    ASSERT(thread_current()->wait_on_lock != NULL); 
	// wait_on_lock에 등록되어있다는건 holder가 쥐고있다는 의미. holder가 없다면 wait_on_lock은 reset되어있어야함
    ASSERT(thread_current()->wait_on_lock->holder != NULL); 

    struct thread *curr_thread = thread_current();
    struct thread *curr_holder = curr_thread->wait_on_lock->holder;
   
    for (int i=0; i < NESTED_MAX_DEPTH; i++) // max nested depth is 8
    {
    	curr_holder->priority = curr_thread->priority; // priority donation
    	if (!curr_holder->wait_on_lock) // 8이 되기 전에 더이상 nested되지 않았다면 끝
    		break;
		// wait_on_lock에 lock을 기다린다고 되어있다면 반드시 그 lock의 홀더가 있어야하므로 임시 ASSERT 추가
		ASSERT(curr_holder->wait_on_lock->holder != NULL);
    	curr_holder = curr_holder->wait_on_lock->holder;
    }
   list_sort(&ready_list, cmp_priority, NULL); // donation으로 인한 ready_list 우선순위 변동으로 sort 필요
}

/*** Jack ***/
/*** Lock Release시 Donation list 갱신 ***/
void refresh_donator_list(struct lock *lock)
{
    ASSERT(lock != NULL); // 입력 확인

	struct list *curr_dona_li = &(thread_current()->donator_list);
	struct list_elem *curr_d_elem; // 순회용
	struct list_elem *temp; // 리스트에서 제거시 순회용 elem 수정위해 임시 저장

	for (curr_d_elem = list_begin(curr_dona_li); curr_d_elem != list_tail(curr_dona_li); curr_d_elem = list_next(curr_d_elem))
	{
		struct thread *curr_thread = list_entry(curr_d_elem, struct thread, d_elem); // d_elem으로부터 thread 추출
		if (curr_thread->wait_on_lock == lock) // 해당 thread가 기다리는 lock이 현재 release하는 lock이면 donator list에서 제거
		{
			temp = list_remove(curr_d_elem);
			curr_d_elem = list_prev(temp); // 제거 후 순회용 elem 복구
		}
	}
}


/*** GrilledSalmon ***/
void mlfqs_load_avg(void)
{
	int ready_threads = 1; // 실행 중인 thread 포함
	struct list_elem *curr_elem = list_begin(&ready_list);

	while (curr_elem != list_tail(&ready_list)) {
		ready_threads++;
		curr_elem = list_next(curr_elem);
	}

	load_avg = mult_fp(div_mixed(int_to_fp(59), 60), load_avg) + mult_mixed(div_mixed(int_to_fp(1), 60), ready_threads);
		
	if (fp_to_int(load_avg) < 0){ // load_avg는 0보다 작아질 수 없다.
		load_avg = LOAD_AVG_DEFAULT;
	}
}

/*** GrilledSalmon ***/
void mlfqs_increment(void)
{
	struct thread *curr_thread = thread_current();

	if (curr_thread != idle_thread) {
		curr_thread->recent_cpu = add_mixed(curr_thread->recent_cpu, 1);
	}
}

/*** hyeRexx ***/
/* Calculate thread priority */
void mlfqs_priority(struct thread *t)
{
    ASSERT(t != NULL);
    ASSERT(t != idle_thread);

    int recent_cpu_fp = t->recent_cpu;
    int nice_fp = int_to_fp(t->nice);
    int div = div_mixed(recent_cpu_fp, 4);
    int mul = mult_mixed(nice_fp, 2);

    t->priority = fp_to_int(int_to_fp(PRI_MAX) - div - mul);
}


/* Iterate all threads and update their priority and recent cpu */
void mlfqs_recalc(void) 
{
    struct list_elem *ref_i; // referenced integrated list elem
    struct thread *ref_t;    // referenced thread contain ref_i
    
    mlfqs_load_avg();   // update load average

    // iterate integrated list and update priority and recent cpu 
    for(ref_i = list_begin(&integrated_list); ref_i != list_tail(&integrated_list); ref_i = list_next(ref_i)) {
        ref_t = list_entry(ref_i, struct thread, i_elem);
        if(ref_t == idle_thread) // filter out idle thread 
        {
            continue;
        }
        mlfqs_recent_cpu(ref_t); // update recent cpu ~~ Jack 확인
        mlfqs_priority(ref_t);   // update priority
    }

    list_sort(&ready_list, cmp_priority, NULL);
}

/*** Jack ***/
/*** thread t 의 recent_cpu를 재계산함 ***/
void mlfqs_recent_cpu(struct thread *t)
{
	ASSERT(t != NULL);
	ASSERT(t != idle_thread);
	
	// recent_cpu = ((2 * load_avg)/(2 * load_avg + 1)) * recent_cpu + nice
	int operand_up = mult_mixed(load_avg, 2); // (2 * load_avg)
	int operand_down = add_mixed(mult_mixed(load_avg, 2), 1); // (2 * load_avg + 1)
	int res_div = div_fp(operand_up, operand_down); // division
	int res_multi = mult_fp(res_div, t->recent_cpu); // multiply and round down
	t->recent_cpu = res_multi + int_to_fp(t->nice); // add nice and change
	
	return;

}

