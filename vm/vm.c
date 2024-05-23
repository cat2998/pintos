/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"
#include "threads/malloc.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include <string.h>

struct list frame_list;
struct lock frame_lock;

void clear_spt_hash(struct hash_elem *hash_elem, void *aux);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    list_init(&frame_list);
    lock_init(&frame_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {

    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        bool (*new_initializer)(struct page *, enum vm_type, void *) = NULL;
        struct page *newPage = calloc(1, sizeof *newPage);
        if (!newPage)
            return false;

        if (VM_TYPE(type) == VM_ANON)
            new_initializer = anon_initializer;
        else if (VM_TYPE(type) == VM_FILE)
            new_initializer = file_backed_initializer;

        uninit_new(newPage, upage, init, type, aux, new_initializer);
        newPage->is_page_writable = writable;

        /* TODO: Insert the page into the spt. */
        spt_insert_page(spt, newPage);

        return true;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    struct page *page = NULL;
    struct page _page;
    struct hash_elem *hash_elem;

    _page.va = pg_round_down(va);

    hash_elem = hash_find(&spt->spt_hash, &_page.hash_elem);

    if (!hash_elem)
        return NULL;
    page = hash_entry(hash_elem, struct page, hash_elem);
    return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    int succ = false;
    struct hash_elem *h_elem;

    h_elem = hash_insert(&spt->spt_hash, &page->hash_elem);
    if (!h_elem)
        succ = true;
    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void) {
    struct frame *victim = NULL;
    struct list_elem *e;
    /* TODO: The policy for eviction is up to you. */

    lock_acquire(&frame_lock);
    for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e)) {
        victim = list_entry(e, struct frame, elem);
        if (!pml4_is_accessed(thread_current()->pml4, victim->page->va)) {
            lock_release(&frame_lock);
            return victim;
        }
        pml4_set_accessed(thread_current()->pml4, victim->page->va, false);
    }
    victim = list_entry(list_begin(&frame_list), struct frame, elem);
    lock_release(&frame_lock);

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void) {
    struct frame *victim = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */
    if (!swap_out(victim->page))
        return NULL;

    lock_acquire(&frame_lock);
    list_remove(&victim->elem);
    lock_release(&frame_lock);

    memset(victim->kva, 0, PGSIZE);
    victim->page = NULL;
    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = NULL;

    frame = calloc(1, sizeof *frame);
    if (!frame)
        PANIC("todo");

    frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
    if (!frame->kva) {
        free(frame);
        frame = vm_evict_frame();
    }

    lock_acquire(&frame_lock);
    list_push_back(&frame_list, &frame->elem);
    lock_release(&frame_lock);

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED) {
    void *stack_bottom = thread_current()->stack_bottom;

    while (stack_bottom > addr) {
        stack_bottom = (void *)(((uint8_t *)stack_bottom) - PGSIZE);

        if (!vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1))
            return;

        if (!vm_claim_page(stack_bottom))
            return;
    }
    thread_current()->stack_bottom = stack_bottom;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */

    if (not_present) { // frame없어

        if (thread_current()->stack_bottom > addr && addr > USER_STACK - (1 << 20)) { // Are you stack? page 없어?
            void *user_rsp = thread_current()->user_rsp;
            if (user)
                user_rsp = f->rsp;
            if (user_rsp == addr || user_rsp - 8 == addr) {
                vm_stack_growth(addr);
                return true;
            }
            return false;
        }

        page = spt_find_page(spt, addr);
        if (!page) {      // page 없어, frame 없어
            return false; // ㄹㅇ 폴트
        }

        return vm_do_claim_page(page); // page찾으면 레이지로딩
    }

    page = spt_find_page(spt, addr);

    if(page && page->is_parent_writable)
    {
        void *parent_kva = page->frame->kva;

        page->is_page_writable = true;
        vm_do_claim_page(page);
        memcpy(page->frame->kva, parent_kva, PGSIZE);
        return true;
    }
    

    /* TODO: Your code goes here */
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
    struct page *page = NULL;

    /* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt, va);
    if (!page)
        return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
    struct thread *curr = thread_current();
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(curr->pml4, page->va, frame->kva, page->is_page_writable))
        return false;

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    hash_init(&thread_current()->spt.spt_hash, page_hash_func, page_hash_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    hash_first(&i, &src->spt_hash);
    while (hash_next(&i)) {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        struct page *dst_page;

        enum vm_type type = src_page->operations->type;

        if (VM_TYPE(type) == VM_UNINIT) {
            // struct lazy_load_aux *aux = calloc(1, sizeof(struct lazy_load_aux));
            // memcpy(aux, src_page->uninit.aux, sizeof(struct lazy_load_aux));
            // if (!vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->is_writable, src_page->uninit.init, aux))
            if (!vm_alloc_page_with_initializer(src_page->uninit.type, src_page->va, src_page->is_page_writable, src_page->uninit.init, src_page->uninit.aux))
            {
                dst_page = spt_find_page(dst, src_page->va);
                return false;
            }
        } else {
            if (!vm_alloc_page(type, src_page->va, 0))
                return false;
            // if (!vm_claim_page(src_page->va))
                // return false;
            dst_page = spt_find_page(dst, src_page->va);
            dst_page->is_parent_writable = src_page->is_page_writable;
            dst_page->frame = src_page->frame;
            dst_page->frame->indegree_cnt += 1;
            pml4_set_page(thread_current()->pml4, dst_page->va, src_page->frame->kva, 0);
            // memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
        }
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->spt_hash, clear_spt_hash);
}

void clear_spt_hash(struct hash_elem *hash_elem, void *aux) {
    struct page *delete_page = hash_entry(hash_elem, struct page, hash_elem);
    // if (delete_page)
    vm_dealloc_page(delete_page);
}

uint64_t page_hash_func(const struct hash_elem *e, void *aux) {
    struct page *p = hash_entry(e, struct page, hash_elem);

    return hash_bytes(&p->va, sizeof *p->va);
}

bool page_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct page *p_a = hash_entry(a, struct page, hash_elem);
    struct page *p_b = hash_entry(b, struct page, hash_elem);
    return p_a->va < p_b->va;
}

void delete_frame(struct frame *frame) {
    ASSERT(frame != NULL);
    ASSERT(frame->page != NULL);
    if(frame->indegree_cnt > 0) {
        frame->indegree_cnt -= 1;
        return;
    }
    lock_acquire(&frame_lock);
    list_remove(&frame->elem);
    lock_release(&frame_lock);
    palloc_free_page(frame->kva);
    free(frame);
}