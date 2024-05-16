/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"
#include "threads/malloc.h"
#include "vm/inspect.h"
#include "threads/mmu.h"

struct list frame_list;

// #define VA_MASK(va) (((uint64_t)va) & ~0xFFF)

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
        newPage->is_writable = writable;

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
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
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
        // victim_frame = vm_evict_frame();
        // frame->kva = palloc_get_page(PAL_USER);
        PANIC("todo");
    }

    list_push_back(&frame_list, &frame->elem);

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = spt_find_page(spt, addr);
    /* TODO: Validate the fault */
    if (!page)
        return false; // ㄹㅇ 폴트

    /* TODO: Your code goes here */

    return vm_do_claim_page(page);
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
    if (!pml4_set_page(curr->pml4, page->va, frame->kva, page->is_writable))
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
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
}

uint64_t page_hash_func(const struct hash_elem *e, void *aux) {
    struct page *p = hash_entry(e, struct page, hash_elem);
    // p->va = VA_MASK(p->va);
    return hash_bytes(&p->va, sizeof *p->va);
}

bool page_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct page *p_a = hash_entry(a, struct page, hash_elem);
    struct page *p_b = hash_entry(b, struct page, hash_elem);
    return p_a->va < p_b->va;
}