/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);
bool lazy_load_file_back(struct page *page, void *aux);
/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    size_t read_bytes = length;
    void *upage = pg_round_down(addr);

    while (read_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        struct lazy_load_aux *aux = calloc(1, sizeof(struct lazy_load_aux));
        *aux = (struct lazy_load_aux){
            .file = file,
            .offset = offset,
            .page_read_bytes = page_read_bytes,
            .page_zero_bytes = page_zero_bytes,
            .mmap_addr = addr,
        };

        if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_load_file_back, (void *)aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        offset += page_read_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Do the munmap */
void do_munmap(void *addr) {
    
}

bool lazy_load_file_back(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */

    /* Load this page. */
    struct lazy_load_aux *llaux = aux;

    if (file_read_at(llaux->file, page->frame->kva + (llaux->mmap_addr - page->va), llaux->page_read_bytes, llaux->offset) != (int)llaux->page_read_bytes) {
        return false;
    }
    return true;
}