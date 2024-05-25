/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include "string.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);
bool lazy_load_file_back(struct page *page, void *aux);
extern struct lock file_lock;

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
    page->file.file = NULL;
    struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;
    if (!file_page->file) 
        return true;
    if (file_read_at(file_page->file, kva, file_page->page_read_bytes, file_page->ofs) != (int)file_page->page_read_bytes)
        return false;
    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
    struct thread *curr = thread_current();

    lock_acquire(&file_lock);
    if (pml4_is_dirty(curr->pml4, page->va)) {
        if (file_write_at(file_page->file, page->frame->kva, file_page->page_read_bytes, file_page->ofs) != file_page->page_read_bytes) {
            lock_release(&file_lock);
            return false;
        }
        pml4_set_dirty(curr->pml4, page->va, 0);
    }
    lock_release(&file_lock);

    page->frame = NULL;
    pml4_clear_page(curr->pml4, page->va);

    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page) {
    struct thread *curr = thread_current();
    struct file_page *file_page = &page->file;

    lock_acquire(&file_lock);
    if (pml4_is_dirty(curr->pml4, page->va)) {
        file_write_at(file_page->file, page->frame->kva, file_page->page_read_bytes, file_page->ofs);
        pml4_set_dirty(curr->pml4, page->va, 0);
    }

    pml4_clear_page(curr->pml4, page->va);
    lock_release(&file_lock);

    if (page->frame)
        delete_frame(page->frame);

    hash_delete(&curr->spt.spt_hash, &page->hash_elem);
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    size_t total_read_bytes = file_length(file) < length ? file_length(file) : length;
    void *upage = addr;

    while (total_read_bytes > 0) {
        size_t page_read_bytes = total_read_bytes < PGSIZE ? total_read_bytes : PGSIZE;

        struct lazy_load_aux *aux = calloc(1, sizeof(struct lazy_load_aux));
        *aux = (struct lazy_load_aux){
            .file = file,
            .offset = offset,
            .page_read_bytes = page_read_bytes,
            .total_read_bytes = total_read_bytes,
        };

        if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_load_file_back, aux))
            return false;
        
        // struct page *page = spt_find_page(&thread_current()->spt, upage);
        // struct file_page *file_page = &page->file;
        // file_page->file = file;
        // file_page->ofs = offset;
        // file_page->page_read_bytes = page_read_bytes;
        // file_page->total_read_bytes = total_read_bytes;

        total_read_bytes -= page_read_bytes;
        offset += page_read_bytes;
        upage += PGSIZE;
    }
    return addr;
}

/* Do the munmap */
void do_munmap(void *addr) {
    ASSERT(pg_ofs(addr) == 0);

    struct thread *thread = thread_current();
    struct page *page = spt_find_page(&thread->spt, addr);
    struct file *file = page->file.file;
    size_t total_read_bytes = page->file.total_read_bytes;
    off_t offset = page->file.ofs;

    while (total_read_bytes > 0) {
        page = spt_find_page(&thread->spt, addr);
        if (pml4_is_dirty(thread->pml4, addr)) {
            lock_acquire(&file_lock);
            file_write_at(page->file.file, page->frame->kva, page->file.page_read_bytes, offset);
            lock_release(&file_lock);
            pml4_set_dirty(thread->pml4, addr, 0);
        }

        addr += PGSIZE;
        offset += page->file.page_read_bytes;
        total_read_bytes -= page->file.page_read_bytes;

        vm_dealloc_page(page);
    }
    lock_acquire(&file_lock);
    file_close(file);
    lock_release(&file_lock);
}

bool lazy_load_file_back(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */

    /* Load this page. */
    struct lazy_load_aux *llaux = aux;

    // struct file_page *file_page = &page->file;
        // file_page->file = file;
        // file_page->ofs = offset;
        // file_page->page_read_bytes = page_read_bytes;
        // file_page->total_read_bytes = total_read_bytes;
// printf("!!!!!!!!!!!%p %d %d %d\n", file_page->file, file_page->ofs, file_page->page_read_bytes, file_page->total_read_bytes);
    if (file_read_at(llaux->file, page->frame->kva, llaux->page_read_bytes, llaux->offset) != (int)llaux->page_read_bytes) {
        // free(aux);
        return false;
    }

    page->file.file = llaux->file;
    page->file.total_read_bytes = llaux->total_read_bytes;
    page->file.page_read_bytes = llaux->page_read_bytes;
    page->file.ofs = llaux->offset;

    // free(aux);
    return true;
}