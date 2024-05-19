/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/mmu.h"

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
    page->file.file = NULL;
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

    struct file_page *file_page = &page->file;

    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(file_page->file, page->frame->kva, file_page->page_read_bytes, file_page->ofs);
    }
    // pml4_clear_page(thread_current()->pml4, page->va);
    // if (page->frame) {
    //     delete_frame(page->frame->kva);
    // }
    // hash_delete(&thread->spt.spt_hash, &page->hash_elem);
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    size_t total_read_bytes = length;
    void *upage = addr;

    while (total_read_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = total_read_bytes < PGSIZE ? total_read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        struct lazy_load_aux *aux = calloc(1, sizeof(struct lazy_load_aux));
        *aux = (struct lazy_load_aux){
            .file = file,
            .offset = offset,
            .page_read_bytes = page_read_bytes,
            .page_zero_bytes = page_zero_bytes,
            .total_read_bytes = total_read_bytes,
        };

        if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_load_file_back, (void *)aux))
            return false;

        /* Advance. */
        total_read_bytes -= page_read_bytes;
        offset += page_read_bytes;
        upage += PGSIZE;
    }
    return upage;
}

/* Do the munmap */
void do_munmap(void *addr) {
    struct thread *thread = thread_current();
    struct page *page = spt_find_page(&thread->spt, addr);

    size_t total_read_bytes = page->file.total_read_bytes;
    off_t offset = 0;

    ASSERT(pg_ofs(addr) == 0);
    while (total_read_bytes > 0) {
        page = spt_find_page(&thread->spt, addr);
        if (pml4_is_dirty(thread->pml4, addr))
            file_write_at(page->file.file, page->frame->kva, page->file.page_read_bytes, offset);

        addr += PGSIZE;
        offset += page->file.page_read_bytes;
        total_read_bytes -= page->file.page_read_bytes;

        if (page->frame) {
            // pml4 매핑정보도 없애야하는거 아님?
            delete_frame(page->frame->kva);
            // destroy에서 frame, 매핑정보 없애는 흐름이라면 이 if 문 없어도 될듯. vm_dealloc_page()->destroy() 호출하니까
        }

        hash_delete(&thread->spt.spt_hash, &page->hash_elem);
        vm_dealloc_page(page);
    }
}

void delete_frame(void *kva) {
    struct list_elem *e;
    struct list_elem *ed;
    struct frame *frame = NULL;
    for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e)) {
        frame = list_entry(e, struct frame, elem);
        if (frame->kva == kva) {
            e = list_remove(e);
            palloc_free_page(frame->kva);
            free(frame);
            break;
        }
    }
}

bool lazy_load_file_back(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */

    /* Load this page. */
    struct lazy_load_aux *llaux = aux;
    if (file_read_at(llaux->file, page->frame->kva, llaux->page_read_bytes, llaux->offset) != (int)llaux->page_read_bytes) {
        return false;
    }
    page->file.file = llaux->file;
    page->file.total_read_bytes = llaux->total_read_bytes;
    page->file.page_read_bytes = llaux->page_read_bytes;
    page->file.ofs = llaux->offset;
    return true;
} 