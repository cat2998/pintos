/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "devices/disk.h"
#include "vm/vm.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "lib/stddef.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);
size_t find_disk_sec_no(void);
struct bitmap *swap_table;
struct lock swap_lock;

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    size_t disk_total_size = disk_size(swap_disk);
    swap_table = bitmap_create(disk_total_size);
    bitmap_set_all(swap_table, 0);
    lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    anon_page->sec_no = -1;
    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;

    ASSERT(page != NULL);
    ASSERT(kva != NULL);

    if (anon_page->sec_no == -1)
        return true;

    if (bitmap_test(swap_table, anon_page->sec_no) == false)
        return false;

    lock_acquire(&swap_lock);
    for (int i = 0; i < 8; i++) {
        disk_read(swap_disk, anon_page->sec_no + i, kva + i * DISK_SECTOR_SIZE);
        bitmap_set(swap_table, anon_page->sec_no + i, 0);
    }
    lock_release(&swap_lock);
    anon_page->sec_no = -1;

    return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;
    disk_sector_t sec_no = find_disk_sec_no();
    if (sec_no == BITMAP_ERROR)
        return false;

    lock_acquire(&swap_lock);
    for (int i = 0; i < 8; i++) {
        disk_write(swap_disk, sec_no + i, page->frame->kva + i * DISK_SECTOR_SIZE);
        bitmap_set(swap_table, sec_no + i, 1);
    }
    lock_release(&swap_lock);

    anon_page->sec_no = sec_no;
    page->frame = NULL;
    pml4_clear_page(thread_current()->pml4, page->va);

    return true;
}

size_t find_disk_sec_no(void) {
    size_t sec_no;
    lock_acquire(&swap_lock);
    sec_no = bitmap_scan(swap_table, 0, 8, 0);
    lock_release(&swap_lock);
    return sec_no;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page) {
    struct anon_page *anon_page = &page->anon;
    struct thread *curr = thread_current();

    lock_acquire(&swap_lock);
    if (anon_page->sec_no != -1) {
        for (int i = 0; i < 8; i++)
            bitmap_set(swap_table, anon_page->sec_no + i, 0);
    }

    pml4_clear_page(curr->pml4, page->va);
    lock_release(&swap_lock);

    if (page->frame)
        delete_frame(page->frame);

    hash_delete(&curr->spt.spt_hash, &page->hash_elem);
}
