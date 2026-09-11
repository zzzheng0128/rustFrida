//! pthread shim 的线程/key 值表。按需扩容，地址稳定，不依赖 TLS 或 pthread 锁。
//! 普通清除映射不释放值；线程退出时由 destroy_thread_values 在锁外调用析构函数。

use std::alloc::{alloc_zeroed, Layout};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};

const SLOTS_PER_PAGE: usize = 512;
const DESTRUCTOR_ITERATIONS: usize = 4;
pub(crate) type ThreadToken = u128;
pub(crate) type TlsDestructor = unsafe extern "C" fn(*mut std::ffi::c_void);

#[derive(Clone, Copy)]
struct Slot {
    thread: ThreadToken,
    key: u32,
    value: usize,
}

impl Slot {
    const EMPTY: Self = Self {
        thread: 0,
        key: 0,
        value: 0,
    };
}

struct Page {
    slots: [Slot; SLOTS_PER_PAGE],
    next: *mut Page,
}

impl Page {
    const EMPTY: Self = Self {
        slots: [Slot::EMPTY; SLOTS_PER_PAGE],
        next: std::ptr::null_mut(),
    };

    fn find(&mut self, thread: ThreadToken, key: u32) -> Option<&mut Slot> {
        let mut page = self;
        loop {
            if let Some(slot) = page.slots.iter_mut().find(|s| s.thread == thread && s.key == key) {
                return Some(slot);
            }
            // 页的遍历与摘除均持有表锁，引用不得越过 guard 的生命周期。
            page = unsafe { page.next.as_mut()? };
        }
    }

    fn vacant(&mut self) -> Option<&mut Slot> {
        let mut page = self;
        loop {
            if let Some(slot) = page.slots.iter_mut().find(|s| s.thread == 0) {
                return Some(slot);
            }
            page = unsafe { page.next.as_mut()? };
        }
    }

    fn allocate() -> Option<Box<Self>> {
        // Page 只含整数和原始指针，全零是有效空页。直接在堆上分配，
        // 避免在 hook 回调的 C 栈上构造整个 512 槽数组。
        let raw = unsafe { alloc_zeroed(Layout::new::<Self>()) } as *mut Self;
        if raw.is_null() {
            None
        } else {
            Some(unsafe { Box::from_raw(raw) })
        }
    }

    fn detach_empty_pages(&mut self) -> *mut Page {
        let mut detached = std::ptr::null_mut();
        let mut link = &mut self.next as *mut *mut Page;
        unsafe {
            while let Some(page) = (*link).as_mut() {
                if page.slots.iter().all(|slot| slot.thread == 0) {
                    let removed = *link;
                    *link = page.next;
                    page.next = detached;
                    detached = removed;
                } else {
                    link = &mut page.next;
                }
            }
        }
        detached
    }
}

unsafe fn free_pages(mut next: *mut Page) {
    while !next.is_null() {
        let page = Box::from_raw(next);
        next = page.next;
    }
}

pub(crate) struct TlsValueStore {
    locked: AtomicBool,
    head: UnsafeCell<Page>,
}

// head 及所有后续页只在持有 locked 时访问；空页摘链后才在锁外释放。
unsafe impl Sync for TlsValueStore {}

impl TlsValueStore {
    pub(crate) const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            head: UnsafeCell::new(Page::EMPTY),
        }
    }

    fn lock(&self) -> StoreGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        }
        StoreGuard { store: self }
    }

    pub(crate) fn get(&self, thread: ThreadToken, key: u32) -> usize {
        self.lock().head().find(thread, key).map_or(0, |slot| slot.value)
    }

    pub(crate) fn set(&self, thread: ThreadToken, key: u32, value: usize) -> Result<(), ()> {
        if thread == 0 || key == 0 {
            return Err(());
        }
        let mut extra: Option<Box<Page>> = None;
        loop {
            let mut guard = self.lock();
            let head = guard.head();
            if let Some(slot) = head.find(thread, key) {
                *slot = if value == 0 {
                    Slot::EMPTY
                } else {
                    Slot { thread, key, value }
                };
                let retired = if value == 0 {
                    head.detach_empty_pages()
                } else {
                    std::ptr::null_mut()
                };
                // 锁外释放竞争扩容时多分配的页。
                drop(guard);
                drop(extra);
                unsafe { free_pages(retired) };
                return Ok(());
            }
            if value == 0 {
                drop(guard);
                drop(extra);
                return Ok(());
            }
            if let Some(slot) = head.vacant() {
                *slot = Slot { thread, key, value };
                drop(guard);
                drop(extra);
                return Ok(());
            }
            if let Some(mut page) = extra.take() {
                page.slots[0] = Slot { thread, key, value };
                page.next = head.next;
                head.next = Box::into_raw(page);
                return Ok(());
            }
            // allocator 可能自行访问线程状态，绝不能在持表锁时分配。
            drop(guard);
            extra = Some(Page::allocate().ok_or(())?);
        }
    }

    pub(crate) fn remove_key(&self, key: u32) {
        self.remove_matching(|slot| slot.key == key);
    }

    pub(crate) fn remove_thread(&self, thread: ThreadToken) {
        self.remove_matching(|slot| slot.thread == thread);
    }

    fn remove_matching(&self, matches: impl Fn(&Slot) -> bool) {
        let mut guard = self.lock();
        let mut page = guard.head();
        loop {
            for slot in &mut page.slots {
                if matches(slot) {
                    *slot = Slot::EMPTY;
                }
            }
            match unsafe { page.next.as_mut() } {
                Some(next) => page = next,
                None => break,
            }
        }
        let retired = guard.head().detach_empty_pages();
        drop(guard);
        unsafe { free_pages(retired) };
    }

    pub(crate) fn take(&self, thread: ThreadToken, key: u32) -> usize {
        let mut guard = self.lock();
        if let Some(slot) = guard.head().find(thread, key) {
            let value = slot.value;
            *slot = Slot::EMPTY;
            return value;
        }
        0
    }

    /// 必须在所属线程真正退出时调用；调用方保证 value 与析构函数相匹配。
    /// 先清值再析构，允许析构重入 set/get，最多执行四轮；最终丢弃剩余映射。
    pub(crate) unsafe fn destroy_thread_values(
        &self,
        thread: ThreadToken,
        key_count: u32,
        mut resolve: impl FnMut(u32) -> Option<TlsDestructor>,
    ) {
        for _ in 0..DESTRUCTOR_ITERATIONS {
            let mut called = false;
            for key in 1..key_count {
                if let Some(destructor) = resolve(key) {
                    let value = self.take(thread, key);
                    if value != 0 {
                        called = true;
                        destructor(value as *mut std::ffi::c_void);
                    }
                }
            }
            if !called {
                break;
            }
        }
        self.remove_thread(thread);
    }

    #[cfg(test)]
    fn page_count(&self) -> usize {
        let mut guard = self.lock();
        let mut page = guard.head();
        let mut count = 1;
        while let Some(next) = unsafe { page.next.as_mut() } {
            count += 1;
            page = next;
        }
        count
    }
}

impl Drop for TlsValueStore {
    fn drop(&mut self) {
        // &mut self 保证不再有并发访问；只释放元数据页，不释放 TLS 值。
        unsafe { free_pages(self.head.get_mut().next) };
    }
}

struct StoreGuard<'a> {
    store: &'a TlsValueStore,
}

impl StoreGuard<'_> {
    fn head(&mut self) -> &mut Page {
        unsafe { &mut *self.store.head.get() }
    }
}

impl Drop for StoreGuard<'_> {
    fn drop(&mut self) {
        self.store.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removing_exited_threads_reclaims_pages_without_touching_live_threads() {
        let store = TlsValueStore::new();
        store.set(9000, 1, 77).unwrap();
        for thread in 1..=1600 {
            store.set(thread, 1, thread as usize).unwrap();
        }
        assert!(store.page_count() > 1);
        for thread in 1..=1600 {
            store.remove_thread(thread);
        }
        assert_eq!(store.page_count(), 1);
        assert_eq!(store.get(9000, 1), 77);
        assert_eq!(store.get(9001, 1), 0);
    }

    #[test]
    fn clearing_values_and_deleting_keys_release_empty_pages() {
        let store = TlsValueStore::new();
        for thread in 1..=1200 {
            store.set(thread, 1, 11).unwrap();
        }
        assert!(store.page_count() > 1);
        for thread in 1..=1200 {
            store.set(thread, 1, 0).unwrap();
        }
        assert_eq!(store.page_count(), 1);
        for thread in 1..=1200 {
            store.set(thread, 2, 22).unwrap();
        }
        store.remove_key(2);
        assert_eq!(store.page_count(), 1);
    }

    #[test]
    fn concurrent_thread_cleanup_does_not_invalidate_other_readers() {
        let store = TlsValueStore::new();
        let start = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let store = &store;
                let start = &start;
                scope.spawn(move || {
                    let thread = worker + 1;
                    start.wait();
                    for _ in 0..10 {
                        for key in 1..=600 {
                            store.set(thread, key, key as usize).unwrap();
                        }
                        for key in 1..=600 {
                            assert_eq!(store.get(thread, key), key as usize);
                        }
                        store.remove_thread(thread);
                    }
                });
            }
        });
        assert_eq!(store.page_count(), 1);
    }

    struct Rearm {
        store: *const TlsValueStore,
        calls: usize,
        limit: usize,
    }

    unsafe extern "C" fn rearm(value: *mut std::ffi::c_void) {
        let state = &mut *(value as *mut Rearm);
        let store = &*state.store;
        // 析构调用前必须清空旧值，并释放表锁。
        assert_eq!(store.get(1, 1), 0);
        state.calls += 1;
        if state.calls < state.limit {
            store.set(1, 1, value as usize).unwrap();
        }
    }

    #[test]
    fn destructors_run_without_table_lock_and_can_rearm_values() {
        let store = TlsValueStore::new();
        let mut state = Rearm {
            store: &store,
            calls: 0,
            limit: 2,
        };
        store.set(1, 1, &mut state as *mut _ as usize).unwrap();
        unsafe { store.destroy_thread_values(1, 2, |_| Some(rearm)) };
        assert_eq!(state.calls, 2);
        assert_eq!(store.get(1, 1), 0);
    }

    #[test]
    fn perpetually_rearmed_destructor_stops_after_four_rounds() {
        let store = TlsValueStore::new();
        let mut state = Rearm {
            store: &store,
            calls: 0,
            limit: usize::MAX,
        };
        store.set(1, 1, &mut state as *mut _ as usize).unwrap();
        unsafe { store.destroy_thread_values(1, 2, |_| Some(rearm)) };
        assert_eq!(state.calls, 4);
        assert_eq!(store.get(1, 1), 0);
    }

    #[test]
    fn values_remain_readable_beyond_old_capacity() {
        let store = TlsValueStore::new();
        for thread in 1..=2048 {
            for key in 1..=2 {
                let value = thread as usize * 10 + key as usize;
                store.set(thread, key, value).unwrap();
                assert_eq!(store.get(thread, key), value);
            }
        }
        for thread in 1..=2048 {
            for key in 1..=2 {
                assert_eq!(store.get(thread, key), thread as usize * 10 + key as usize);
            }
        }
    }

    #[test]
    fn clear_and_key_deletion_preserve_other_values_and_reuse_slots() {
        let store = TlsValueStore::new();
        for thread in 1..=600 {
            store.set(thread, 1, 11).unwrap();
            store.set(thread, 2, 22).unwrap();
        }
        store.set(1, 2, 33).unwrap();
        store.set(2, 2, 0).unwrap();
        store.remove_key(1);
        assert_eq!(store.get(1, 2), 33);
        assert_eq!(store.get(2, 2), 0);
        for thread in 1..=600 {
            assert_eq!(store.get(thread, 1), 0);
            store.set(thread, 3, 44).unwrap();
            assert_eq!(store.get(thread, 3), 44);
        }
        assert_eq!(store.get(600, 2), 22);
    }

    #[test]
    fn concurrent_growth_keeps_thread_and_key_isolation() {
        let store = TlsValueStore::new();
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let store = &store;
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    for index in 1..=200 {
                        let thread = worker * 200 + index;
                        store.set(thread, 1, thread as usize).unwrap();
                        store.set(thread, 2, thread as usize + 1).unwrap();
                        assert_eq!(store.get(thread, 1), thread as usize);
                        assert_eq!(store.get(thread, 2), thread as usize + 1);
                    }
                });
            }
        });
        for thread in 1..=1600 {
            assert_eq!(store.get(thread, 1), thread as usize);
            assert_eq!(store.get(thread, 2), thread as usize + 1);
        }
    }
}
