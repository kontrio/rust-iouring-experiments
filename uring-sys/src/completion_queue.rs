use core::pin::Pin;
use crate::{
    CompletionQueueEntry,
    MappedMemory,
    SetupParameters,
};

#[derive(Debug)]
pub struct CompletionQueue {
    // updated in userspace
    k_head: *mut u32,
    // update in kernel
    k_tail: *mut u32,
    k_ring_mask: u32,
    k_ring_entries: *mut u32,
    k_overflow: *mut u32,
    k_completion_queue_entries: *mut u32,

    // This is used for iterating over the completion entries without copying.
    // If we were to update k_head while iterating it's possible that the kernel 
    // could overwrite the data that we're reading, 
    // instead we keep track of _our_ head, and flush it to the kernel when we're
    // done reading.
    head: u32,

    size: usize,
}

pub struct CompletedIter<'a>(&'a mut CompletionQueue); 

impl<'a> Iterator for CompletedIter<'a> {
    type Item = Pin<&'a CompletionQueueEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_drained() {
            None
        } else {
            let index = self.0.head & self.0.k_ring_mask;
            let mem_offset = index as usize * core::mem::size_of::<CompletionQueueEntry>();
            let cqe = unsafe { self.0.k_completion_queue_entries.offset(mem_offset as isize) as *mut CompletionQueueEntry };
            self.0.head = self.0.head.wrapping_add(1);

            if cqe == core::ptr::null_mut() {
                None
            } else {
                Some(Pin::new(unsafe { &*cqe }))
            }
        }
    }
}

impl Drop for CompletedIter<'_> {
    fn drop(&mut self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        unsafe { core::ptr::write_volatile(self.0.k_head, self.0.head) };
    }
}

impl CompletionQueue {
    pub fn new(
        size_bytes: usize, 
        cq_memory: &MappedMemory, 
        params: &SetupParameters) -> Self { 

        CompletionQueue {
            k_head:         cq_memory.get_offset(params.cq_ring_offsets.head as usize),
            k_tail:         cq_memory.get_offset(params.cq_ring_offsets.tail as usize),
            // The kernel code and docs suggest this is always constant (entries - 1)
            k_ring_mask:    unsafe { *cq_memory.get_offset(params.cq_ring_offsets.ring_mask as usize) },
            k_ring_entries: cq_memory.get_offset(params.cq_ring_offsets.ring_entries as usize),
            k_overflow:     cq_memory.get_offset(params.cq_ring_offsets.overflow as usize),
            k_completion_queue_entries: cq_memory.get_offset(params.cq_ring_offsets.completion_queue_entries as usize),
            head: 0,
            size: size_bytes, //  TODO: is this set by us from params or kernel?
        }
    }

    fn is_drained(&self) -> bool {
        self.head == load_acquire(self.k_tail)
    }

    pub fn drain(&mut self) -> CompletedIter {
        CompletedIter(self)
    }
}


//TODO: Could we use AtomicU32?..
fn load_acquire<T>(ptr: *const T) -> T {
    let read_once = unsafe { core::ptr::read_volatile(ptr) };
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    read_once
}
