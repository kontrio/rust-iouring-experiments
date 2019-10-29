use core::pin::Pin;
use crate::{
    CompletedIter,
    CompletionQueue,
    CompletionQueueEntry,
    MappedMemory,
    SubmissionQueue,
    SubmissionQueueEntry,
    Syscalls,
    SyscallLib,
};

pub type Uring = IoUring<Syscalls>;

pub struct IoUring<S: SyscallLib> {
    submission_queue: SubmissionQueue<MappedMemory, S>,
    completion_queue: CompletionQueue,

    // Because "sq_memory" _could_ be shared between the sq, and the cq, we hold
    // the mapped memory values here rather than putting them inside the queues they belong to.
    // ideally, since the queue's memory safety depends on valid memory maps, they would own
    // their own maps.
    _sq_memory: MappedMemory,
    _cq_memory: Option<MappedMemory>,

    uring_fd: i32,
}

impl<S: SyscallLib> IoUring<S> {
    pub(crate) fn new(
        uring_fd: i32,
        submission_queue: SubmissionQueue<MappedMemory, S>,
        completion_queue: CompletionQueue,
        _sq_memory: MappedMemory,
        _cq_memory: Option<MappedMemory>) -> Self {

        Self {
            submission_queue,
            completion_queue,
            _sq_memory,
            _cq_memory,
            uring_fd,
        }
    }

    pub fn new_submission(&mut self) -> Option<Pin<&'static mut SubmissionQueueEntry>> {
        self.submission_queue.get_next_entry().ok()
    }

    pub fn submit(&mut self) -> Result<u32, i32> {
        self.submission_queue.submit()
    }

    pub fn drain(&mut self) -> CompletedIter {
        self.completion_queue.drain()
    }
}

impl<S: SyscallLib> Drop for IoUring<S> {
    fn drop(&mut self) {
        unsafe { libc::close(self.uring_fd) };
    }
}
