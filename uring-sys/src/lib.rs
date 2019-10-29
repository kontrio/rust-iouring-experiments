#![no_std]

// TODO: Do we have to macro_use? I can't get this crate to work without it
#[macro_use]
extern crate static_assertions;

mod contiguous_mem;
pub(crate) use contiguous_mem::{
    ContiguousMem,
};

mod completion_queue;
pub use completion_queue::{
    CompletedIter,
    CompletionQueue,
};

// External library API (pub use)
pub(crate) mod io_uring;
pub use io_uring::{ 
    IORING_OFF_SQ_RING,
    IORING_OFF_CQ_RING,
    IORING_OFF_SQES,
    CompletionQueueEntry,
    CompletionQueueRingOffsets,
    EnterFlag,
    FeatureFlag,
    FileDescriptor,
    IOPriority,
    Opcode,
    ReadWriteFlags,
    SetupFlag,
    SetupParameters, 
    SubmissionEntryFlags,
    SubmissionQueueEntry,
    SubmissionQueueFlag,
    SubmissionQueueRingOffsets,
};

//TODO: until the stuff in the io_uring module is moved out, then this mod is named without the 'u'
mod io_ring;
pub use io_ring::{
    IoUring,
    Uring,
};

mod io_uring_builder;
pub use io_uring_builder::{
    IoUringBuilder,
};

pub(crate) mod mmap;
pub use mmap::{
    MappedMemory,
};


mod submission_queue;
pub use submission_queue::{
    SubmissionQueue,
};

mod syscall;
pub use syscall::{
    Syscalls,
    SyscallLib,
};

