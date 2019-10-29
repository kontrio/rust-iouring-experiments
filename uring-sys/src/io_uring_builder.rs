use core::ops::DerefMut;
use crate::{
    IORING_OFF_SQ_RING,
    IORING_OFF_CQ_RING,
    IORING_OFF_SQES,
    CompletionQueue,
    FeatureFlag,
    IoUring,
    MappedMemory,
    SetupFlag,
    SetupParameters,
    SubmissionQueue,
    SyscallLib,
    Syscalls,
};

#[derive(Default)]
pub struct IoUringBuilder {
    flags: SetupFlag,
    queue_entries: usize,
    cq_size: usize,
}

impl IoUringBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_io_poll(mut self, option: bool) -> Self {
        if option {
            self.flags |= SetupFlag::IO_POLL;
        } else {
            self.flags &= !SetupFlag::IO_POLL;
        }
        self
    }

    /// The kernel will create a thread to poll the submission queue
    pub fn with_submission_queue_kernel_poller(mut self, option: bool) -> Self {

        if option {
            self.flags |= SetupFlag::SQ_POLL;
        } else {
            self.flags &= !SetupFlag::SQ_POLL;
        }
        self
    }

    pub fn with_submission_queue_affinity(mut self, option: bool) -> Self {
        if option {
            self.flags |= SetupFlag::SQ_AFFINITY;
        } else {
            self.flags &= !SetupFlag::SQ_AFFINITY;
        }
        self
    }

    /// Indicate the completion queue size, if this isn't done the kernel will decide. Setting this
    /// to '0' is equivalent to unsetting this flag.
    pub fn with_completion_queue_size(mut self, size: usize) -> Self {
        if size > 0 {
            self.flags |= SetupFlag::CQ_SIZE;
        } else {
            self.flags &= !SetupFlag::CQ_SIZE;
        }

        self.cq_size = size;
        self
    }

    pub fn with_submission_queue_entries(mut self, entries: usize) -> Self {
        self.queue_entries = entries;
        self
    }

    pub fn build(self) -> Result<IoUring<Syscalls>, i32> {
        // mutable because we will pin the memory, and pass it into the kernel to fill out.
        let mut setup_parameters = SetupParameters::with_flags(self.flags);
        let mut setup_parameters = core::pin::Pin::new(&mut setup_parameters);

        // this is the file descriptor we can mmap onto
        let uring_fd = Syscalls::io_uring_setup(self.queue_entries, setup_parameters.deref_mut());

        if uring_fd < 0 {
            //TODO: real errors
            return Err(uring_fd);
        }     

        Self::do_mmapping(uring_fd, &setup_parameters)
    }

    fn do_mmapping(uring_fd: i32, setup_params: &SetupParameters) -> Result<IoUring<Syscalls>, i32> {

        let mut submission_queue_bytes = setup_params.submission_queue_bytes();
        let mut completion_queue_bytes = setup_params.completion_queue_bytes();

        // if the kernel indicates a single mmap, we make the queues equal sizes picking the largest
        // of the two.
        let has_single_mmap_feature = setup_params.has_feature(FeatureFlag::SINGLE_MMAP);

        if has_single_mmap_feature {
            completion_queue_bytes = core::cmp::max(completion_queue_bytes, submission_queue_bytes);
            submission_queue_bytes = completion_queue_bytes;
        }
        
        let submission_queue_entries_bytes = setup_params.submission_queue_entries_bytes();

        let sq_memory   = MappedMemory::map(uring_fd, IORING_OFF_SQ_RING, submission_queue_bytes)?;
        let sqes_memory = MappedMemory::map(uring_fd, IORING_OFF_SQES, submission_queue_entries_bytes)?;

        let submission_queue: SubmissionQueue<MappedMemory, Syscalls> = SubmissionQueue::new(
            submission_queue_entries_bytes,
            uring_fd,
            &sq_memory,
            sqes_memory,
            setup_params); 

        let cq_memory = if has_single_mmap_feature {
            None
        } else {
            let cq_memory = MappedMemory::map(uring_fd, IORING_OFF_CQ_RING, completion_queue_bytes)?;
            Some(cq_memory)
        };

        let completion_queue = CompletionQueue::new(
            completion_queue_bytes,
            match cq_memory {
                Some(ref inner) => inner,     
                // share the submission queue memory in single mmap mode
                None => &sq_memory,
            },
            setup_params);

        Ok(IoUring::new(uring_fd, submission_queue, completion_queue, sq_memory, cq_memory))
    }
}
