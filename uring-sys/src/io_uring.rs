use bitflags::bitflags;

pub const IORING_OFF_SQ_RING: u64 = 0_u64;
pub const IORING_OFF_CQ_RING: u64 = 0x8000000_u64;
pub const IORING_OFF_SQES: u64    = 0x10000000_u64;

const_assert_eq!(16, core::mem::size_of::<CompletionQueueEntry>());

/// IO completion data structure - a single entry in the completion queue.
#[repr(C)]
#[derive(Debug)]
pub struct CompletionQueueEntry {
    /// Data passed back from the submission, so that the application could link a submission to a
    /// completion
    pub user_data: u64,
    /// Result code for this event
    pub result: i32,
    pub flags: u32,
}

const_assert_eq!(40,  core::mem::size_of::<CompletionQueueRingOffsets>());

#[repr(C)]
#[derive(Default, Debug)]
pub struct CompletionQueueRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub completion_queue_entries: u32,
    pub __reserved: [u64; 2]
}

const_assert_eq!(40,  core::mem::size_of::<SubmissionQueueRingOffsets>());

#[repr(C)]
#[derive(Default, Debug)]
pub struct SubmissionQueueRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub __resv1: u32,
    pub __resv2: u64,
}

bitflags!{
    #[derive(Default)]
    pub struct SetupFlag: u32 {
        /// The IoContext is polled
        const IO_POLL     = (1_u32 << 0);
        /// The kernel creates a thread to poll the submission queue
        const SQ_POLL     = (1_u32 << 1);
        /// sq_thread_cpu is valid?? (TODO: what's the implication)
        const SQ_AFFINITY = (1_u32 << 2);
        /// The application defines the completion queue size.
        const CQ_SIZE     = (1_u32 << 3);
    }
}

bitflags! {
    pub struct SubmissionQueueFlag: u32 {
        /// Needs wakeup during enter
        const NEED_WAKEUP = (1_u32 << 0);
    }
}

bitflags! {
    pub struct EnterFlag: u32 {
        const EMPTY     = (0_u32);
        const GETEVENTS = (1_u32 << 0);
        const SQ_WAKEUP = (1_u32 << 1);
    }
}

bitflags! {
    #[derive(Default)]
    pub struct FeatureFlag: u32 {
        const SINGLE_MMAP = (1_u32 << 0);
    }
}

const_assert_eq!(120, core::mem::size_of::<SetupParameters>());

/// The kernel will update this data structure in memory wih additional parameters
#[repr(C)]
#[derive(Default, Debug)]
pub struct SetupParameters {
    pub submission_queue_entries: u32,
    pub completion_queue_entries: u32,
    pub flags: SetupFlag,
    pub submission_queue_thread_cpu: u32,
    pub submission_queue_thread_idle: u32,
    pub features: FeatureFlag,

    pub __reserved: [u32;4],
    pub sq_ring_offsets: SubmissionQueueRingOffsets, 
    pub cq_ring_offsets: CompletionQueueRingOffsets, 
}

impl SetupParameters {
    pub fn with_flags(flags: SetupFlag) -> Self {
        let mut params: Self = Default::default();
        params.flags = flags;
        params
    }

    #[inline]
    pub fn has_feature(&self, flag: FeatureFlag) -> bool {
        (self.features & flag).bits() != 0
    }
    
    #[inline]
    pub fn submission_queue_bytes(&self) -> usize {
        (self.sq_ring_offsets.array + self.submission_queue_entries * (core::mem::size_of::<u32>() as u32)) as usize
    }

    #[inline]
    pub fn completion_queue_bytes(&self) -> usize {
        (self.cq_ring_offsets.completion_queue_entries + self.completion_queue_entries * (core::mem::size_of::<CompletionQueueEntry>() as u32)) as usize
    }

    #[inline]
    pub fn submission_queue_entries_bytes(&self) -> usize {
        self.submission_queue_entries as usize * core::mem::size_of::<SubmissionQueueEntry>()
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SubmissionEntryFlags: u8 {
        /// Use fixed fileset
        const FIXED_FILE = 0;
        /// Issue after inflight IO (TODO: Implications???)
        const IO_DRAIN = 1;
        /// Links next submission queue entry. (TODO: Implications???)
        const IO_LINK = 2;
    }
}

#[repr(C)]
pub union FileOffset {
    offset: u64,
    addr: u64,
}

#[repr(C)]
pub union SubmissionOpcodeFlags {
    /// kernel read/write flag 
    rw_flag: ReadWriteFlags, 
    fsync_flags: FsyncFlags,
    poll_events: u16,
    sync_range_flags: u32,
    msg_flags: u32,
    timeout_flags: TimeoutFlags,
    accept_flags: u32,
}

#[repr(C)]
pub union FixedBufferIndex {
    index: u16,
    __pad: [u64; 3],
}

pub type IOPriority = u16;

bitflags! {
    pub struct Opcode: u8 {
        const NOOP = 0;
        const READV = 1;
        const WRITEV = 2;
        const FSYNC = 3;
        const READ_FIXED = 4;
        const WRITE_FIXED = 5;
        const POLL_ADD = 6;
        const POLL_REMOVE = 7;
        const SYNC_FILE_RANGE = 8;
        const SENDMSG = 9;
        const RECVMESG = 10;
        const TIMEOUT = 11;
        const TIMEOUT_REMOVE = 12;
        const ACCEPT = 13;
    }
}

bitflags! {
    pub struct FsyncFlags: u32 {
        const DATA_SYNC = 0;
    }
}

bitflags! {
    pub struct TimeoutFlags: u32 {
        const ABS = 0;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct ReadWriteFlags: u32 {
        /// High priority request, will use poll if possible on block based devices, which ultimately provides
        /// lower latency. The trade off is, the kernel will allocate a thread resource to do the
        /// polling, and so uses more resources. Only usable on files opened with O_DIRECT flag.
        const HIPRI = 0x00000001;
        /// Per-IO equivalent of the O_DSYNC open(2) flag.  
        const DSYNC = 0x00000002;
        /// Per-IO equivalent of the O_SYNC open(2) flag.
        const SYNC   = 0x00000004;
        /// Per-IO, returns -EAGAIN if the operation would block, for example when there is no data
        /// immediately available.  If this flag is specified the preadv2() system call will return
        /// instantly if it would need to wait on a lock or the storage device.
        const NOWAIT = 0x00000008;
        /// Per-IO equivalent of the O_APPEND open(2) flag. With this flag, the offset argument
        /// will not affect the write operation, with data always appended to the end of the file.
        /// If the offset argument is -1, then the current file offset is updated.
        const APPEND = 0x00000010;

        const SUPPORTED = 0 | Self::HIPRI.bits | Self::DSYNC.bits | Self::SYNC.bits | Self::NOWAIT.bits | Self::APPEND.bits;

        #[doc(hidden)]
        const _ALL = !0;
    }
}

impl From<ReadWriteFlags> for SubmissionOpcodeFlags {
    fn from(rw_flag: ReadWriteFlags) -> Self {
        Self { rw_flag, }
    }
}

const_assert_eq!(64, core::mem::size_of::<SubmissionQueueEntry>());
#[repr(C)]
pub struct SubmissionQueueEntry {
    pub opcode: Opcode,
    pub flags: SubmissionEntryFlags,
    pub io_priority: IOPriority,
    pub fd: i32,
    pub offset: FileOffset,
    /// Pointer to a buffer or "iovecs" data
    pub addr: u64,
    /// Sized of the buffer, or number of "iovecs"
    pub len: u32,
    pub opcode_flags: SubmissionOpcodeFlags,
    pub user_data: u64,
    pub buffer_index: FixedBufferIndex,
}

/// Whenever a standard file descriptor is filled into a submissione queue entry and submitted to
/// the kernel, the kernel will retrieve a reference to the given file descriptor. Then once the IO on
/// that FD is complete the reference is dropped again. On high IOP workloads whis can cause a
/// slowdown as the kernel repeats fd lookups.
///
/// If you know in advance that you're going to be doing some heavy IO on a set of open fds, you can
/// pre-register the descriptors, and then reference them by index, essentially caching the fds for
/// submissions to the queue.
pub enum FileDescriptor {
    /// A standard file descriptor
    FD(i32),
    /// Index to previously registered list of file descriptors
    RegisteredIndex(u32),
}

impl SubmissionQueueEntry {
    pub unsafe fn clear(&mut self) {
        *self = core::mem::zeroed();
    }

    #[inline]
    fn iov(&mut self, op: Opcode, priority: IOPriority, fd: FileDescriptor, offset: u64, flags: ReadWriteFlags, user_data: u64, iov: *const [libc::iovec]) {
        unsafe { self.clear() };
        self.opcode = op;
        self.flags = Default::default();
        match fd {
            FileDescriptor::FD(standard_fd) => {
                self.fd = standard_fd;
            },
            FileDescriptor::RegisteredIndex(index) => {
                self.flags |= SubmissionEntryFlags::FIXED_FILE;
                self.fd = index as i32;
            }
        };
        self.io_priority = priority;
        self.offset = FileOffset { offset, };
        self.addr = unsafe { (*iov).as_ptr() } as usize as u64;
        self.len = unsafe { (*iov).len() } as u32;
        self.opcode_flags = flags.into();
        self.user_data = user_data;
        self.buffer_index.index = 0;
    }

    pub fn readv(&mut self, priority: IOPriority, fd: FileDescriptor, offset: u64, flags: ReadWriteFlags, user_data: u64, iov: *const [libc::iovec]) {
        self.iov(Opcode::READV, priority, fd, offset, flags, user_data, iov)
    }

    pub fn writev(&mut self, priority: IOPriority, fd: FileDescriptor, offset: u64, flags: ReadWriteFlags, user_data: u64, iov: *const [libc::iovec]) {
        self.iov(Opcode::WRITEV, priority, fd, offset, flags, user_data, iov)
    }
    
}
