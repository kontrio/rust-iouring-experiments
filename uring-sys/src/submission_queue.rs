use core::pin::Pin;
use crate::{
    ContiguousMem,
    EnterFlag,
    SetupFlag,
    SetupParameters,
    SubmissionQueueEntry,
    SubmissionQueueFlag,
    SyscallLib,
};

#[derive(Debug)]
pub enum SubmissionError {
    QueueFull,
}

#[derive(Debug)]
pub struct SubmissionQueue<M: ContiguousMem, S: SyscallLib> {
    k_head: *mut u32,
    k_tail: *mut u32,
    k_ring_mask: *mut u32,
    k_ring_entries: *mut u32,
    k_flags: *mut u32,
    k_dropped: *mut u32,

    arr: *mut u32,

    head: u32,
    tail: u32,

    size: usize,

    setup_flags: SetupFlag,
    uring_fd: i32,

    entries_memory: M,

    syscall_lib_marker: core::marker::PhantomData<S>,
}

impl<M: ContiguousMem, S: SyscallLib> SubmissionQueue<M, S> {
    pub fn new(
        size: usize, 
        uring_fd: i32,
        sq_memory: &M, 
        entries_memory: M, 
        params: &SetupParameters) -> Self {

        SubmissionQueue {
            k_head:         sq_memory.offset_mut(params.sq_ring_offsets.head as usize),
            k_tail:         sq_memory.offset_mut(params.sq_ring_offsets.tail as usize),
            k_ring_mask:    sq_memory.offset_mut(params.sq_ring_offsets.ring_mask as usize),
            k_ring_entries: sq_memory.offset_mut(params.sq_ring_offsets.ring_entries as usize), 
            k_flags:        sq_memory.offset_mut(params.sq_ring_offsets.flags as usize),
            k_dropped:      sq_memory.offset_mut(params.sq_ring_offsets.dropped as usize),
            arr:            sq_memory.offset_mut(params.sq_ring_offsets.array as usize),

            head: 0,
            tail: 0,

            size,
            setup_flags: params.flags,
            uring_fd,
            entries_memory,

            syscall_lib_marker: core::marker::PhantomData,
        }
    }

    pub fn get_next_entry(&mut self) -> Result<Pin<&'static mut SubmissionQueueEntry>, SubmissionError> {
        let next = self.tail + 1;

        if (next - self.head) > unsafe { *self.k_ring_entries } {
            Err(SubmissionError::QueueFull)
        } else {
            let entry_index = self.tail & unsafe { *self.k_ring_mask };
            let entry = self.get_entry_at_index(entry_index as usize);

            self.tail = next;
            Ok(Pin::new(unsafe { &mut *entry}))
        }
    }

    fn flush(&mut self) -> u32 {
        let mask = unsafe { *self.k_ring_mask };

        if self.head == self.tail {
            0
        } else {
            // flush all the sqes that have been queued
            let to_submit = self.tail - self.head;

            let mut k_tail = unsafe { *self.k_tail };
            for _ in 0..to_submit {
                let offset = k_tail & mask; 
                unsafe { *self.arr.offset(offset as isize) = self.head & mask };
                k_tail += 1;
                self.head += 1;
            }

            if to_submit > 0 {
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                unsafe { core::ptr::write_volatile(self.k_tail, k_tail) };
            }

            to_submit
        }
    }

    pub fn submit(&mut self) -> Result<u32, i32> {
        self.submit_and_wait(0)
    }

    fn submit_and_wait(&mut self, wait: u32) -> Result<u32, i32> {
        let submitted = self.flush();
        if submitted > 0 {
            return self.submit_impl(submitted, wait);
        }

        Ok(0)
    }

    fn submit_impl(&mut self, submitted: u32, wait: u32) -> Result<u32, i32> {
        let mut flags: EnterFlag = EnterFlag::EMPTY;
        let has_wait = wait > 0;

        if has_wait || self.needs_enter(&mut flags) {
            if has_wait && wait > submitted {
                flags |= EnterFlag::GETEVENTS;
            }

            let result = S::io_uring_enter(self.uring_fd, submitted, wait, flags.bits(), core::ptr::null());
            if result < 0 {
                return Err(result);
            }

            Ok(submitted)
        } else {
            Ok(0)
        }
    }

    // bluehh: &mut EnterFlag
    fn needs_enter(&mut self, flags: &mut EnterFlag) -> bool {
        if (self.setup_flags & SetupFlag::SQ_POLL).bits() == 0 {
            true
        } else {
            //TODO: refactor the shit out of this ugliness ..
            if (unsafe { *self.k_flags } & SubmissionQueueFlag::NEED_WAKEUP.bits()) != 0 {
                *flags |= EnterFlag::SQ_WAKEUP;
                true
            } else {
                false
            }
        }
    }

    fn get_entry_at_index(&self, index: usize) -> *mut SubmissionQueueEntry {
        self.entries_memory.offset_mut::<SubmissionQueueEntry>(index * core::mem::size_of::<SubmissionQueueEntry>())
    }
}

#[cfg(test)]
mod test {
    use byteorder::{ 
        ByteOrder, 
        NativeEndian, 
    };
    use crate::{
        FileDescriptor,
        Opcode,
        ReadWriteFlags,
        SubmissionEntryFlags,
        SubmissionQueueRingOffsets,
    };
    use libc::{
        c_int,
        c_uint,
        c_void,
    };
    use super::*;

    struct MockSyscallLib;

    impl SyscallLib for MockSyscallLib {
        fn io_uring_register(_fd: c_int, _opcode: c_uint, _arg: *const c_void, _nr_args: c_uint) -> c_int { 0 }
        fn io_uring_enter(_fd: c_int, _to_submit: c_uint, _min_complete: c_uint, _flags: c_uint, _sigs: *const libc::sigset_t) -> c_int { 0 }
        fn io_uring_setup(_entries: usize, _io_uring_params: *mut SetupParameters) -> c_int { 3 }
    }

    
    impl ContiguousMem for *const u8 {
        fn offset<T>(&self, offset: usize) -> *const T {
            unsafe { Self::offset(*self, offset as isize) as *const T }
        }
    }
    
    fn iovec_from(data: &[u8]) -> libc::iovec {
        libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        }
    }

    #[test]
    fn test_get_entry_readv() {
        // submission queue memory
        let mut mem: [u8; 160] = [0; 160];
        // entries:
        NativeEndian::write_u32(&mut mem[12..16], 2);

        let fd = 3;
        let size = 2;
        let params = create_setup_parameters();

        let mut submission_queue: SubmissionQueue<*const u8, MockSyscallLib> = SubmissionQueue::new(size, fd, &mem[0..32].as_ptr(), mem[32..160].as_ptr(), &params);

        let test_data: [libc::iovec; 2] = [iovec_from("hello".as_bytes()), iovec_from(", world".as_bytes())]; 
        // Mutating an entry should update the memory visible to the kernel (no copying mem to the
        // kernel)
        let mut entry = submission_queue.get_next_entry().unwrap();
        unsafe { entry.readv(5, FileDescriptor::FD(4), 0x10FEEDF00D0FF5E7, ReadWriteFlags::NOWAIT, 0xFACADEFACADEFACE, &test_data); }

        assert_eq!(Opcode::READV.bits(), mem[32]);
        assert_eq!(SubmissionEntryFlags::FIXED_FILE.bits(), mem[33]);
        assert_eq!(5, NativeEndian::read_u16(&mem[34..36]));
        assert_eq!(4, NativeEndian::read_i32(&mem[36..40]));
        assert_eq!(0x10FEEDF00D0FF5E7, NativeEndian::read_u64(&mem[40..48]));
        assert_eq!(test_data.as_ptr() as u64, NativeEndian::read_u64(&mem[48..56]));
        assert_eq!(2, NativeEndian::read_u32(&mem[56..60]));
        assert_eq!(ReadWriteFlags::NOWAIT.bits(), NativeEndian::read_u32(&mem[60..64]));
        assert_eq!(0xFACADEFACADEFACE, NativeEndian::read_u64(&mem[64..72]));
    }
    
    #[test]
    fn test_get_entry_writev() {
        // submission queue memory
        let mut mem: [u8; 160] = [0; 160];
        // entries:
        NativeEndian::write_u32(&mut mem[12..16], 2);

        let fd = 3;
        let size = 2;
        let params = create_setup_parameters();

        let mut submission_queue: SubmissionQueue<*const u8, MockSyscallLib> = SubmissionQueue::new(size, fd, &mem[0..32].as_ptr(), mem[32..160].as_ptr(), &params);

        let buffer: [libc::iovec; 2] = [iovec_from("hello".as_bytes()), iovec_from(", world".as_bytes())]; 
        // Mutating an entry should update the memory visible to the kernel (no copying mem to the
        // kernel)
        let mut entry = submission_queue.get_next_entry().unwrap();
        unsafe { entry.writev(5, FileDescriptor::FD(4), 0x10FEEDF00D0FF5E7, ReadWriteFlags::NOWAIT, 0xFACADEFACADEFACE, &buffer); }

        assert_eq!(Opcode::WRITEV.bits(), mem[32]);
        assert_eq!(SubmissionEntryFlags::FIXED_FILE.bits(), mem[33]);
        assert_eq!(5, NativeEndian::read_u16(&mem[34..36]));
        assert_eq!(4, NativeEndian::read_i32(&mem[36..40]));
        assert_eq!(0x10FEEDF00D0FF5E7, NativeEndian::read_u64(&mem[40..48]));
        assert_eq!(buffer.as_ptr() as u64, NativeEndian::read_u64(&mem[48..56]));
        assert_eq!(2, NativeEndian::read_u32(&mem[56..60]));
        assert_eq!(ReadWriteFlags::NOWAIT.bits(), NativeEndian::read_u32(&mem[60..64]));
        assert_eq!(0xFACADEFACADEFACE, NativeEndian::read_u64(&mem[64..72]));
    }
    
    #[test]
    fn test_get_entry_twice_and_flush() {
        // submission queue memory
        let mut mem: [u8; 160] = [0; 160];
        // entries:
        NativeEndian::write_u32(&mut mem[12..16], 2);
        NativeEndian::write_u32(&mut mem[8..12], 1);

        let fd = 3;
        let size = 2;
        let params = create_setup_parameters();

        let mut submission_queue: SubmissionQueue<*const u8, MockSyscallLib> = SubmissionQueue::new(size, fd, &mem[0..32].as_ptr(), mem[32..160].as_ptr(), &params);

        let buffer: [libc::iovec; 2] = [iovec_from("hello".as_bytes()), iovec_from(", world".as_bytes())]; 
        // Mutating an entry should update the memory visible to the kernel (no copying mem to the
        // kernel)
        let mut entry = submission_queue.get_next_entry().unwrap();
        unsafe { entry.writev(5, FileDescriptor::FD(4), 0x10FEEDF00D0FF5E7, ReadWriteFlags::NOWAIT, 0xFACADEFACADEFACE, &buffer); }
        let mut entry_b = submission_queue.get_next_entry().unwrap();
        unsafe { entry_b.writev(5, FileDescriptor::FD(4), 0x10FEEDF00D0FF5E7, ReadWriteFlags::NOWAIT, 0xFACADEFACADEFACE, &buffer); }

        assert_eq!(Opcode::WRITEV.bits(), mem[32]);
        assert_eq!(SubmissionEntryFlags::FIXED_FILE.bits(), mem[33]);
        assert_eq!(5, NativeEndian::read_u16(&mem[34..36]));
        assert_eq!(4, NativeEndian::read_i32(&mem[36..40]));
        assert_eq!(0x10FEEDF00D0FF5E7, NativeEndian::read_u64(&mem[40..48]));
        assert_eq!(buffer.as_ptr() as u64, NativeEndian::read_u64(&mem[48..56]));
        assert_eq!(2, NativeEndian::read_u32(&mem[56..60]));
        assert_eq!(ReadWriteFlags::NOWAIT.bits(), NativeEndian::read_u32(&mem[60..64]));
        assert_eq!(0xFACADEFACADEFACE, NativeEndian::read_u64(&mem[64..72]));
        
        let offset = core::mem::size_of::<SubmissionQueueEntry>() * 1;
        assert_eq!(Opcode::WRITEV.bits(), mem[32 + offset]);
        assert_eq!(SubmissionEntryFlags::FIXED_FILE.bits(), mem[33 + offset]);
        assert_eq!(5, NativeEndian::read_u16(&mem[34 + offset..36 + offset]));
        assert_eq!(4, NativeEndian::read_i32(&mem[36 + offset..40 + offset]));
        assert_eq!(0x10FEEDF00D0FF5E7, NativeEndian::read_u64(&mem[40 + offset..48 + offset]));
        assert_eq!(buffer.as_ptr() as u64, NativeEndian::read_u64(&mem[48 + offset..56 + offset]));
        assert_eq!(2, NativeEndian::read_u32(&mem[56 + offset..60 + offset]));
        assert_eq!(ReadWriteFlags::NOWAIT.bits(), NativeEndian::read_u32(&mem[60 + offset..64 + offset]));
        assert_eq!(0xFACADEFACADEFACE, NativeEndian::read_u64(&mem[64 + offset..72 + offset]));

        // k_tail is 0 before flushing to the kernel
        assert_eq!(0, NativeEndian::read_u32(&mem[4..8]));
        submission_queue.submit().unwrap();
        // k_tail is 2 after flush (since we made two submissions)
        assert_eq!(2, NativeEndian::read_u32(&mem[4..8]));
    }

    fn _debug_print_mem(mem: &[u8]) {
        // *feels sick*
        let format_str: &'static [libc::c_char; 8] = &[b'0' as i8, b'x' as i8, b'%' as i8, b'0' as i8, b'2' as i8, b'X' as i8, b' ' as i8, 0_i8];
        let num_fmt: &'static [libc::c_char; 7] = &[b'%' as i8, b'0' as i8, b'4' as i8, b'd' as i8, b':' as i8, b' ' as i8, 0_i8]; 
        let new_line = &[b'\n' as i8, 0_i8];
        let mut i = 0;
        for bytes in mem.chunks(4) {

            unsafe { libc::printf(num_fmt.as_ptr(), i) };
            for byte in bytes.iter() {
                unsafe { libc::printf(format_str.as_ptr(), *byte as *const libc::c_uint) };
            }
            unsafe { libc::printf(new_line.as_ptr()) };
            i += 4;
        }
    }

    fn create_setup_parameters() -> SetupParameters {
        SetupParameters {
            submission_queue_entries: 1,
            completion_queue_entries: 1,
            flags: Default::default(),
            submission_queue_thread_cpu: 0,
            submission_queue_thread_idle: 0,
            features: Default::default(),
            __reserved: [0; 4],
            sq_ring_offsets: SubmissionQueueRingOffsets {
                head: 0,
                tail: 4,
                ring_mask: 8,
                ring_entries: 12,
                flags: 16,
                dropped: 20,
                array: 24,
                __resv1: 0,
                __resv2: 0,
            },
            cq_ring_offsets: Default::default(),
        }
    }
}
