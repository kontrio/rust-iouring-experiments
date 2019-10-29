///! These syscalls are only necessary until libc has support for io_uring
use crate::{ SetupParameters, };
use libc::{
    c_int,
    c_uint,
    c_void,
    c_long,
};

const SYS_IO_URING_SETUP: c_long = 425;
const SYS_IO_URING_ENTER: c_long = 426;
const SYS_IO_URING_REGISTER: c_long = 427;

pub trait SyscallLib {
    fn io_uring_register(fd: c_int, opcode: c_uint, arg: *const c_void, nr_args: c_uint) -> c_int;
    fn io_uring_enter(fd: c_int, to_submit: c_uint, min_complete: c_uint, flags: c_uint, sigs: *const libc::sigset_t) -> c_int;
    fn io_uring_setup(entries: usize, io_uring_params: *mut SetupParameters) -> c_int;
}

pub struct Syscalls;

impl SyscallLib for Syscalls {
    #[inline]
    fn io_uring_register(fd: c_int, opcode: c_uint, arg: *const c_void, nr_args: c_uint) -> c_int {
        unsafe {
            libc::syscall(
                SYS_IO_URING_REGISTER,
                fd as c_long,
                opcode as c_long,
                arg as usize as c_long,
                nr_args as c_long,
            ) as c_int
        }
    }

    #[inline]
    fn io_uring_enter(fd: c_int, to_submit: c_uint, min_complete: c_uint, flags: c_uint, sigs: *const libc::sigset_t) -> c_int {
        unsafe {
            libc::syscall(
                SYS_IO_URING_ENTER,
                fd as c_long,
                to_submit as c_long,
                min_complete as c_long,
                flags as c_long,
                sigs as usize as c_long,
                core::mem::size_of::<libc::sigset_t>() as c_long,
            ) as c_int
        }
    }

    #[inline]
    fn io_uring_setup(entries: usize, io_uring_params: *mut SetupParameters) -> c_int {
        unsafe {
            libc::syscall(
                SYS_IO_URING_SETUP,
                entries as c_long,
                io_uring_params as usize as c_long,
            ) as c_int
        }
    }
}
