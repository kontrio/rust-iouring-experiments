use crate::ContiguousMem;

fn last_os_err() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[derive(Debug)]
pub struct MappedMemory {
    addr: *mut libc::c_void,
    length: usize,
}

impl MappedMemory {
    pub fn map(file_descriptor: i32, offset: u64, length: usize) -> Result<Self, i32> {
        let addr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                file_descriptor,
                offset as libc::c_long,
            )
        };

        if addr == libc::MAP_FAILED {
            Err(last_os_err())
        } else {
            Ok(Self { addr, length })
        }
    }

    pub fn get_offset<T>(&self, offset: usize) -> *mut T {
        unsafe { self.addr.offset(offset as isize) as *mut T }
    }

    pub fn debug_print_mem(&self) {
        let mem = unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.length) };
        // *feels sick*
        let format_str: &'static [libc::c_char; 8] = &[
            b'0' as i8, b'x' as i8, b'%' as i8, b'0' as i8, b'2' as i8, b'X' as i8, b' ' as i8,
            0_i8,
        ];
        let num_fmt: &'static [libc::c_char; 17] = &[
            b'0' as i8, b'x' as i8, b'%' as i8, b'0' as i8, b'1' as i8, b'6' as i8, b'l' as i8,
            b'l' as i8, b'X' as i8, b'[' as i8, b'%' as i8, b'0' as i8, b'4' as i8, b'd' as i8,
            b']' as i8, b' ' as i8, 0_i8,
        ];
        let new_line = &[b'\n' as i8, 0_i8];
        let mut i = 0;
        for bytes in mem.chunks(4) {
            unsafe { libc::printf(num_fmt.as_ptr(), self.addr as u64 + i, i) };
            for byte in bytes.iter() {
                unsafe { libc::printf(format_str.as_ptr(), *byte as *const libc::c_uint) };
            }
            unsafe { libc::printf(new_line.as_ptr()) };
            i += 4;
        }
    }
}

impl ContiguousMem for MappedMemory {
    fn offset<T>(&self, offset: usize) -> *const T {
        self.get_offset(offset as usize)
    }
}

impl Drop for MappedMemory {
    fn drop(&mut self) {
        if self.length > 0 {
            let munmap_result = unsafe { libc::munmap(self.addr, self.length) };

            if munmap_result != 0 {
                panic!(
                    "a uring munmap(0x{:x}, {}) -> {} failed",
                    self.addr as usize,
                    self.length,
                    last_os_err()
                );
            }
        }
    }
}
