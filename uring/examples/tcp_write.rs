use std::net::TcpStream;
use std::os::unix::io::IntoRawFd;
use uring_sys::{FileDescriptor, IOPriority, IoUringBuilder};

fn iovec_from(data: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    }
}

pub fn main() -> std::io::Result<()> {
    let queue_depth = 4096;
    let mut uring = IoUringBuilder::new()
        .with_submission_queue_entries(queue_depth)
        .build()
        .unwrap();

    let stream = TcpStream::connect("0.0.0.0:9090")?;
    let fd = stream.into_raw_fd();

    let string_hello = "Hello";
    let string_world = ", world";
    let iov_hello: [libc::iovec; 2] = [
        iovec_from(string_hello.as_bytes()),
        iovec_from(string_world.as_bytes()),
    ];
    let offset = 0;

    let user_data = 0xFACA_DEFA_CADE_FAFA;
    let rw_flags = Default::default();
    let mut sqe = uring.new_submission().unwrap();
    unsafe {
        sqe.writev(
            0 as IOPriority,
            FileDescriptor::FD(fd),
            offset,
            rw_flags,
            user_data,
            &iov_hello,
        )
    };

    uring.submit().unwrap();

    Ok(())
}
