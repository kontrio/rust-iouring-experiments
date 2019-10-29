use std::cell::Cell;
use std::fs::File;
use std::future::{ Future, };
use std::task::{ Context, Waker, Poll };
use std::pin::Pin;
use std::rc::Rc;

use std::os::unix::io::AsRawFd;
use uring_sys::{
    FileDescriptor,
    IOPriority,
    IoUringBuilder,
    Uring
};

#[derive(Copy, Clone)]
enum CompletionState {
    Pending,
    Submitted,
    Completed(i32),
}

struct IoTask<'a> {
    state: Cell<CompletionState>,
    buf: &'a [u8],

    waker: Option<Waker>,
}

impl<'a> IoTask<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            state: Cell::new(CompletionState::Pending),
            waker: None,
        }
    }

    fn as_iovec(&self) -> [libc::iovec; 1] {
        [iovec_from(self.buf)]
    }

    fn set_state(&self, state: CompletionState) {
        self.state.set(state);

        if let Some(ref waker) = self.waker {
            waker.wake_by_ref();
        }
    }
}

impl Future for TaskHandle<'_> {
    type Output = std::io::Result<i32>;
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        match self.0.state.get() {
            CompletionState::Pending | CompletionState::Submitted => {
                let waker = ctx.waker().clone();
                if let Some(ref mut inner) = Rc::get_mut(&mut self.0) {
                    inner.waker = Some(waker);
                }

                Poll::Pending
            },
            CompletionState::Completed(result) => {
                if result < 0 {
                    Poll::Ready(Err(std::io::Error::from_raw_os_error(-result)))
                } else {
                    Poll::Ready(Ok(result)) 
                }
            },
        }
    }
}

struct IoTaskDriver {
    uring: Uring,
}

impl IoTaskDriver {
    fn new() -> std::io::Result<Self> {
        let uring = IoUringBuilder::new()
            .with_submission_queue_entries(4096)
            .build()
            .map_err(std::io::Error::from_raw_os_error)?;
        Ok(Self {
            uring,
        })
    }
}

struct TaskHandle<'a>(Rc<IoTask<'a>>);
    
fn iovec_from(data: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    }
}

impl IoTaskDriver {
    fn read_at<'a, F: AsRawFd>(&mut self, fd: &F, buf: &'a mut [u8], offset: u64) -> std::io::Result<TaskHandle<'a>> {
        if let Some(ref mut submission) = self.uring.new_submission() {
            // take an ownership of the buf reference in the IoTask
            let task = Rc::new(IoTask::new(buf));

            // Increment the reference count by cloning, then turn the clone into a raw ptr 
            // so that we pass the kernel ownership of this reference - we do this
            // using the "user_data" field in the uring submission - which we should get back from
            // the kernel with a completion event, which we will turn back into the Rc, and retake
            // ownership
            let kernels_ref = Rc::clone(&task);
            let kernels_raw_ptr = Rc::into_raw(kernels_ref) as u64;

            submission.readv(0 as IOPriority, FileDescriptor::FD(fd.as_raw_fd()), offset, Default::default(), kernels_raw_ptr, &task.as_iovec());

            Ok(TaskHandle(task))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "IO submission queue is full"))
        }
    }


    fn turn(&mut self) -> usize {
        self.uring.submit();
        let mut completed = 0;
        for completion in self.uring.drain() {
            // take ownership back from the kernel
            let io_task: Rc<IoTask<'_>> = unsafe { Rc::from_raw(completion.user_data as *const IoTask) };
            io_task.set_state(CompletionState::Completed(completion.result));
            if completion.result < 0 {
                println!("{:?}", std::io::Error::last_os_error());
            }
            completed += 1;
        }
        completed
    }
}

#[tokio::main(single_thread)]
pub async fn main() -> std::io::Result<()> {
    let mut io_task_driver = IoTaskDriver::new()?;
    // TODO: can we make this an IO task, maybe with a supplemental thread pool for file tasks that
    // don't yet have uring opcodes?

    let file = std::fs::File::open("/tmp/a-test-file")?;
    let mut buffer: Vec<u8> = vec![0;10];
    let task = io_task_driver.read_at(&file, buffer.as_mut_slice(), 0)?;

    loop {
        let completed = io_task_driver.turn();
        if completed == 0 {
            std::thread::yield_now();
        } else {
            let value = task.await?;
            println!("value: {:?}", String::from_utf8(buffer));
            
            // do workl
            break;
        }
    }

    Ok(())
}
