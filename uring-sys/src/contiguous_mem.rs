pub trait ContiguousMem {
    fn offset<T>(&self, offset: usize) -> *const T;
    
    fn offset_mut<T>(&self, offset: usize) -> *mut T {
        self.offset::<T>(offset) as *mut T
    }
}
