//! Single dispatch point for data-parallel workloads, so the parallel
//! backend is swappable and benchmarkable.
//!
//! - default: youpipe fused engine (`pipe_ref().for_each()`)
//! - feature `rayon-backend`: rayon `par_iter().for_each()`
//!
//! Both variants accept a `Fn(&T) + Sync` closure that may borrow
//! stack-local data; the terminal call blocks until all workers finish.

#[cfg(feature = "rayon-backend")]
pub fn for_each<T: Sync>(items: &[T], f: impl Fn(&T) + Sync + Send) {
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
    items.par_iter().for_each(f);
}

#[cfg(not(feature = "rayon-backend"))]
pub fn for_each<T: Sync>(items: &[T], f: impl Fn(&T) + Sync) {
    use youpipe::Workload;
    // File sizes are heavily skewed (a few large files dominate total bytes),
    // so oversplit fine leaves to let idle workers steal around slow items.
    youpipe::pipe_ref(items)
        .with_workload(Workload::Unbalanced)
        .for_each(f);
}
