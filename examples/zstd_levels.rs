//! Level sweep on real files: time and ratio per level.
use std::time::Instant;

use youpipe::pipe_ref;

// Benchmark-only casts are fine.
#[allow(clippy::cast_precision_loss)]

fn main() {
    let files: Vec<std::path::PathBuf> = std::env::args()
        .skip(1)
        .flat_map(|dir| walkdir(&dir))
        .collect();
    let total: u64 = files.iter().map(|f| f.metadata().unwrap().len()).sum();
    println!("{} files, {:.1} MB", files.len(), total as f64 / 1e6);

    for level in [1, 3, 5, 9, 12, 15, 19] {
        let t = Instant::now();
        let v: Vec<usize> = pipe_ref(&files)
            .map(|f| {
                let data = std::fs::read(f).unwrap();
                zstd::bulk::compress(&data, level).unwrap().len()
            })
            .collect();
        let out: usize = v.iter().sum();
        let d = t.elapsed().as_secs_f64();
        println!(
            "level {level:2}: {d:.2}s ({:6.1} MB/s), ratio {:.3}",
            total as f64 / 1e6 / d,
            total as f64 / out as f64
        );
    }
}

fn walkdir(dir: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                out.push(e.path());
            }
        }
    }
    out
}
