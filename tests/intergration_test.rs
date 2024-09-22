#![feature(test)]

extern crate test;

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::Ok;
use colored::Colorize;
use git_simple_encrypt::{Cli, SetField, SubCommand};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use tap::Tap;
use tempfile::TempDir;
use test::Bencher;

fn bench_init() -> TempDir {
    let pwd = TempDir::new().unwrap();

    // Initialize a new repository
    exec("git init", pwd.path()).unwrap();
    // Set key
    run(
        SubCommand::Set {
            field: SetField::key,
            value: "12345678910987654321".to_owned(),
        },
        pwd.path(),
    )
    .unwrap();

    pwd
}

fn test_init() -> TempDir {
    _ = env_logger::try_init();
    bench_init()
}

fn exec(cmd: &str, pwd: impl AsRef<Path>) -> std::io::Result<Output> {
    let mut temp = cmd.split_whitespace();
    let mut command = Command::new(temp.next().unwrap());
    command.args(temp).current_dir(pwd.as_ref()).output()
}

fn run(cmd: SubCommand, pwd: impl Into<PathBuf>) -> anyhow::Result<()> {
    let pwd = pwd.into();
    std::env::set_current_dir(&pwd).unwrap();
    git_simple_encrypt::run(&Cli {
        command: cmd,
        repo: pwd,
    })?;
    Ok(())
}

#[test]
fn test() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    // Create a new file and stage it for commit
    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    std::fs::write(temp_dir.join("t3.txt"), "do not crypt")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;
    assert!(temp_dir.join("t1.txt").is_file());
    assert!(temp_dir.join("t2.txt").is_file());

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "t2.txt", "dir"]
                .map(ToString::to_string)
                .to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt
    run(SubCommand::Encrypt, temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    dbg!(std::fs::read_to_string(temp_dir.join("git_simple_encrypt.toml")).unwrap());
    assert!(temp_dir.join("t1.txt.enc").exists());
    assert!(temp_dir.join("t2.txt.zst.enc").exists());
    assert!(temp_dir.join("t3.txt").exists());
    assert!(temp_dir.join("dir/t4.txt.enc").exists());
    assert!(!temp_dir.join("t1.txt").exists());
    assert!(!temp_dir.join("t2.txt").exists());
    assert!(!temp_dir.join("dir/t4.txt").exists());

    // Decrypt
    run(SubCommand::Decrypt { path: None }, temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    assert!(temp_dir.join("t1.txt").exists());
    assert!(temp_dir.join("t2.txt").exists());
    assert!(temp_dir.join("t3.txt").exists());
    assert!(temp_dir.join("dir/t4.txt").exists());
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t3.txt"))?,
        "do not crypt"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t4.txt"))?,
        "dir test"
    );
    Ok(())
}

#[test]
fn test_reencrypt() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(ToString::to_string).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt multiple times
    run(SubCommand::Encrypt, temp_dir)?;
    run(SubCommand::Encrypt, temp_dir)?;
    run(SubCommand::Encrypt, temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    temp_dir
        .join("dir")
        .read_dir()?
        .for_each(|x| println!("{:?}", x));
    assert!(temp_dir.join("t1.txt.enc").exists());
    assert!(temp_dir.join("dir/t4.txt.enc").exists());
    assert!(!temp_dir.join("t1.txt").exists());
    assert!(!temp_dir.join("dir/t4.txt").exists());

    // Decrypt
    run(SubCommand::Decrypt { path: None }, temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test

    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").exists());
    assert!(temp_dir.join("dir/t4.txt").exists());
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t4.txt"))?,
        "dir test"
    );

    Ok(())
}

#[test]
#[ignore = "This test takes too long to run, and it's not necessary to run it every time. You can run it manually if you want."]
fn test_many_files() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let dir = temp_dir.join("dir");
    std::fs::create_dir(&dir)?;
    let files = (1..2000)
        .map(|i| {
            dir.join(format!("file{}.txt", i))
                .tap(|f| std::fs::write(f, "Hello").unwrap())
        })
        .collect::<Vec<PathBuf>>();

    // Add file
    run(
        SubCommand::Add {
            paths: vec!["dir".into()],
        },
        temp_dir,
    )?;

    // Encrypt
    run(SubCommand::Encrypt, temp_dir)?;
    // Decrypt
    run(SubCommand::Decrypt { path: None }, temp_dir)?;

    // Test
    for _ in 1..10 {
        let file_name = files.choose(&mut rand::thread_rng()).unwrap();
        println!("Testing file: {}", file_name.display());
        assert_eq!(std::fs::read_to_string(file_name)?, "Hello");
    }

    Ok(())
}

#[test]
fn test_partial_decrypt() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(ToString::to_string).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt
    run(SubCommand::Encrypt, temp_dir)?;

    // Partial decrypt
    run(
        SubCommand::Decrypt {
            path: Some("dir/**".into()),
        },
        temp_dir,
    )?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt.enc").exists());
    assert!(temp_dir.join("dir/t4.txt").exists());

    // Reencrypt
    run(SubCommand::Encrypt, temp_dir)?;

    // Partial decrypt
    run(
        SubCommand::Decrypt {
            path: Some("t1.txt.enc".into()),
        },
        temp_dir,
    )?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").exists());
    assert!(temp_dir.join("dir/t4.txt.enc").exists());

    Ok(())
}

#[bench]
fn bench_encrypt_and_decrypt(b: &mut Bencher) -> anyhow::Result<()> {
    const FILES_NUM: i32 = 3;
    const FILE_SIZE: usize = 100;

    let pwd = bench_init();
    let temp_dir = pwd.path();
    let inner_dir = temp_dir.join("dir");
    std::fs::create_dir(&inner_dir).unwrap();

    let mut rng = rand::rngs::SmallRng::from_seed([0, 1].repeat(16).as_slice().try_into().unwrap());
    let mut random_vec = || {
        let mut v = Vec::with_capacity(FILE_SIZE);
        for _ in 0..FILE_SIZE {
            v.push(rng.gen::<u8>());
        }
        v
    };
    for i in 1..=FILES_NUM {
        std::fs::write(inner_dir.join(format!("file{}", i)), random_vec()).unwrap();
    }

    run(
        SubCommand::Add {
            paths: vec![inner_dir.to_string_lossy().to_string()],
        },
        temp_dir,
    )?;

    b.iter(|| {
        run(SubCommand::Encrypt, temp_dir).unwrap();
        run(SubCommand::Decrypt { path: None }, temp_dir).unwrap();
    });

    Ok(())
}
