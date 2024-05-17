#![crate_type = "proc-macro"]
extern crate proc_macro;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

use anyhow::Ok;
use colored::Colorize;
use git_simple_encrypt::*;
use rand::seq::SliceRandom;
use tap::Tap;
use temp_testdir::TempDir;

#[tokio::test]
async fn test() -> anyhow::Result<()> {
    let _ = env_logger::try_init();
    let _lock = TempDir::default();
    let temp_dir = &_lock;
    let exec = |cmd: &str| -> std::io::Result<Output> {
        let mut temp = cmd.split_whitespace();
        let mut command = Command::new(temp.next().unwrap());
        command.args(temp).current_dir(temp_dir).output()
    };
    macro_rules! run {
        ($cmd:expr) => {
            run(&Cli {
                command: $cmd,
                repo: temp_dir.to_path_buf(),
            })
            .await?;
        };
    }

    // Initialize a new repository
    exec("git init")?;

    // Create a new file and stage it for commit
    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    std::fs::write(temp_dir.join("t3.txt"), "do not crypt")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;
    assert!(temp_dir.join("t1.txt").is_file());
    assert!(temp_dir.join("t2.txt").is_file());

    // Set key
    run!(SubCommand::Set {
        field: SetField::key,
        value: "123".to_owned(),
    });

    // Add file
    run!(SubCommand::Add {
        path: ["t1.txt", "t2.txt", "dir"]
            .map(ToString::to_string)
            .to_vec(),
    });

    // Encrypt
    run!(SubCommand::Encrypt);

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
    run!(SubCommand::Decrypt);
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

#[tokio::test]
async fn test_reencrypt() -> anyhow::Result<()> {
    let _ = env_logger::try_init();
    let _lock = TempDir::default();
    let temp_dir = &_lock;
    let exec = |cmd: &str| -> std::io::Result<Output> {
        let mut temp = cmd.split_whitespace();
        let mut command = Command::new(temp.next().unwrap());
        command.args(temp).current_dir(temp_dir).output()
    };
    macro_rules! run {
        ($cmd:expr) => {
            run(&Cli {
                command: $cmd,
                repo: temp_dir.to_path_buf(),
            })
            .await?;
        };
    }

    exec("git init")?;
    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Set key
    run!(SubCommand::Set {
        field: SetField::key,
        value: "123".to_owned(),
    });

    // Add file
    run!(SubCommand::Add {
        path: ["t1.txt", "dir"].map(ToString::to_string).to_vec(),
    });

    // Encrypt multiple times
    run!(SubCommand::Encrypt);
    run!(SubCommand::Encrypt);
    run!(SubCommand::Encrypt);

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
    run!(SubCommand::Decrypt);
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

#[tokio::test]
#[ignore = "This test takes too long to run, and it's not necessary to run it every time. You can run it manually if you want."]
async fn test_many_files() -> anyhow::Result<()> {
    let _lock = TempDir::default();
    let temp_dir = &_lock;
    let exec = |cmd: &str| -> std::io::Result<Output> {
        let mut temp = cmd.split_whitespace();
        let mut command = Command::new(temp.next().unwrap());
        command.args(temp).current_dir(temp_dir).output()
    };
    macro_rules! run {
        ($cmd:expr) => {
            run(&Cli {
                command: $cmd,
                repo: temp_dir.to_path_buf(),
            })
            .await?;
        };
    }

    exec("git init")?;
    let dir = temp_dir.join("dir");
    std::fs::create_dir(&dir)?;
    let files = (1..2000)
        .map(|i| {
            dir.join(format!("file{}.txt", i))
                .tap(|f| std::fs::write(f, "Hello").unwrap())
        })
        .collect::<Vec<PathBuf>>();

    // Set key
    run!(SubCommand::Set {
        field: SetField::key,
        value: "123".to_owned(),
    });

    // Add file
    run!(SubCommand::Add {
        path: vec!["dir".into()]
    });

    // Encrypt
    run!(SubCommand::Encrypt);
    // Decrypt
    run!(SubCommand::Decrypt);

    // Test
    for _ in 1..10 {
        let file_name = files.choose(&mut rand::thread_rng()).unwrap();
        println!("Testing file: {}", file_name.display());
        assert_eq!(std::fs::read_to_string(file_name)?, "Hello");
    }

    Ok(())
}
