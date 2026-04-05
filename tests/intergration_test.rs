use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::Ok;
use colored::Colorize;
use git_simple_encrypt::{Cli, FileHeader, SetField, SubCommand};
use rand::prelude::*;
use tap::Tap;
use tempfile::TempDir;

fn bench_init() -> TempDir {
    let pwd = TempDir::new().unwrap();

    // Initialize a new repository
    exec("git init", pwd.path()).unwrap();
    // Set key
    run(
        SubCommand::Set {
            field: SetField::Key {
                value: "12345678910987654321".to_owned(),
            },
        },
        pwd.path(),
    )
    .unwrap();

    pwd
}

fn test_init() -> TempDir {
    _ = pretty_env_logger::try_init();
    bench_init()
}

fn exec(cmd: &str, pwd: impl AsRef<Path>) -> std::io::Result<Output> {
    let mut temp = cmd.split_whitespace();
    let mut command = Command::new(temp.next().unwrap());
    command.args(temp).current_dir(pwd.as_ref()).output()
}

fn run(cmd: SubCommand, pwd: impl Into<PathBuf>) -> anyhow::Result<()> {
    let pwd = pwd.into();
    git_simple_encrypt::run(Cli {
        command: cmd,
        repo: pwd,
    })?;
    Ok(())
}

trait PathExt {
    fn is_encrypted(&self) -> bool;
    fn is_compressed(&self) -> bool;
    fn is_not_encrypted(&self) -> bool {
        !self.is_encrypted()
    }
}

impl<T> PathExt for T
where
    T: AsRef<Path>,
{
    fn is_encrypted(&self) -> bool {
        let mut f = fs::File::open(self.as_ref()).unwrap();
        FileHeader::read_from(&mut f).is_ok()
    }

    /// Check if the file is both encrypted and compressed.
    fn is_compressed(&self) -> bool {
        let mut f = fs::File::open(self.as_ref()).unwrap();
        FileHeader::read_from(&mut f).unwrap().is_compressed()
    }
}

// ============ region Tests ============

#[test]
fn test_basic() -> anyhow::Result<()> {
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
            paths: ["t1.txt", "t2.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt (added files)
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    dbg!(std::fs::read_to_string(temp_dir.join("git_simple_encrypt.toml")).unwrap());
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("t2.txt").is_compressed());
    assert!(temp_dir.join("t3.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    // Decrypt
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test decrypt result
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    assert!(temp_dir.join("t1.txt").is_not_encrypted());
    assert!(temp_dir.join("t2.txt").is_not_encrypted());
    assert!(temp_dir.join("t3.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_not_encrypted());
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
fn test_encrypt_multiple_times() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt multiple times
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    temp_dir
        .join("dir")
        .read_dir()?
        .for_each(|x| println!("{:?}", x));
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    // Decrypt
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test

    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_not_encrypted());
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
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    // Decrypt
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;

    // Test
    for _ in 1..10 {
        let file_name = files.choose(&mut rand::rng()).unwrap();
        println!("Testing file: {}", file_name.display());
        assert_eq!(std::fs::read_to_string(file_name)?, "Hello");
    }

    Ok(())
}

#[test]
fn test_large_file_encrypt_decrypt() -> anyhow::Result<()> {
    const FILE_SIZE: usize = 5 * 1024 * 1024; // 5 MB
    let pwd = test_init();
    let temp_dir = pwd.path();

    let mut rng = rand::rngs::SmallRng::from_seed([42; 32]);
    let original_data: Vec<u8> = (0..FILE_SIZE).map(|_| rng.random::<u8>()).collect();

    let file_path = temp_dir.join("large.bin");
    std::fs::write(&file_path, &original_data)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    assert!(file_path.is_encrypted());
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;

    let decrypted_data = std::fs::read(&file_path)?;
    assert_eq!(decrypted_data, original_data);
    assert!(file_path.is_not_encrypted());

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
            paths: ["t1.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Partial decrypt
    run(
        SubCommand::Decrypt {
            paths: vec!["dir".into()],
        },
        temp_dir,
    )?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("dir/t4.txt").exists());

    // Reencrypt
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    // Partial decrypt
    run(
        SubCommand::Decrypt {
            paths: vec!["t1.txt".into()],
        },
        temp_dir,
    )?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").exists());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    Ok(())
}

#[test]
fn test_tampered_encrypted_file_fails_aad() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let file_path = temp_dir.join("secret.txt");
    let original_content = b"Hello, this is a secret message that must be authenticated!";
    std::fs::write(&file_path, original_content)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    assert!(file_path.is_encrypted());
    let mut encrypted_data = std::fs::read(&file_path)?;
    assert!(!encrypted_data.is_empty());

    // 篡改：翻转中间的一个字节
    let mid = encrypted_data.len() / 2;
    encrypted_data[mid] ^= 0xFF;

    // 写回篡改后的数据
    std::fs::write(&file_path, &encrypted_data)?;

    // 尝试解密，应该失败（AAD 校验不通过）
    let decrypt_result = run(SubCommand::Decrypt { paths: vec![] }, temp_dir);
    dbg!(&decrypt_result);
    assert!(decrypt_result.is_err());
    // 可选：验证文件仍然处于加密状态（因为解密失败，文件未被修改）
    assert!(file_path.is_encrypted());

    // 另一种篡改方式：截断文件末尾 10 个字节
    let mut encrypted_data2 = std::fs::read(&file_path)?;
    encrypted_data2.truncate(encrypted_data2.len().saturating_sub(10));
    std::fs::write(&file_path, &encrypted_data2)?;

    let decrypt_result2 = run(SubCommand::Decrypt { paths: vec![] }, temp_dir);
    dbg!(&decrypt_result);
    assert!(decrypt_result2.is_err());

    Ok(())
}

#[test]
fn test_deterministic_reencryption() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    std::fs::write(temp_dir.join("dir/t3.txt"), "nested file")?;

    // Add files
    run(
        SubCommand::Add {
            paths: ["t1.txt", "t2.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // ---- First encrypt ----
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("t2.txt").is_compressed());
    assert!(temp_dir.join("dir/t3.txt").is_encrypted());

    let enc1_t1 = std::fs::read(temp_dir.join("t1.txt"))?;
    let enc1_t2 = std::fs::read(temp_dir.join("t2.txt"))?;
    let enc1_t3 = std::fs::read(temp_dir.join("dir/t3.txt"))?;

    // ---- Decrypt ----
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t3.txt"))?,
        "nested file"
    );

    // ---- Re-encrypt (should produce identical ciphertext) ----
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;

    let enc2_t1 = std::fs::read(temp_dir.join("t1.txt"))?;
    let enc2_t2 = std::fs::read(temp_dir.join("t2.txt"))?;
    let enc2_t3 = std::fs::read(temp_dir.join("dir/t3.txt"))?;

    assert_eq!(
        enc1_t1, enc2_t1,
        "t1.txt: decrypt→encrypt must produce identical ciphertext"
    );
    assert_eq!(
        enc1_t2, enc2_t2,
        "t2.txt: decrypt→encrypt must produce identical ciphertext"
    );
    assert_eq!(
        enc1_t3, enc2_t3,
        "dir/t3.txt: decrypt→encrypt must produce identical ciphertext"
    );

    // Verify the files still decrypt correctly
    run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t3.txt"))?,
        "nested file"
    );

    Ok(())
}

#[test]
fn test_deterministic_reencryption_multiple_cycles() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("data.txt"), "persistent data")?;

    run(
        SubCommand::Add {
            paths: vec!["data.txt".into()],
        },
        temp_dir,
    )?;

    // Encrypt and capture ciphertext from 3 decrypt→encrypt cycles
    run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
    let reference = std::fs::read(temp_dir.join("data.txt"))?;

    for cycle in 1..=3 {
        run(SubCommand::Decrypt { paths: vec![] }, temp_dir)?;
        assert_eq!(
            std::fs::read_to_string(temp_dir.join("data.txt"))?,
            "persistent data",
            "Data corrupted at cycle {cycle}"
        );

        run(SubCommand::Encrypt { paths: vec![] }, temp_dir)?;
        let ciphertext = std::fs::read(temp_dir.join("data.txt"))?;
        assert_eq!(ciphertext, reference, "Ciphertext changed at cycle {cycle}");
    }

    Ok(())
}
