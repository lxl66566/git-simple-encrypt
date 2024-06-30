# git-simple-encrypt

English | [简体中文](./docs/README_zh-CN.md)

A **very simple and easy to use** git encryption tool that encrypts/decrypts your git repositories on any device with one **single password**. Supports partial file encryption, incremental encryption.

- Why not use [`git-crypt`](https://github.com/AGWA/git-crypt)?
  - **This project is more focused on ease of use than security.** Single-password symmetric encryption is my bottom line.

> [!WARNING]  
> **This repository does not make any guarantees about encryption security and backward compatibility.** (Please use the same major version)

## Installation

There are several different ways to install it, you can choose **any** of them.

- Download the file from [Releases](https://github.com/lxl66566/git-simple-encrypt/releases), unzip and place it in `C:\Windows\System32` (If you're using Windows) or any `Path` directory.
- Using [bpm](https://github.com/lxl66566/bpm):
  ```sh
  bpm i git-simple-encrypt -b git-se -q
  ```
- Using [scoop](https://scoop.sh/):
  ```sh
  scoop bucket add absx https://github.com/absxsfriends/scoop-bucket
  scoop install git-simple-encrypt
  ```
- Using cargo:
  ```sh
  cargo +nightly install git-simple-encrypt
  ```
  or [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):
  ```sh
  cargo binstall git-simple-encrypt
  ```

## Usage

```sh
git-se set key 123456       # Set the password to `123456`.
git-se add file.txt         # Add `file.txt` to the need-to-be-encrypted list.
git-se add mydir            # Add `mydir` to the need-to-be-encrypted list.
git-se e                    # Encrypt files in list in the current repository.
git-se d                    # Decrypt all files with extension `.enc`, `.zst.enc`.
git-se d 'src/*'            # Decrypt all encrypted files in `src` folder.
```

Type `git-se -h` and `git-se [subcommand] -h` to get more information.

## Caution

- `git add -A` is automatically executed when encrypting, so make sure that `.gitignore` is handled properly.
- Do not add files with `.zst`, `.enc` suffixes and folders containing them to the encrypted list.
- To delete file/dir from encrypt list, edit `git_simple_encrypt.toml`.

## Algorithm

```mermaid
graph TD;
    A[Key: 123] -- SHA3_224 --> 602bdc204140db016bee5374895e5568ce422fabe17e064061d80097 -- CUT --> 602bdc204140db016bee5374895e5568 --cipher--> Aes128GcmSiv  -- output--> 14a7dd2666afd854788c80f5518fea892491f23e72798d2fbc67bfc6259610d6f4
    B[Text: '6' * 60] --zstd--> 28b52ffd006045000010363601003f0116 --content--> Aes128GcmSiv
    CONST --NONCE--> Aes128GcmSiv
```

- If zstd compression has the opposite effect, skip compression.
- Decrypt all files with extension `.enc`, `.zst.enc`.

## TODO

- [ ] zstd effect checking
- [x] partial decrypt
