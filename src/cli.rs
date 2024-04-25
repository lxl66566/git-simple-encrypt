use clap::{Parser, Subcommand};

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None, after_help = r#"Examples:
"#)]
#[clap(args_conflicts_with_subcommands = true)]
pub struct Cli {
    /// Encrypt, Decrypt and Add
    #[command(subcommand)]
    pub command: SubCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SubCommand {
    /// Encrypt all files with crypt attr.
    #[clap(alias("e"))]
    Encrypt,
    /// Decrypt all files with crypt attr and `.enc` extension.
    #[clap(alias("d"))]
    Decrypt,
    /// Add crypt attr to file or folder.
    Add,
    /// Remove crypt attr to file or folder.
    Remove,
}
