use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sigpack",
    version,
    about = "Store data inside the Authenticode signature of a signed PE without breaking it"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Append a blob to the signature's unauthenticated attributes.
    Add {
        /// Signed PE image (.exe, .dll, .sys, ...)
        file: PathBuf,
        /// File whose contents are embedded in the signature
        blob: PathBuf,
        /// Output path (defaults to editing FILE in place)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List the blobs stored in a signature.
    List {
        /// Signed PE image
        file: PathBuf,
        /// Write each blob verbatim to a file in this directory instead of
        /// printing it (required for binary payloads)
        #[arg(short, long, value_name = "DIR")]
        extract: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Add { file, blob, output } => {
            let image = fs::read(&file)?;
            let data = fs::read(&blob)?;
            let updated = sigpack::add_blob(&image, &data)?;
            let target = output.unwrap_or(file);
            fs::write(&target, &updated)?;
            eprintln!("wrote {} ({} bytes)", target.display(), updated.len());
        }
        Command::List { file, extract } => {
            let image = fs::read(&file)?;
            let blobs = sigpack::list_blobs(&image)?;
            if blobs.is_empty() {
                eprintln!("no blobs found");
            }

            if let Some(dir) = extract {
                fs::create_dir_all(&dir)?;
                let stem = file
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("blob");
                for (index, blob) in blobs.iter().enumerate() {
                    let path = dir.join(format!("{stem}.{index}.blob"));
                    fs::write(&path, blob)?;
                    println!("{}", path.display());
                }
            } else {
                for (index, blob) in blobs.iter().enumerate() {
                    match std::str::from_utf8(blob) {
                        Ok(text) if !text.chars().any(char::is_control) => {
                            println!("#{index} ({} bytes): {text}", blob.len());
                        }
                        _ => println!("#{index} ({} bytes): {}", blob.len(), hex(blob)),
                    }
                }
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
