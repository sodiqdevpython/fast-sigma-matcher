use anyhow::{ anyhow, Result };
use clap::{ Parser, Subcommand };
use std::{
    fs::File,
    io::{ self, BufRead, BufReader, BufWriter, LineWriter, Write },
    path::{ Path, PathBuf },
    time::Instant,
};
use walkdir::WalkDir;

use sigma_runner::SigmaRuntime;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Sigma rules root folder ni olishim uchun kerak
    #[arg(long)]
    rules: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Faqat load qiladi va valid, invalid listni chiqaradi
    LoadInfo,

    Repl,

    /// JSONL folder scan: hamma *.jsonl ni ketma-ket o'qishi uchun kerak
    ScanJsonlDir {
        #[arg(long)]
        logs: PathBuf,

        /// ixtiyoriy: natijani filega yozishim uchun kerak lekin c# dan chaqirmasam kerak
        #[arg(long)]
        out: Option<PathBuf>,

        /// HIT bo'lganda o'sha JSON log line ni ham chiqarishi uchun
        #[arg(long, default_value_t = false)]
        include_line: bool,

        /// include_line=true bo'lsa log line uzunligini cheklash
        #[arg(long, default_value_t = 4096)]
        max_line_bytes: usize,
    },

    /// Qo'lda reload test
    ReloadTest,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut rt = SigmaRuntime::load(&cli.rules)?;

    match cli.cmd {
        Command::LoadInfo => {
            println!("INIT OK");
            println!("RulesDir={}", cli.rules.display());
            println!("TotalRules={}", rt.total_rules());
            println!("InvalidCount={}", rt.invalid_rules().len());
            println!("ValidRules={}", rt.valid_rules());

            if !rt.invalid_rules().is_empty() {
                println!("\nINVALID RULES:");
                for (i, inv) in rt.invalid_rules().iter().enumerate() {
                    let err = inv.error.replace('\r', " ").replace('\n', " ");
                    println!("{}\t{}\t{}", i, inv.path.display(), err);
                }
                io::stdout().flush().ok();
            }
        }

        Command::Repl => {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin.lock());

            let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
            let mut line_no: u64 = 0;

            loop {
                buf.clear();
                let n = reader.read_until(b'\n', &mut buf)?;
                if n == 0 {
                    break;
                }
                line_no += 1;

                let slice = trim_eol(&buf);
                if slice.is_empty() {
                    continue;
                }

                match rt.evaluate_json_line_bytes(slice) {
                    Ok(matched) => {
                        for idx in matched {
                            let rule_path = rt
                                .rule_path_by_index(idx)
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "<unknown>".to_string());

                            println!("STDIN\t{}\t{}\t{}", line_no, idx, rule_path);
                        }
                    }
                    Err(e) => {
                        eprintln!("PARSE_OR_EVAL_ERR\t{}\t{}", line_no, e);
                    }
                }
            }
        }

        Command::ScanJsonlDir { logs, out, include_line, max_line_bytes } => {
            // stdout real-time ko'rinishi uchun LineWriter
            let mut writer: Box<dyn Write> = match out {
                Some(path) => {
                    let f = File::create(&path).map_err(|e|
                        anyhow!("Failed to create output file {:?}: {}", path, e)
                    )?;
                    Box::new(BufWriter::new(f))
                }
                None => Box::new(LineWriter::new(io::stdout())),
            };

            let mut files = collect_jsonl_files(&logs)?;
            files.sort();

            let start = Instant::now();
            let mut total_lines: u64 = 0;
            let mut total_hits: u64 = 0;

            for file_path in files {
                let f = File::open(&file_path).map_err(|e|
                    anyhow!("Failed to open {:?}: {}", file_path, e)
                )?;
                let mut reader = BufReader::new(f);

                let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
                let mut line_no: u64 = 0;

                loop {
                    buf.clear();
                    let n = reader.read_until(b'\n', &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    line_no += 1;
                    total_lines += 1;

                    let slice = trim_eol(&buf);
                    if slice.is_empty() {
                        continue;
                    }

                    match rt.evaluate_json_line_bytes(slice) {
                        Ok(matched) => {
                            if matched.is_empty() {
                                continue;
                            }

                            // line ni faqat HIT bo'lsa stringga aylantirishim uchun
                            let mut line_str = String::new();
                            if include_line {
                                let slice2 = if slice.len() > max_line_bytes {
                                    &slice[..max_line_bytes]
                                } else {
                                    slice
                                };

                                line_str = String::from_utf8_lossy(slice2).to_string();
                                // TSV ni saqlab turishim uchun tushunarli qilib
                                line_str = line_str
                                    .replace('\t', " ")
                                    .replace('\r', " ")
                                    .replace('\n', " ");
                            }

                            for idx in matched {
                                total_hits += 1;

                                let rule_path = rt
                                    .rule_path_by_index(idx)
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_else(|| "<unknown>".to_string());

                                if include_line {
                                    writeln!(
                                        writer,
                                        "{}\t{}\t{}\t{}\t{}",
                                        file_path.display(),
                                        line_no,
                                        idx,
                                        rule_path,
                                        line_str
                                    )?;
                                } else {
                                    writeln!(
                                        writer,
                                        "{}\t{}\t{}\t{}",
                                        file_path.display(),
                                        line_no,
                                        idx,
                                        rule_path
                                    )?;
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }

            writer.flush()?;
            eprintln!(
                "SCAN DONE lines={} hits={} elapsed_ms={}",
                total_lines,
                total_hits,
                start.elapsed().as_millis()
            );
        }

        Command::ReloadTest => {
            println!("Before: total={} invalid={}", rt.total_rules(), rt.invalid_rules().len());
            rt.reload()?;
            println!("After : total={} invalid={}", rt.total_rules(), rt.invalid_rules().len());
        }
    }

    Ok(())
}

fn collect_jsonl_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "jsonl" {
            out.push(p.to_path_buf());
        }
    }
    Ok(out)
}

fn trim_eol(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    &buf[..end]
}
