use anyhow::{anyhow, Result};
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::HashSet,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

// sigma-engine API
use sigma_engine::{EngineConfig, SigmaEngine};

#[derive(Debug, Clone)]
pub struct InvalidRule {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Debug, Clone)]
struct RuleDoc {
    path: PathBuf,
    yaml: String,
}

pub struct SigmaRuntime {
    rules_dir: PathBuf,
    engine: SigmaEngine,
    rule_paths: Vec<PathBuf>, // index -> path
    rules: Vec<RuleDoc>,      // reload uchun
    invalid: Vec<InvalidRule>,
}

impl SigmaRuntime {
    pub fn load(rules_dir: impl AsRef<Path>) -> Result<Self> {
        let rules_dir = rules_dir.as_ref().to_path_buf();
        let rules = load_rule_files_recursive(&rules_dir)?;
        let (engine, invalid) = build_engine_with_invalid_detection(&rules)?;
        let rule_paths = rules.iter().map(|r| r.path.clone()).collect();

        Ok(Self {
            rules_dir,
            engine,
            rule_paths,
            rules,
            invalid,
        })
    }

    pub fn reload(&mut self) -> Result<()> {
        let rules = load_rule_files_recursive(&self.rules_dir)?;
        let (engine, invalid) = build_engine_with_invalid_detection(&rules)?;
        self.rule_paths = rules.iter().map(|r| r.path.clone()).collect();
        self.rules = rules;
        self.engine = engine;
        self.invalid = invalid;
        Ok(())
    }

    pub fn valid_rules(&self) -> usize {
        self.total_rules().saturating_sub(self.invalid.len())
    }

    pub fn total_rules(&self) -> usize {
        self.rules.len()
    }

    pub fn invalid_rules(&self) -> &[InvalidRule] {
        &self.invalid
    }

    pub fn rule_path_by_index(&self, idx: u32) -> Option<&Path> {
        self.rule_paths.get(idx as usize).map(|p| p.as_path())
    }

    /// Real-time: bitta JSON line bytes → matched rule indexlar (u32)
    pub fn evaluate_json_line_bytes(&mut self, json_line: &[u8]) -> Result<Vec<u32>> {
        let event: Value = serde_json::from_slice(json_line)
            .map_err(|e| anyhow!("JSON parse error: {e}"))?;

        let res = self
            .engine
            .evaluate(&event)
            .map_err(|e| anyhow!("engine.evaluate error: {e:?}"))?;

        Ok(res.matched_rules) // Vec<u32>
    }
}

/// Recursive *.yml / *.yaml yig‘adi (index stabil bo‘lishi uchun sort qiladi)
fn load_rule_files_recursive(rules_dir: &Path) -> Result<Vec<RuleDoc>> {
    let mut out = Vec::new();

    for entry in WalkDir::new(rules_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if ext != "yml" && ext != "yaml" {
            continue;
        }

        let yaml = fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read rule file {:?}: {}", path, e))?;

        out.push(RuleDoc {
            path: path.to_path_buf(),
            yaml,
        });
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// Engine build + invalid rule pathlarni topish (bisection)
fn build_engine_with_invalid_detection(rules: &[RuleDoc]) -> Result<(SigmaEngine, Vec<InvalidRule>)> {
    if rules.is_empty() {
        return Err(anyhow!("No rule files found"));
    }

    let all_idxs: Vec<usize> = (0..rules.len()).collect();
    if let Ok(engine) = try_build_engine(rules, &all_idxs) {
        return Ok((engine, vec![]));
    }

    let invalid_idxs = find_invalid_indices_bisect(rules, &all_idxs);

    let invalid_set: HashSet<usize> = invalid_idxs.iter().copied().collect();
    let valid_idxs: Vec<usize> = (0..rules.len()).filter(|i| !invalid_set.contains(i)).collect();

    let engine = try_build_engine(rules, &valid_idxs)
        .map_err(|e| anyhow!("Engine build failed even after removing invalid rules: {e}"))?;

    let mut invalid = Vec::new();
    for &i in &invalid_idxs {
        let err = match try_build_engine(rules, &[i]) {
            Ok(_) => "Unknown (passes alone, fails in batch)".to_string(),
            Err(e) => e,
        };
        invalid.push(InvalidRule {
            path: rules[i].path.clone(),
            error: err,
        });
    }

    Ok((engine, invalid))
}

fn try_build_engine(rules: &[RuleDoc], idxs: &[usize]) -> std::result::Result<SigmaEngine, String> {
    let mut rule_refs: Vec<&str> = Vec::with_capacity(idxs.len());
    for &i in idxs {
        rule_refs.push(rules[i].yaml.as_str());
    }

    let config = EngineConfig::production();

    SigmaEngine::builder()
        .with_config(config)
        .build(&rule_refs)
        .map_err(|e| format!("{e:?}"))
}

fn find_invalid_indices_bisect(rules: &[RuleDoc], idxs: &[usize]) -> Vec<usize> {
    if idxs.is_empty() {
        return vec![];
    }
    if try_build_engine(rules, idxs).is_ok() {
        return vec![];
    }
    if idxs.len() == 1 {
        return vec![idxs[0]];
    }

    let mid = idxs.len() / 2;
    let mut left = find_invalid_indices_bisect(rules, &idxs[..mid]);
    let mut right = find_invalid_indices_bisect(rules, &idxs[mid..]);
    left.append(&mut right);
    left
}

/* ===========================
   FFI (Rust DLL exports)
   =========================== */

#[repr(C)]
pub struct SigmaBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

thread_local! {
    static LAST_ERROR: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

fn set_last_error(msg: impl AsRef<str>) {
    let s = msg.as_ref().as_bytes().to_vec();
    LAST_ERROR.with(|e| *e.borrow_mut() = s);
}

fn ok_buf(v: Vec<u8>) -> SigmaBuffer {
    // Box<[u8]> qilib leak qilamiz (free uchun alohida func bor)
    let len = v.len();
    let boxed: Box<[u8]> = v.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8;
    SigmaBuffer { ptr, len }
}

fn err_buf(e: impl AsRef<str>) -> SigmaBuffer {
    set_last_error(e.as_ref());
    SigmaBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

unsafe fn utf8_from_ptr(ptr: *const u8, len: usize) -> Result<&'static str> {
    if ptr.is_null() || len == 0 {
        return Err(anyhow!("null/empty utf8 input"));
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    let s = std::str::from_utf8(slice).map_err(|e| anyhow!("utf8 error: {e}"))?;
    // C# tomonda string bytes lifetime mustaqil; bu yerda faqat call ichida ishlatamiz,
    // shuning uchun &'static kerak emas aslida. Lekin funksiyalar ichida darhol ishlatamiz.
    // Shu sababli: leak qilmasdan ishlatish uchun, pastdagi calllarda `to_string()` qilamiz.
    Ok(std::mem::transmute::<&str, &'static str>(s))
}

/// INIT: rules_dir UTF-8 (ptr+len) → handle
#[no_mangle]
pub extern "C" fn sigma_init(rules_ptr: *const u8, rules_len: usize) -> *mut SigmaRuntime {
    let res = (|| -> Result<*mut SigmaRuntime> {
        let rules_dir = unsafe { utf8_from_ptr(rules_ptr, rules_len)? }.to_string();
        let rt = SigmaRuntime::load(&rules_dir)?;
        Ok(Box::into_raw(Box::new(rt)))
    })();

    match res {
        Ok(h) => h,
        Err(e) => {
            set_last_error(e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn sigma_destroy(handle: *mut SigmaRuntime) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Reload rules (tahrir/o‘chirish/qo‘shish bo‘lsa)
#[no_mangle]
pub extern "C" fn sigma_reload(handle: *mut SigmaRuntime) -> i32 {
    if handle.is_null() {
        set_last_error("sigma_reload: null handle");
        return 0;
    }
    let r = unsafe { &mut *handle }.reload();
    match r {
        Ok(_) => 1,
        Err(e) => {
            set_last_error(e.to_string());
            0
        }
    }
}

/// 1 marta rule pathlar ro‘yxatini olib C# da cache qiling
/// Format: u32 count, then [u32 len + bytes] * count
#[no_mangle]
pub extern "C" fn sigma_get_rule_paths(handle: *mut SigmaRuntime) -> SigmaBuffer {
    if handle.is_null() {
        return err_buf("sigma_get_rule_paths: null handle");
    }
    let rt = unsafe { &mut *handle };

    let mut out: Vec<u8> = Vec::new();
    let count = rt.rule_paths.len() as u32;
    out.extend_from_slice(&count.to_le_bytes());

    for p in &rt.rule_paths {
        let s = p.to_string_lossy();
        let b = s.as_bytes();
        let len = b.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(b);
    }

    ok_buf(out)
}

/// Invalid rules list (xohlasangiz C# ga ko‘rsatish uchun)
/// Format: u32 count, then [u32 path_len + path_bytes + u32 err_len + err_bytes] * count
#[no_mangle]
pub extern "C" fn sigma_get_invalid_rules(handle: *mut SigmaRuntime) -> SigmaBuffer {
    if handle.is_null() {
        return err_buf("sigma_get_invalid_rules: null handle");
    }
    let rt = unsafe { &mut *handle };

    let mut out: Vec<u8> = Vec::new();
    let count = rt.invalid.len() as u32;
    out.extend_from_slice(&count.to_le_bytes());

    for inv in &rt.invalid {
        let path = inv.path.to_string_lossy();
        let err = inv.error.as_bytes();

        let pb = path.as_bytes();
        out.extend_from_slice(&(pb.len() as u32).to_le_bytes());
        out.extend_from_slice(pb);

        out.extend_from_slice(&(err.len() as u32).to_le_bytes());
        out.extend_from_slice(err);
    }

    ok_buf(out)
}

/// JSONL file scan (har file uchun 1 call)
/// Return format:
/// u32 version=1
/// u32 hit_count
/// repeated hit:
///   u32 line_no
///   u32 rule_idx
///   u32 line_len
///   [line bytes...]
#[no_mangle]
pub extern "C" fn sigma_scan_jsonl_file(
    handle: *mut SigmaRuntime,
    path_ptr: *const u8,
    path_len: usize,
    include_line: u8,
    max_line_bytes: u32,
) -> SigmaBuffer {
    let res = (|| -> Result<SigmaBuffer> {
        if handle.is_null() {
            return Ok(err_buf("sigma_scan_jsonl_file: null handle"));
        }
        let rt = unsafe { &mut *handle };

        let path = unsafe { utf8_from_ptr(path_ptr, path_len)? }.to_string();
        let f = fs::File::open(&path)?;
        let mut reader = BufReader::new(f);

        let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&0u32.to_le_bytes()); // hit_count placeholder
        let mut hit_count: u32 = 0;

        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut line_no: u32 = 0;

        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            line_no = line_no.wrapping_add(1);

            let slice = trim_eol(&buf);
            if slice.is_empty() {
                continue;
            }

            let matched = match rt.evaluate_json_line_bytes(slice) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if matched.is_empty() {
                continue;
            }

            // include_line bo‘lsa — faqat HIT bo‘lganda line bytes’ni olamiz
            let mut line_bytes: &[u8] = &[];
            let mut line_len_u32: u32 = 0;

            if include_line != 0 {
                let maxb = max_line_bytes as usize;
                let s2 = if slice.len() > maxb { &slice[..maxb] } else { slice };
                line_bytes = s2;
                line_len_u32 = s2.len() as u32;
            }

            for idx in matched {
                hit_count = hit_count.wrapping_add(1);

                out.extend_from_slice(&line_no.to_le_bytes());
                out.extend_from_slice(&idx.to_le_bytes());
                out.extend_from_slice(&line_len_u32.to_le_bytes());
                if line_len_u32 != 0 {
                    out.extend_from_slice(line_bytes);
                }
            }
        }

        // hit_count ni joyiga yozib qo‘yamiz (offset 4..8)
        out[4..8].copy_from_slice(&hit_count.to_le_bytes());

        Ok(ok_buf(out))
    })();

    match res {
        Ok(b) => b,
        Err(e) => err_buf(e.to_string()),
    }
}

/// Last error’ni olish (UTF-8 buffer). O‘qib bo‘lgach free qiling.
#[no_mangle]
pub extern "C" fn sigma_take_last_error() -> SigmaBuffer {
    let mut v = Vec::new();
    LAST_ERROR.with(|e| {
        let mut b = e.borrow_mut();
        if !b.is_empty() {
            v.append(&mut *b);
        }
    });
    ok_buf(v)
}

/// Rust qaytargan barcha SigmaBuffer’larni C# shu bilan free qiladi
#[no_mangle]
pub extern "C" fn sigma_free_buffer(buf: SigmaBuffer) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len);
        drop(Box::from_raw(slice));
    }
}

fn trim_eol(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    &buf[..end]
}


#[no_mangle]
pub extern "C" fn sigma_eval_json_line(
    handle: *mut SigmaRuntime,
    json_ptr: *const u8,
    json_len: usize,
    include_line: u8,
    max_line_bytes: u32,
) -> SigmaBuffer {
    let res = (|| -> Result<SigmaBuffer> {
        if handle.is_null() {
            return Ok(err_buf("sigma_eval_json_line: null handle"));
        }
        if json_ptr.is_null() || json_len == 0 {
            return Ok(err_buf("sigma_eval_json_line: null/empty json"));
        }

        let rt = unsafe { &mut *handle };
        let json = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };

        let matched = rt.evaluate_json_line_bytes(json).unwrap_or_default();
        if matched.is_empty() {
            let mut out = Vec::new();
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            return Ok(ok_buf(out));
        }

        let mut out: Vec<u8> = Vec::with_capacity(64);
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&(matched.len() as u32).to_le_bytes());

        // include_line bo‘lsa: line’ni (qirqib) har hitga qo‘shamiz
        let mut line_bytes: &[u8] = &[];
        let mut line_len_u32: u32 = 0;
        if include_line != 0 {
            let maxb = max_line_bytes as usize;
            let s2 = if json.len() > maxb { &json[..maxb] } else { json };
            line_bytes = s2;
            line_len_u32 = s2.len() as u32;
        }

        for idx in matched {
            out.extend_from_slice(&1u32.to_le_bytes()); // line_no=1
            out.extend_from_slice(&idx.to_le_bytes());
            out.extend_from_slice(&line_len_u32.to_le_bytes());
            if line_len_u32 != 0 {
                out.extend_from_slice(line_bytes);
            }
        }

        Ok(ok_buf(out))
    })();

    match res {
        Ok(b) => b,
        Err(e) => err_buf(e.to_string()),
    }
}
