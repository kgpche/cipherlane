//! 仓库级一致性 / 零 Node 守卫（`cargo test --release --test consistency`）。
//!
//! 纯只读：不 spawn 子进程、不加测试锁，可与协议/CLI/浏览器测试并行运行。
//! 覆盖：
//!   1) Cargo.toml [package].version == README / README.zh-CN 版本徽章
//!   2) Rust `include_bytes!` 内嵌资源 ↔ public/ 文件（存在、无遗漏、无多余）
//!   3) 三个 bin 声明与源文件存在
//!   4) 五个 Rust 测试目标存在（crypto / protocol / cli / browser / consistency）
//!   5) 产品、构建、CI、文档命令块中无 Node/npm/旧 Node 实现残留
//!
//! 失败信息带 `文件:行号`，便于直接定位。
use std::fs;
use std::path::{Component, Path, PathBuf};

// ---------- 路径工具 ----------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cipherlane-rs 应位于仓库根目录下")
        .to_path_buf()
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()))
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// 归一化路径（不触碰文件系统）：折叠 `.` 与 `..`。
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn walk_files(dir: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("读取目录 {} 失败: {e}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("读取 {} 条目失败: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, suffix, out);
        } else if path.to_string_lossy().ends_with(suffix) {
            out.push(path);
        }
    }
}

// ---------- 文本/清单解析 ----------

/// 取 Cargo.toml 中 [package] 段的 version（忽略 dependencies 里的 version）。
fn package_version(manifest: &str) -> String {
    let mut in_package = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if in_package {
            if let Some(rest) = t.strip_prefix("version") {
                if let Some(v) = rest.trim_start().strip_prefix('=') {
                    return v.trim().trim_matches('"').to_string();
                }
            }
        }
    }
    panic!("cipherlane-rs/Cargo.toml 的 [package] 段缺少 version");
}

/// 解析 `[[bin]]` 的 (name, path)。
fn manifest_bins(manifest: &str) -> Vec<(String, String)> {
    let mut bins = Vec::new();
    let mut name = None;
    let mut path = None;
    let mut in_bin = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if in_bin {
                if let (Some(n), Some(p)) = (name.take(), path.take()) {
                    bins.push((n, p));
                }
            }
            in_bin = t == "[[bin]]";
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(v) = t.strip_prefix("name") {
            if let Some(v) = v.trim_start().strip_prefix('=') {
                name = Some(v.trim().trim_matches('"').to_string());
            }
        } else if let Some(v) = t.strip_prefix("path") {
            if let Some(v) = v.trim_start().strip_prefix('=') {
                path = Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    if in_bin {
        if let (Some(n), Some(p)) = (name, path) {
            bins.push((n, p));
        }
    }
    bins
}

/// 从 README 的 shields.io 徽章里取 `version-X.Y.Z`。
fn badge_version(text: &str) -> Option<(usize, String)> {
    const TAG: &str = "badge/version-";
    let pos = text.find(TAG)?;
    let rest = &text[pos + TAG.len()..];
    let end = rest.find('-')?;
    let version = &rest[..end];
    if version.chars().all(|c| c.is_ascii_digit() || c == '.') && version.matches('.').count() == 2 {
        Some((text[..pos].matches('\n').count() + 1, version.to_string()))
    } else {
        None
    }
}

/// 取 Markdown 围栏代码块（``` ... ```）的行号与内容。
fn fenced_blocks(text: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut in_block = false;
    let mut start = 0;
    let mut body = String::new();
    for (idx, line) in text.lines().enumerate() {
        let no = idx + 1;
        if line.trim_start().starts_with("```") {
            if in_block {
                blocks.push((start, std::mem::take(&mut body)));
                in_block = false;
            } else {
                in_block = true;
                start = no;
            }
            continue;
        }
        if in_block {
            body.push_str(line);
            body.push('\n');
        }
    }
    blocks
}

// ---------- 禁止 token 扫描 ----------

/// 需要从产品/构建/CI/文档命令块中消失的 Node 痕迹。
const FORBIDDEN: &[&str] = &[
    "node",
    "npm",
    "npx",
    "package.json",
    "sea-config",
    "postject",
    "server.js",
    "cli.mjs",
    "setup-node",
];

/// 简易词边界匹配（大小写不敏感），避免 `node_modules`、`anode` 之类误报。
fn contains_token(line: &str, token: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let is_boundary = |c: Option<char>| c.map_or(true, |ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'));
    let mut from = 0;
    while let Some(pos) = lower[from..].find(token) {
        let idx = from + pos;
        let before = lower[..idx].chars().next_back();
        let after = lower[idx + token.len()..].chars().next();
        if is_boundary(before) && is_boundary(after) {
            return true;
        }
        from = idx + token.len();
    }
    false
}

/// 扫描一个文件；`skip_comment_lines` 用于 Rust 源码（历史兼容性注释不算残留）。
fn scan_file(path: &Path, root: &Path, skip_comment_lines: bool, violations: &mut Vec<String>) {
    let text = read_text(path);
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if skip_comment_lines
            && (trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*'))
        {
            continue;
        }
        for token in FORBIDDEN {
            if contains_token(line, token) {
                violations.push(format!("{}:{}: 禁止 token `{token}` ← {}", rel(root, path), idx + 1, line.trim()));
            }
        }
    }
}

// ---------- 测试 ----------

#[test]
fn version_consistent_between_manifest_and_readme_badges() {
    let root = repo_root();
    let version = package_version(&read_text(&crate_root().join("Cargo.toml")));
    for doc in ["README.md", "README.zh-CN.md"] {
        let path = root.join(doc);
        let text = read_text(&path);
        match badge_version(&text) {
            Some((line, badge)) => assert_eq!(
                version, badge,
                "{doc}:{line}: 版本徽章 {badge} != Cargo.toml [package].version {version}"
            ),
            None => panic!("{doc}: 未找到 shields.io 版本徽章（badge/version-X.Y.Z-）"),
        }
    }
}

#[test]
fn embedded_assets_match_public_dir() {
    let root = repo_root();
    let crate_dir = crate_root();
    let mut rs_files = Vec::new();
    walk_files(&crate_dir.join("src"), ".rs", &mut rs_files);

    let mut embedded: Vec<PathBuf> = Vec::new();
    for file in &rs_files {
        let source = read_text(file);
        let mut from = 0;
        while let Some(pos) = source[from..].find("include_bytes!") {
            let after = from + pos + "include_bytes!".len();
            let Some(q1) = source[after..].find('"') else { break };
            let lit_start = after + q1 + 1;
            let Some(q2) = source[lit_start..].find('"') else { break };
            let literal = &source[lit_start..lit_start + q2];
            let resolved = normalize(&file.parent().expect("源文件应有父目录").join(literal));
            embedded.push(resolved);
            from = lit_start + q2 + 1;
        }
    }
    assert!(
        !embedded.is_empty(),
        "cipherlane-rs/src 下未找到任何 include_bytes!（前端资源应编译期内嵌）"
    );

    let mut missing: Vec<String> = embedded
        .iter()
        .filter(|p| !p.is_file())
        .map(|p| rel(&root, p))
        .collect();
    missing.sort();

    let mut public_disk: Vec<String> = fs::read_dir(root.join("public"))
        .expect("public/ 目录应存在")
        .map(|e| format!("public/{}", e.expect("读取 public/ 失败").file_name().to_string_lossy()))
        .collect();
    public_disk.sort();

    let mut embedded_public: Vec<String> = embedded
        .iter()
        .filter(|p| p.starts_with(root.join("public")))
        .map(|p| rel(&root, p))
        .collect();
    embedded_public.sort();
    embedded_public.dedup();

    let not_embedded: Vec<&String> = public_disk.iter().filter(|p| !embedded_public.contains(p)).collect();
    let dangling: Vec<&String> = embedded_public.iter().filter(|p| !public_disk.contains(p)).collect();

    assert!(
        missing.is_empty(),
        "include_bytes! 引用了不存在的文件:\n  {}",
        missing.join("\n  ")
    );
    assert!(
        not_embedded.is_empty(),
        "public/ 下存在未内嵌的文件（打包后运行时不可达）:\n  {}",
        not_embedded.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  ")
    );
    assert!(
        dangling.is_empty(),
        "include_bytes! 指向了 public/ 中不存在的文件:\n  {}",
        dangling.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  ")
    );
}

#[test]
fn required_bins_declared_and_sources_exist() {
    let crate_dir = crate_root();
    let bins = manifest_bins(&read_text(&crate_dir.join("Cargo.toml")));
    let declared: Vec<&str> = bins.iter().map(|(n, _)| n.as_str()).collect();
    for required in ["cipherlane", "cipherlane-tray", "cipherlane-cli"] {
        assert!(
            declared.contains(&required),
            "cipherlane-rs/Cargo.toml 缺少 [[bin]] name = \"{required}\"（当前: {declared:?}）"
        );
    }
    for (name, path) in &bins {
        let src = crate_dir.join(path);
        assert!(src.is_file(), "bin `{name}` 的源文件不存在: cipherlane-rs/{path}");
    }
}

#[test]
fn rust_test_targets_exist() {
    let tests_dir = crate_root().join("tests");
    for name in ["crypto", "protocol", "cli", "browser", "consistency"] {
        let path = tests_dir.join(format!("{name}.rs"));
        assert!(
            path.is_file(),
            "缺少 Rust 测试目标: cipherlane-rs/tests/{name}.rs（cargo test --test {name} 需要）"
        );
    }
}

#[test]
fn no_node_remnants_in_product_build_ci_docs() {
    let root = repo_root();
    let mut violations: Vec<String> = Vec::new();

    // 1) 产品源码：只扫代码行（历史兼容性注释里提到旧 Node 实现不算残留）
    let mut src_files = Vec::new();
    walk_files(&crate_root().join("src"), ".rs", &mut src_files);
    for file in &src_files {
        scan_file(file, &root, true, &mut violations);
    }

    // 2) 打包脚本：整文件不得出现 Node/npm/SEA/旧实现
    let package_sh = root.join("build/package.sh");
    assert!(package_sh.is_file(), "缺少 build/package.sh");
    scan_file(&package_sh, &root, false, &mut violations);

    // 3) CI / Release 工作流
    let workflows = root.join(".github/workflows");
    let mut wf_files = Vec::new();
    walk_files(&workflows, ".yml", &mut wf_files);
    assert!(!wf_files.is_empty(), "缺少 .github/workflows/*.yml");
    for file in &wf_files {
        scan_file(file, &root, false, &mut violations);
    }

    // 4) README 命令块（历史 changelog 的说明性文字不在围栏内，自然白名单）
    for doc in ["README.md", "README.zh-CN.md"] {
        let path = root.join(doc);
        let text = read_text(&path);
        for (start, block) in fenced_blocks(&text) {
            for (offset, line) in block.lines().enumerate() {
                for token in FORBIDDEN {
                    if contains_token(line, token) {
                        violations.push(format!(
                            "{}:{}: 文档命令块含禁止 token `{token}` ← {}",
                            doc,
                            start + offset,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "发现 {} 处 Node/npm 残留（仓库应为零 Node）:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}
