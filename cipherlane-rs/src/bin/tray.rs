// cipherlane · 密道 —— 系统托盘入口
//
// 实现仅在 Linux（StatusNotifierItem / AppIndicator，源码见 src/tray_linux.rs）。
// 其他平台保留一个占位二进制，使 `cargo build --release` 在三平台都能成功；
// 实际分发物在 Windows/macOS 只包含 server + cli（见 build/package.sh）。
#[cfg(target_os = "linux")]
#[path = "../tray_linux.rs"]
mod imp;

#[cfg(target_os = "linux")]
fn main() {
    imp::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("cipherlane-tray 仅支持 Linux（StatusNotifierItem/AppIndicator）");
    std::process::exit(2);
}
