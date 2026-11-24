#!/bin/sh
# cipherlane v1.0 打包脚本 —— 三平台产物全部为 Rust 二进制，构建/打包无运行时依赖。
#
#   sh build/package.sh [版本号]       # 版本号默认取自 cipherlane-rs/Cargo.toml（唯一来源）
#
# 按宿主平台自动产出（build/dist/）：
#   Linux   → cipherlane_<ver>_amd64.deb
#             musl 静态 server + tray + cli、systemd 单元、桌面入口、托盘自启
#   macOS   → cipherlane_<ver>_macos_universal.tar.gz
#             lipo 合并 x86_64 + arm64 的 server/cli，附 cipherlane.command 启动器
#   Windows → cipherlane_<ver>_windows_x64.zip
#             cipherlane.exe + cipherlane-cli.exe（静态 CRT，无 VC++ 运行库依赖）
#
# 依赖：cargo/rustup（stable）；Linux 另需 rustup musl target + dpkg-deb；
#       macOS 需 Xcode 命令行工具（lipo）；Windows 在 Git Bash 中运行。
# 可移植性：macOS 上本脚本由系统自带的 bash 3.2 以 sh 模式执行。实测（Rust 版 Release
#       工作流首次空跑）"变量名后紧跟全角括号 / 中文逗号"的写法——比如 echo "... $t" 的
#       变量后面不加空格直接跟全角括号——会让它把后面的高位字节也当成变量名的一部分，
#       在 set -u 下报 "unbound variable"。同样的写法在 Linux 的 dash / bash 5 上完全正常，
#       所以普通 CI 发现不了。凡是变量后面紧接非 ASCII 字符，一律写 ${变量名}
#      （由 tests/consistency.rs 守卫）。
# 每次运行都会刷新 build/dist/cipherlane-<ver>-SHA256SUMS.txt。
set -eu
cd "$(dirname "$0")/.."

BUILD=build
DIST=$BUILD/dist
MANIFEST=cipherlane-rs/Cargo.toml
TARGET_DIR=cipherlane-rs/target
ARTIFACTS=""   # 本次实际产出的文件（校验和只覆盖它们，避免把 dist 里旧版本/旧平台产物算进去）
VER=${1:-$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$MANIFEST" | head -n 1)}
[ -n "$VER" ] || { echo "✗ 无法从 $MANIFEST 解析版本号"; exit 1; }
OS=$(uname -s)
ARCH=$(uname -m)

mkdir -p "$DIST"

need() { command -v "$1" >/dev/null 2>&1 || { echo "✗ 缺少命令: $1"; exit 1; }; }
cargo_build() { cargo build --release --manifest-path "$MANIFEST" "$@"; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"
  else echo "✗ 缺少 sha256sum/shasum" >&2; exit 1
  fi
}

write_sums() {
  ( cd "$DIST"
    for f in $ARTIFACTS; do sha256_of "$f"; done > "cipherlane-$VER-SHA256SUMS.txt" )
  echo ">> 校验和: $DIST/cipherlane-$VER-SHA256SUMS.txt"
}

# zip 三选一（Windows Git Bash 通常只有 powershell.exe）
make_zip() { # $1=输出 zip；其余=要打包的文件（当前目录）
  out=$1; shift
  rm -f "$out"
  if command -v zip >/dev/null 2>&1; then
    zip -q -9 "$out" "$@"
  elif command -v 7z >/dev/null 2>&1; then
    7z a -tzip -mx=9 "$out" "$@" >/dev/null
  elif command -v powershell.exe >/dev/null 2>&1; then
    winout=$(cygpath -w "$out")
    winpaths=""
    for f in "$@"; do winpaths="$winpaths,'$(cygpath -w "$f")'"; done
    powershell.exe -NoProfile -Command "Compress-Archive -Force -DestinationPath '$winout' -Path @(${winpaths#,})"
  else
    echo "✗ 无法创建 zip：缺少 zip / 7z / powershell.exe"
    exit 1
  fi
}

# ================= Linux：musl 静态二进制 + .deb =================
package_linux() {
  [ "$ARCH" = "x86_64" ] || { echo "✗ Linux 产物目前仅支持 x86_64（当前 ${ARCH}）"; exit 1; }
  need cargo
  need dpkg-deb
  if command -v rustup >/dev/null 2>&1; then
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
  fi
  # v1.0 加固起引入 rustls（ring 含 C 代码）：musl 交叉编译需要 musl-gcc。
  # CI 已自动安装 musl-tools；本机缺失时给出明确指引（cc 报错会深得多）。
  if ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1 && [ -z "$CC_x86_64_unknown_linux_musl" ]; then
    echo "✗ 缺少 musl 交叉 C 编译器（rustls 的 ring 后端需要）。任选其一："
    echo "    sudo apt-get install -y musl-tools        # 方式一：系统包"
    echo "    export CC_x86_64_unknown_linux_musl='zig cc -target x86_64-linux-musl'  # 方式二：已有 zig"
    exit 1
  fi
  echo ">> 构建 Linux musl 静态二进制（server / tray / cli）…"
  cargo_build --target x86_64-unknown-linux-musl
  REL=$TARGET_DIR/x86_64-unknown-linux-musl/release
  for b in cipherlane cipherlane-tray cipherlane-cli; do
    [ -x "$REL/$b" ] || { echo "✗ 缺少产物: $REL/$b"; exit 1; }
  done

  DEBROOT=$BUILD/deb-root
  rm -rf "$DEBROOT"
  mkdir -p "$DEBROOT/DEBIAN" "$DEBROOT/usr/bin" "$DEBROOT/usr/lib/systemd/system" \
    "$DEBROOT/usr/share/applications" "$DEBROOT/usr/share/icons/hicolor/scalable/apps"
  cp "$REL/cipherlane" "$DEBROOT/usr/bin/cipherlane"
  cp "$REL/cipherlane-cli" "$DEBROOT/usr/bin/cipherlane-cli"
  cp "$REL/cipherlane-tray" "$DEBROOT/usr/bin/cipherlane-tray"
  chmod 755 "$DEBROOT/usr/bin/cipherlane" "$DEBROOT/usr/bin/cipherlane-cli" "$DEBROOT/usr/bin/cipherlane-tray"
  cp logo/02-shield-lane.svg "$DEBROOT/usr/share/icons/hicolor/scalable/apps/cipherlane.svg"
  cp logo/02-shield-lane-stopped.svg "$DEBROOT/usr/share/icons/hicolor/scalable/apps/cipherlane-stopped.svg"

  # 桌面启动器：未运行则后台启动（带会话停机令牌），随后打开控制面板
  mkdir -p "$DEBROOT/usr/lib/cipherlane"
  cat > "$DEBROOT/usr/lib/cipherlane/cipherlane-app" << 'APP'
#!/bin/sh
# cipherlane 桌面启动器：未运行则后台启动，随后打开传输主页。
# 职责边界：这里只负责"传输主页"，且必须开局域网地址（回环 origin 会与 LAN origin
# 裂成两个身份，页面内链接/二维码也以 LAN 为准）；管理面板 /panel 只在回环打开、
# 只经托盘进入。启动不带停机令牌——留给托盘 adopt 接管（否则托盘 409 变只读）。
PORT=${CIPHERLANE_PORT:-7777}
LOCAL="http://127.0.0.1:$PORT"
probe() { (curl -sf "$LOCAL/api/version" || wget -qO- "$LOCAL/api/version") >/dev/null 2>&1; }
version_json() { curl -sf "$LOCAL/api/version" 2>/dev/null || wget -qO- "$LOCAL/api/version" 2>/dev/null; }
# 公开访问地址：优先服务器报告的局域网 IP；"lan":null/解析失败时退回环（本机仍可用）
public_base() {
  lan=$(version_json | sed -n 's/.*"lan":"\([0-9][0-9.]*\)".*/\1/p')
  if [ -n "$lan" ]; then echo "http://$lan:$PORT"; else echo "$LOCAL"; fi
}
if ! probe; then
  # 日志写用户态 XDG 目录：/var/log 普通用户无权创建,曾导致服务器静默不启动
  LOGDIR="${XDG_STATE_HOME:-$HOME/.local/state}/cipherlane"
  mkdir -p "$LOGDIR"
  PORT="$PORT" nohup /usr/bin/cipherlane >>"$LOGDIR/app.log" 2>&1 &
  for i in $(seq 1 50); do probe && break; sleep 0.2; done
  if ! probe; then
    MSG="密道启动失败。常见原因：端口 $PORT 被旧实例占用（fuser -k $PORT/tcp 后重试）。日志：$LOGDIR/app.log"
    if command -v zenity >/dev/null 2>&1; then zenity --error --title cipherlane --text "$MSG" 2>/dev/null; fi
    exit 1
  fi
fi
exec xdg-open "$(public_base)/"
APP
  chmod 755 "$DEBROOT/usr/lib/cipherlane/cipherlane-app"

  cat > "$DEBROOT/usr/share/applications/cipherlane.desktop" << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=cipherlane
Comment=局域网端到端加密传输
Comment[en]=LAN end-to-end encrypted transfer
GenericName=文件传输
Exec=/usr/lib/cipherlane/cipherlane-app
Icon=cipherlane
Terminal=false
Categories=Network;FileTransfer;Utility;
Keywords=lan;transfer;encrypt;airdrop;密道;传输;加密;
StartupNotify=true
X-GNOME-UsesNotifications=false
DESKTOP

  mkdir -p "$DEBROOT/etc/xdg/autostart"
  cat > "$DEBROOT/etc/xdg/autostart/cipherlane-tray.desktop" << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=cipherlane Tray
Comment=密道系统托盘（打开/开启/退出/关于/检查更新）
Exec=cipherlane-tray
Icon=cipherlane
Terminal=false
NoDisplay=true
AUTOSTART

  cat > "$DEBROOT/usr/lib/systemd/system/cipherlane.service" << 'UNIT'
[Unit]
Description=cipherlane · 密道 —— 局域网端到端加密传输
After=network.target

[Service]
ExecStart=/usr/bin/cipherlane
# 开机时服务常先于 Wi-Fi 启动：网卡地址后到 / 变化（换网络、休眠唤醒）由服务自动
# 补绑监听，所以这里不需要等网络就绪（After=network-online 会拖慢开机）。
# 默认与源码运行一致：只绑 127.0.0.1 + 局域网（RFC1918）网卡，避免把明文页暴露到
# VPN/公网网卡。确有全网卡需求（如 VPN 内访问）时用 drop-in 覆盖：
#   systemctl edit cipherlane  →  [Service] Environment=HOST=0.0.0.0
Environment=PORT=7777
Restart=on-failure
RestartSec=2
# 最小权限运行：全部资源内嵌于二进制，无文件写入、无 home、无内核面需求
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT

  cat > "$DEBROOT/DEBIAN/control" << CONTROL
Package: cipherlane
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Maintainer: kgpche <341253778+kgpche@users.noreply.github.com>
Description: cipherlane · 密道 —— 局域网端到端加密传输
 自包含 Rust 静态二进制（内嵌全部前端资源），安装即用、无运行时依赖。
 桌面：应用列表点击 cipherlane（托盘自动随登录启动，管理面板经托盘进入）；
 无桌面环境（服务器）: sudo systemctl enable --now cipherlane，
 然后浏览器打开 http://<本机IP>:7777
Recommends: gnome-shell-extension-appindicator
CONTROL

  cat > "$DEBROOT/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
systemctl daemon-reload 2>/dev/null || true
# 升级前在跑的服务：prerm 已记录并停止，这里拉回（新二进制）
if [ -f /run/cipherlane-was-active ]; then
  rm -f /run/cipherlane-was-active
  systemctl start cipherlane 2>/dev/null || true
fi
# GNOME:启用 Ubuntu 自带的 appindicator 扩展,让系统托盘图标可见(无桌面会话时静默跳过)
if command -v gnome-extensions >/dev/null 2>&1 && gnome-extensions list 2>/dev/null | grep -q '^ubuntu-appindicators@'; then
  gnome-extensions enable ubuntu-appindicators@ubuntu.com 2>/dev/null || true
fi
echo
echo "  cipherlane 已安装。应用列表点击 cipherlane 打开传输主页（局域网地址）；"
echo "  管理面板经系统托盘进入（仅回环）。无桌面环境可: sudo systemctl enable --now cipherlane"
echo
exit 0
POSTINST
  chmod 755 "$DEBROOT/DEBIAN/postinst"

  # prerm：升级/卸载前停服务——否则升级后旧进程继续跑旧二进制直到手动 restart。
  # 升级路径先记录"之前在跑"，postinst 据此把服务拉回（升级不得悄悄断服）。
  cat > "$DEBROOT/DEBIAN/prerm" << 'PRERM'
#!/bin/sh
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl stop cipherlane 2>/dev/null || true
elif [ "$1" = "upgrade" ]; then
  if systemctl is-active --quiet cipherlane 2>/dev/null; then
    touch /run/cipherlane-was-active 2>/dev/null || true
  fi
  systemctl stop cipherlane 2>/dev/null || true
fi
exit 0
PRERM
  chmod 755 "$DEBROOT/DEBIAN/prerm"

  # postrm：卸载后清掉失效的 unit 引用（升级路径由新包 postinst 的 daemon-reload 覆盖）
  cat > "$DEBROOT/DEBIAN/postrm" << 'POSTRM'
#!/bin/sh
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl daemon-reload 2>/dev/null || true
fi
exit 0
POSTRM
  chmod 755 "$DEBROOT/DEBIAN/postrm"

  rm -f "$DIST/cipherlane_${VER}_amd64.deb"
  dpkg-deb --build --root-owner-group "$DEBROOT" "$DIST/cipherlane_${VER}_amd64.deb" >/dev/null
  ARTIFACTS="cipherlane_${VER}_amd64.deb"
  echo ">> 已产出: $DIST/cipherlane_${VER}_amd64.deb"
}

# ================= macOS：universal2（server + cli） =================
package_macos() {
  need cargo
  need lipo
  if command -v rustup >/dev/null 2>&1; then
    rustup target add x86_64-apple-darwin aarch64-apple-darwin >/dev/null 2>&1 || true
  fi
  for t in x86_64-apple-darwin aarch64-apple-darwin; do
    echo ">> 构建 macOS ${t}（server / cli）…"
    cargo_build --target "$t" --bin cipherlane --bin cipherlane-cli
  done
  STAGE=$BUILD/macos-root/cipherlane
  rm -rf "$BUILD/macos-root"
  mkdir -p "$STAGE"
  for b in cipherlane cipherlane-cli; do
    lipo -create \
      "$TARGET_DIR/x86_64-apple-darwin/release/$b" \
      "$TARGET_DIR/aarch64-apple-darwin/release/$b" \
      -output "$STAGE/$b"
    chmod 755 "$STAGE/$b"
  done
  cat > "$STAGE/cipherlane.command" << 'CMD'
#!/bin/sh
# 双击启动密道服务器（Terminal 中显示地址与二维码，Ctrl+C 退出）
cd "$(dirname "$0")"
exec ./cipherlane "$@"
CMD
  chmod 755 "$STAGE/cipherlane.command"
  cat > "$STAGE/README.txt" << 'README'
cipherlane · 密道（macOS 版）
================================
启动：双击 cipherlane.command
      首次运行若被 Gatekeeper 拦截：右键 cipherlane.command → 打开 → 再点"打开"
      （或在终端执行 xattr -dr com.apple.quarantine . 解除隔离）
使用：浏览器打开启动后打印的局域网地址，或手机扫终端里的二维码
停止：终端 Ctrl+C
自带 Apple Silicon (arm64) 与 Intel (x64) 双架构 server 与 CLI（cipherlane-cli），无需安装运行时。

CLI 示例：
  ./cipherlane-cli devices --server http://127.0.0.1:7777
  ./cipherlane-cli send big.zip --server http://127.0.0.1:7777

如需制作 .dmg：在任意 Mac 上执行
  hdiutil create -volname cipherlane -srcfolder cipherlane -ov -format UDZO cipherlane.dmg
README
  rm -f "$DIST/cipherlane_${VER}_macos_universal.tar.gz"
  tar czf "$DIST/cipherlane_${VER}_macos_universal.tar.gz" -C "$BUILD/macos-root" cipherlane
  ARTIFACTS="cipherlane_${VER}_macos_universal.tar.gz"
  echo ">> 已产出: $DIST/cipherlane_${VER}_macos_universal.tar.gz"
}

# ================= Windows：x64 原生（server + cli） =================
package_windows() {
  need cargo
  echo ">> 构建 Windows x64（server / cli，静态 CRT）…"
  # 静态 CRT：产物不依赖 VC++ 运行库，解压即用（子 shell 内生效，不影响其他平台）
  (
    RUSTFLAGS="-C target-feature=+crt-static"
    export RUSTFLAGS
    cargo_build --bin cipherlane --bin cipherlane-cli
  )
  REL=$TARGET_DIR/release
  for b in cipherlane.exe cipherlane-cli.exe; do
    [ -f "$REL/$b" ] || { echo "✗ 缺少产物: $REL/$b"; exit 1; }
  done
  STAGE=$BUILD/win-root
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  cp "$REL/cipherlane.exe" "$REL/cipherlane-cli.exe" "$STAGE/"
  cat > "$STAGE/README.txt" << 'README'
cipherlane · 密道（Windows 版）
================================
启动：双击 cipherlane.exe（控制台显示局域网地址与二维码），Ctrl+C 退出
      首次运行若被 SmartScreen 拦截（未签名 exe 的常规提示）：
      点"更多信息" → "仍要运行"
使用：浏览器打开启动后打印的局域网地址；其他设备需在同一 WiFi/网段
CLI：cipherlane-cli.exe devices --server http://127.0.0.1:7777
     cipherlane-cli.exe send big.zip --server http://127.0.0.1:7777
说明：单文件静态 CRT，无需安装任何运行库；Windows 10/11 x64。
README
  ( cd "$STAGE" && make_zip "../dist/cipherlane_${VER}_windows_x64.zip" cipherlane.exe cipherlane-cli.exe README.txt )
  ARTIFACTS="cipherlane_${VER}_windows_x64.zip"
  echo ">> 已产出: $DIST/cipherlane_${VER}_windows_x64.zip"
}

# ================= 分发 =================
case "$OS" in
  Linux*)                       package_linux ;;
  Darwin*)                      package_macos ;;
  MINGW*|MSYS*|CYGWIN*)         package_windows ;;
  *) echo "✗ 不支持的宿主平台: $OS"; exit 1 ;;
esac

write_sums
echo
echo "✓ 打包完成（cipherlane ${VER}，${OS}/${ARCH}）"
for f in $ARTIFACTS; do ls -la "$DIST/$f"; done
