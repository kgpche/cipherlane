#!/bin/sh
# cipherlane 多平台打包：一条命令产出 .deb / .exe(zip) / macOS 通用包
#
#   sh build/package.sh [版本号]      # 默认取 package.json 的 version
#
# 产物：build/dist/cipherlane_<ver>_amd64.deb          （Linux，内含 systemd 单元）
#       build/dist/cipherlane_<ver>_windows_x64.zip    （Windows 单文件 exe）
#       build/dist/cipherlane_<ver>_macos_universal.tar.gz（arm64+x64 双架构）
#
# 依赖：node ≥22（生成 SEA blob）、curl、tar、zip/unzip、dpkg-deb；
#      postject 已内置于 build/tools/（首次运行自动下载）。
# 官方 Node 二进制会缓存到 build/，重复打包不重复下载。
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)
BUILD=$ROOT/build
DIST=$BUILD/dist
NODE_VER=v22.22.1
VER=${1:-$(node -p "require('./package.json').version")}
FUSE=NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2

mkdir -p "$DIST"

# ---------- 0) postject（纯 JS 二进制注入器，零全局依赖；sha256 固定校验） ----------
POSTJECT_SHA=d1447b53e87d49ddaf7fb3350c870afafa72760eca47f6d5cce4cefd537e7d92
COMMANDER_SHA=b64948bf68db38c26002a1a4b63b8ecb9a80e497e308fdaccbb179cf05142f52
sha_verify() { # $1=期望 sha256 $2=文件
  echo "$1  $2" | sha256sum -c - >/dev/null || { echo "✗ 校验失败: $2（供应链完整性无法确认）"; exit 1; }
}
if [ ! -f "$BUILD/tools/postject/dist/cli.js" ]; then
  echo ">> 下载 postject…"
  mkdir -p "$BUILD/tools/postject/node_modules/commander"
  curl -sL -o /tmp/postject.tgz https://registry.npmjs.org/postject/-/postject-1.0.0-alpha.6.tgz
  sha_verify "$POSTJECT_SHA" /tmp/postject.tgz
  tar xzf /tmp/postject.tgz -C "$BUILD/tools/postject" --strip-components=1
  curl -sL -o /tmp/commander.tgz https://registry.npmjs.org/commander/-/commander-9.5.0.tgz
  sha_verify "$COMMANDER_SHA" /tmp/commander.tgz
  tar xzf /tmp/commander.tgz -C "$BUILD/tools/postject/node_modules/commander" --strip-components=1
fi
POSTJECT="node $BUILD/tools/postject/dist/cli.js"

# ---------- 1) 官方 Node 二进制（缓存；下载后经官方 SHASUMS256.txt 校验） ----------
curl -sL -o "$BUILD/SHASUMS256.txt" "https://nodejs.org/dist/$NODE_VER/SHASUMS256.txt"
verify_from_shasums() { # $1=SHASUMS 中的归档名 $2=本地文件
  want=$(grep " $1\$" "$BUILD/SHASUMS256.txt" | awk '{print $1}')
  [ -n "$want" ] || { echo "✗ SHASUMS256.txt 中找不到 $1"; exit 1; }
  echo "$want  $2" | sha256sum -c - >/dev/null || { echo "✗ 校验失败: $2"; exit 1; }
}
fetch_node() { # $1=文件名 $2=URL $3=解压后内部路径 $4=SHASUMS 中的归档名
  if [ ! -f "$BUILD/$1" ]; then
    echo ">> 下载 $2 …"
    curl -sL -o "$BUILD/$1.dl" "$2"
    verify_from_shasums "$4" "$BUILD/$1.dl"
    case "$2" in
      *.tar.xz) tar xJf "$BUILD/$1.dl" -C "$BUILD" && mv "$BUILD/$3" "$BUILD/$1" ;;
      *.tar.gz) tar xzf "$BUILD/$1.dl" -C "$BUILD" && mv "$BUILD/$3" "$BUILD/$1" ;;
      *.zip)    unzip -o -q "$BUILD/$1.dl" "$3" -d "$BUILD/tmp-zip" && mv "$BUILD/tmp-zip/$3" "$BUILD/$1" && rm -rf "$BUILD/tmp-zip" ;;
    esac
    rm -f "$BUILD/$1.dl"
  fi
}
fetch_node node-linux  https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-linux-x64.tar.xz node-$NODE_VER-linux-x64/bin/node node-$NODE_VER-linux-x64.tar.xz
fetch_node node-win    https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-win-x64.zip      node-$NODE_VER-win-x64/node.exe    node-$NODE_VER-win-x64.zip
fetch_node node-mac-a  https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-darwin-arm64.tar.gz node-$NODE_VER-darwin-arm64/bin/node node-$NODE_VER-darwin-arm64.tar.gz
fetch_node node-mac-x  https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-darwin-x64.tar.gz   node-$NODE_VER-darwin-x64/bin/node   node-$NODE_VER-darwin-x64.tar.gz

# ---------- 2) SEA blob（跨平台共享；关 code cache 保证跨平台兼容） ----------
echo ">> 生成 SEA blob…"
node --experimental-sea-config sea-config.json

# ---------- 3) Linux：SEA 二进制 → .deb ----------
echo ">> 打包 Linux .deb…"
cp "$BUILD/node-linux" "$BUILD/cipherlane-linux-x64"
chmod +x "$BUILD/cipherlane-linux-x64"
$POSTJECT "$BUILD/cipherlane-linux-x64" NODE_SEA_BLOB "$BUILD/sea-prep.blob" --sentinel-fuse $FUSE >/dev/null
DEBROOT=$BUILD/deb-root
rm -rf "$DEBROOT"
mkdir -p "$DEBROOT/DEBIAN" "$DEBROOT/usr/bin" "$DEBROOT/usr/lib/systemd/system"
cp "$BUILD/cipherlane-linux-x64" "$DEBROOT/usr/bin/cipherlane"
chmod 755 "$DEBROOT/usr/bin/cipherlane"
cat > "$DEBROOT/usr/lib/systemd/system/cipherlane.service" << 'EOF'
[Unit]
Description=cipherlane · 密道 —— 局域网端到端加密传输
After=network.target

[Service]
ExecStart=/usr/bin/cipherlane
Environment=HOST=0.0.0.0 PORT=7777
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
EOF
cat > "$DEBROOT/DEBIAN/control" << EOF
Package: cipherlane
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Maintainer: joker <joker@local>
Description: cipherlane · 密道 —— 局域网端到端加密传输
 自包含单文件服务（内嵌 Node 运行时与全部前端资源），安装即用、无需 Node。
 安装后执行: sudo systemctl enable --now cipherlane
 然后浏览器打开 http://<本机IP>:7777
EOF
printf '#!/bin/sh\nsystemctl daemon-reload 2>/dev/null || true\necho\necho "  cipherlane 已安装。启动服务：sudo systemctl enable --now cipherlane"\necho "  或前台运行：cipherlane"\necho\nexit 0\n' > "$DEBROOT/DEBIAN/postinst"
chmod 755 "$DEBROOT/DEBIAN/postinst"
dpkg-deb --build --root-owner-group "$DEBROOT" "$DIST/cipherlane_${VER}_amd64.deb" >/dev/null

# ---------- 4) Windows：SEA 注入 node.exe → cipherlane.exe（zip） ----------
echo ">> 打包 Windows exe…"
cp "$BUILD/node-win" "$BUILD/cipherlane.exe"
$POSTJECT "$BUILD/cipherlane.exe" NODE_SEA_BLOB "$BUILD/sea-prep.blob" --sentinel-fuse $FUSE >/dev/null 2>&1
rm -f "$DIST/cipherlane_${VER}_windows_x64.zip"
(cd "$BUILD" && zip -q -9 "$DIST/cipherlane_${VER}_windows_x64.zip" cipherlane.exe)

# ---------- 5) macOS：源码 + 双架构 node + 双击 .command（通用包） ----------
echo ">> 打包 macOS 通用包…"
PKG=$BUILD/macos-root/cipherlane
rm -rf "$BUILD/macos-root"
mkdir -p "$PKG/app"
cp server.js package.json "$PKG/app/"
cp -r public logo "$PKG/app/"
cp "$BUILD/node-mac-a" "$PKG/node-arm64"
cp "$BUILD/node-mac-x" "$PKG/node-x64"
chmod +x "$PKG/node-arm64" "$PKG/node-x64"
cat > "$PKG/cipherlane.command" << 'EOF'
#!/bin/sh
# 双击启动密道服务器（Terminal 中显示地址与二维码，Ctrl+C 退出）
cd "$(dirname "$0")"
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then NODE=./node-arm64; else NODE=./node-x64; fi
exec "$NODE" app/server.js "$@"
EOF
chmod +x "$PKG/cipherlane.command"
cat > "$PKG/README.txt" << 'EOF'
cipherlane · 密道（macOS 版）
================================
启动：双击 cipherlane.command
      首次运行若被 Gatekeeper 拦截：右键 cipherlane.command → 打开 → 再点"打开"
      （或在终端执行 xattr -dr com.apple.quarantine . 解除隔离）
使用：浏览器打开启动后打印的局域网地址，或手机扫终端里的二维码
停止：终端 Ctrl+C
内含 Apple Silicon (arm64) 与 Intel (x64) 双架构运行时，无需安装 Node。

如需制作 .dmg：在任意 Mac 上执行
  hdiutil create -volname cipherlane -srcfolder cipherlane -ov -format UDZO cipherlane.dmg
EOF
tar czf "$DIST/cipherlane_${VER}_macos_universal.tar.gz" -C "$BUILD/macos-root" cipherlane

echo
echo "✓ 打包完成："
ls -la "$DIST"
