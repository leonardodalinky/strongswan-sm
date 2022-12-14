#!/bin/bash
# 这个文件为 SM 国密算法加密开发过程中所使用的构建脚本
# 以下参数为启用 ipsec 的最小化配置
# 修改之前，请与各位组员讨论

cd $(dirname $0) || exit 1
CUR_DIR=$(pwd)
DEV_DIR="$CUR_DIR/dev"
CONF_DIR="$DEV_DIR/conf"

mkdir -p "$DEV_DIR/systemd/system"

./configure --prefix="$DEV_DIR" \
  --sysconfdir="$CONF_DIR" \
  --enable-curl \
  --enable-kernel-libipsec \
  --enable-libipsec \
  --enable-openssl \
  --enable-tpm \
  --enable-vici \
  --with-linux-headers=/usr/include \
  --with-systemdsystemunitdir="$DEV_DIR/systemd/system"

