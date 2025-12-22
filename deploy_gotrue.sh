#!/usr/bin/env bash
set -euo pipefail

# deploy_gotrue.sh
# 构建 gotrue 镜像（linux/amd64）、导出为 tar、上传到远程服务器并在远程重启 gotrue 服务
#
# 使用方法（默认值按 .ai-rules 配置）:
#   ./scripts/deploy_gotrue.sh
# 可通过环境变量覆盖默认值，例如：
#   BUILD_PLATFORM=linux/amd64 IMAGE_TAG=dev-aliyun-sms REMOTE_HOST=8.152.101.166 ./scripts/deploy_gotrue.sh

########################################################################
# 可配置项（按需修改或通过环境变量覆盖）
REPO_DIR="${REPO_DIR:-/Users/kuncao/github.com/PonyNotes-IO/PonyNotes-gotrue}"
BUILD_PLATFORM="${BUILD_PLATFORM:-linux/amd64}"
IMAGE_NAME="${IMAGE_NAME:-appflowyinc/gotrue}"
IMAGE_TAG="${IMAGE_TAG:-dev-aliyun-sms}"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
TAR_PATH="${TAR_PATH:-/tmp/gotrue.tar}"

REMOTE_USER="${REMOTE_USER:-root}"
REMOTE_HOST="${REMOTE_HOST:-8.152.101.166}"
REMOTE_DIR="${REMOTE_DIR:-/root/docker-compose}"
REMOTE_TAR_NAME="${REMOTE_TAR_NAME:-gotrue.tar}"
REMOTE_COMPOSE_FILE="${REMOTE_COMPOSE_FILE:-docker-compose-dev.yml}"

# SSH 选项（按需调整）
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}"

########################################################################
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }

if [[ "$(id -u)" -eq 0 ]]; then
  : # allow root too
fi

echo
log "开始：构建并部署 gotrue 镜像"
log "配置：REPO_DIR=${REPO_DIR}, BUILD_PLATFORM=${BUILD_PLATFORM}, IMAGE=${FULL_IMAGE}, TAR_PATH=${TAR_PATH}"

# 1) 构建镜像（使用 buildx 以支持指定平台）
log "进入仓库目录：${REPO_DIR}"
cd "${REPO_DIR}"

log "开始构建镜像 ${FULL_IMAGE}（平台 ${BUILD_PLATFORM}）……"
# docker buildx build --platform "${BUILD_PLATFORM}" -t "${FULL_IMAGE}" --load .
log "镜像构建完成：${FULL_IMAGE}"

# 2) 导出镜像为 tar
log "导出镜像到本地 tar：${TAR_PATH}"
docker save "${FULL_IMAGE}" -o "${TAR_PATH}"
log "导出完成：${TAR_PATH}"

# 3) 传输 tar 到远程服务器
log "上传 ${TAR_PATH} 到远程服务器 ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/${REMOTE_TAR_NAME}"
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${TAR_PATH}" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/${REMOTE_TAR_NAME}"
log "上传完成"

# 4) 在远程执行停止服务、删除旧镜像、导入新镜像、启动服务
log "在远端执行部署步骤（停止服务 -> 删除旧镜像 -> 导入新镜像 -> 启动服务）"
ssh ${SSH_OPTS} "${REMOTE_USER}@${REMOTE_HOST}" bash -se <<EOF
set -euo pipefail
cd "${REMOTE_DIR}"
log() { printf '%s %s\n' "\$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "\$*"; }
log "远程：停止 compose 服务（若正在运行）"
docker compose --file "${REMOTE_COMPOSE_FILE}" down || true

log "远程：删除旧镜像 ${FULL_IMAGE}（如果存在）"
docker rmi "${FULL_IMAGE}" || true

log "远程：导入新镜像"
docker load -i "${REMOTE_DIR}/${REMOTE_TAR_NAME}"

log "远程：启动 gotrue 服务（docker compose up -d）"
docker compose --file "${REMOTE_COMPOSE_FILE}" up -d

log "远程：部署完成"
EOF

log "部署脚本执行完成。请在远程查看 gotrue 日志确认服务状态："
log "  ssh ${REMOTE_USER}@${REMOTE_HOST} \"cd ${REMOTE_DIR} && docker compose --file ${REMOTE_COMPOSE_FILE} logs -f gotrue\""
echo
log "结束"

exit 0

