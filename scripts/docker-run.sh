#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-sprox:local}"
CONTAINER_NAME="${CONTAINER_NAME:-sprox}"
CONFIG_PATH="${CONFIG_PATH:-${REPO_ROOT}/config}"

pushd "${REPO_ROOT}" >/dev/null

echo "Building image ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" .

echo "Starting container ${CONTAINER_NAME}..."
docker run --rm \
    --name "${CONTAINER_NAME}" \
    -p "8080:8080" \
    -v "${CONFIG_PATH}:/app/config:ro" \
    "${IMAGE_NAME}" "$@"

popd >/dev/null
