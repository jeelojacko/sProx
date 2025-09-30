#!/usr/bin/env bash
set -euo pipefail

# Helper script to invoke Shaka Packager with Widevine-like placeholders.
# Export the variables below or load them from your preferred secrets store
# before running the script.

: "${SHAKA_BIN:=packager}"             # Override to point to the packager binary
: "${INPUT_VIDEO:?Set INPUT_VIDEO to the source video file}" 
: "${INPUT_AUDIO:?Set INPUT_AUDIO to the source audio file}" 
: "${OUTPUT_DIR:?Set OUTPUT_DIR to the directory for DASH/HLS outputs}" 
: "${STREAM_LABEL:=video}"             # Label used in the manifest for video
: "${AUDIO_LABEL:=audio}"              # Label used in the manifest for audio
: "${PACKAGER_BASE_URL:=https://cdn.example.com/}" # Base URL advertised in the manifests

# DRM placeholders. Replace these with the actual values provided by your DRM
# provider. They can also be injected securely via environment variables in CI.
: "${DRM_KEY_ID:?Set DRM_KEY_ID (hex)}"
: "${DRM_KEY_HEX:?Set DRM_KEY_HEX (hex)}"
: "${DRM_PSSH_BASE64:=}"               # Optional custom PSSH data (base64)
: "${DRM_CONTENT_ID:=sprox-demo}"     # Used for Widevine license requests
: "${DRM_LICENSE_URL:?Set DRM_LICENSE_URL}" # e.g. https://license.example.com

mkdir -p "${OUTPUT_DIR}"

COMMON_PARAMS=(
  "--enable_raw_key_encryption"
  "--key_id=${DRM_KEY_ID}"
  "--key=${DRM_KEY_HEX}"
  "--content_id=${DRM_CONTENT_ID}"
  "--clear_lead=0"
  "--generate_static_mpd"
  "--mpd_output=${OUTPUT_DIR}/manifest.mpd"
  "--hls_master_playlist_output=${OUTPUT_DIR}/master.m3u8"
  "--protection_scheme=cenc"
  "--base_urls=${PACKAGER_BASE_URL}"
)

if [[ -n "${DRM_PSSH_BASE64}" ]]; then
  COMMON_PARAMS+=("--pssh=${DRM_PSSH_BASE64}")
fi

"${SHAKA_BIN}" \
  "in=${INPUT_VIDEO},stream=video,output=${OUTPUT_DIR}/${STREAM_LABEL}.mp4" \
  "in=${INPUT_AUDIO},stream=audio,output=${OUTPUT_DIR}/${AUDIO_LABEL}.mp4" \
  "${COMMON_PARAMS[@]}"

cat <<INFO
Shaka packaging complete.
DASH manifest: ${OUTPUT_DIR}/manifest.mpd
HLS playlist: ${OUTPUT_DIR}/master.m3u8
DRM license URL: ${DRM_LICENSE_URL}
INFO
