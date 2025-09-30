#!/usr/bin/env bash
set -euo pipefail

# Helper script for packaging media with FFmpeg while highlighting the
# configuration that the rest of the pipeline expects. All variables below can
# be sourced from an environment file (e.g. `source ./config/packaging.env`).

: "${FFMPEG_BIN:=ffmpeg}"            # Override to point to a custom FFmpeg build
: "${FFMPEG_INPUT:?Need to set FFMPEG_INPUT to the mezzanine file}" 
: "${FFMPEG_OUTPUT_DIR:?Need to set FFMPEG_OUTPUT_DIR to the output directory}" 
: "${FFMPEG_VIDEO_BITRATE:=3500k}"  # Example video bitrate
: "${FFMPEG_AUDIO_BITRATE:=128k}"   # Example audio bitrate

# DRM placeholders. Replace these with your Widevine/PlayReady keys or point
# to a secrets manager before running the script.
: "${DRM_KEY_ID:?Need to set DRM_KEY_ID}"         # e.g. 0123456789abcdef0123456789abcdef
: "${DRM_KEY_HEX:?Need to set DRM_KEY_HEX}"       # Raw AES-128 key in hex
: "${DRM_IV_HEX:=00000000000000000000000000000000}" # Optional IV override

mkdir -p "${FFMPEG_OUTPUT_DIR}"

"${FFMPEG_BIN}" \
  -y \
  -i "${FFMPEG_INPUT}" \
  -c:v libx264 \
  -b:v "${FFMPEG_VIDEO_BITRATE}" \
  -c:a aac \
  -b:a "${FFMPEG_AUDIO_BITRATE}" \
  -movflags +faststart \
  -encryption_scheme cenc-aes-ctr \
  -encryption_key "${DRM_KEY_HEX}" \
  -encryption_kid "${DRM_KEY_ID}" \
  -encryption_iv "${DRM_IV_HEX}" \
  "${FFMPEG_OUTPUT_DIR}/encrypted_output.mp4"

cat <<INFO
Packaging complete.
Encrypted output stored at: ${FFMPEG_OUTPUT_DIR}/encrypted_output.mp4
Used DRM key ID: ${DRM_KEY_ID}
INFO
