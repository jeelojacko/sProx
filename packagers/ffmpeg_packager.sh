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
: "${DRM_MODE:=enabled}"            # Set to "disabled" for clear output

case "${DRM_MODE}" in
  enabled|disabled) ;;
  *)
    echo "Unsupported DRM_MODE '${DRM_MODE}'. Use 'enabled' or 'disabled'." >&2
    exit 1
    ;;
esac

if [[ "${DRM_MODE}" != "disabled" ]]; then
  # DRM placeholders. Replace these with your Widevine/PlayReady keys or point
  # to a secrets manager before running the script.
  : "${DRM_KEY_ID:?Need to set DRM_KEY_ID}"         # e.g. 0123456789abcdef0123456789abcdef
  : "${DRM_KEY_HEX:?Need to set DRM_KEY_HEX}"       # Raw AES-128 key in hex
  : "${DRM_IV_HEX:=00000000000000000000000000000000}" # Optional IV override
fi

mkdir -p "${FFMPEG_OUTPUT_DIR}"

FFMPEG_CMD=(
  "${FFMPEG_BIN}"
  -y
  -i "${FFMPEG_INPUT}"
  -c:v libx264
  -b:v "${FFMPEG_VIDEO_BITRATE}"
  -c:a aac
  -b:a "${FFMPEG_AUDIO_BITRATE}"
  -movflags +faststart
)

if [[ "${DRM_MODE}" != "disabled" ]]; then
  FFMPEG_CMD+=(
    -encryption_scheme cenc-aes-ctr
    -encryption_key "${DRM_KEY_HEX}"
    -encryption_kid "${DRM_KEY_ID}"
    -encryption_iv "${DRM_IV_HEX}"
  )
fi

OUTPUT_FILENAME="encrypted_output.mp4"
if [[ "${DRM_MODE}" == "disabled" ]]; then
  OUTPUT_FILENAME="clear_output.mp4"
fi

FFMPEG_CMD+=("${FFMPEG_OUTPUT_DIR}/${OUTPUT_FILENAME}")

"${FFMPEG_CMD[@]}"

if [[ "${DRM_MODE}" != "disabled" ]]; then
  cat <<INFO
Packaging complete.
Output stored at: ${FFMPEG_OUTPUT_DIR}/${OUTPUT_FILENAME}
DRM mode: ${DRM_MODE}
Used DRM key ID: ${DRM_KEY_ID}
INFO
else
  cat <<INFO
Packaging complete.
Output stored at: ${FFMPEG_OUTPUT_DIR}/${OUTPUT_FILENAME}
DRM mode: ${DRM_MODE}
INFO
fi
