# Packaging Helpers

This directory provides thin wrappers around the packagers used by the
streaming pipeline. Each script is intentionally verbose about the
environment variables it expects so that the automation driving them can
source values from a secrets manager or `.env` file.

## Bundled binaries

The official Docker image produced from this repository now bundles the
following utilities so the helper scripts can run without additional
setup:

- **FFmpeg 5.1.4-0+deb12u1** (from Debian bookworm) is installed at
  `/usr/bin/ffmpeg` and available via the default `PATH`.
- **Shaka Packager v2.6.1** is installed as `/usr/local/bin/packager` with a
  `shaka-packager` symlink for convenience.

Deployments that rely on these images can invoke the scripts directly, or set
`FFMPEG_BIN` / `SHAKA_BIN` to override the bundled versions when newer builds
are desired.

## `ffmpeg_packager.sh`

Encrypts a mezzanine file using FFmpeg's Common Encryption support. The script
expects the following variables to be exported before invocation:

- `FFMPEG_BIN` *(optional)* – Path to the FFmpeg binary.
- `FFMPEG_INPUT` – Absolute or relative path to the mezzanine input file.
- `FFMPEG_OUTPUT_DIR` – Directory where encrypted assets will be stored.
- `FFMPEG_VIDEO_BITRATE` *(optional)* – Target video bitrate (default: `3500k`).
- `FFMPEG_AUDIO_BITRATE` *(optional)* – Target audio bitrate (default: `128k`).
- `DRM_MODE` *(optional)* – Set to `disabled` to skip DRM entirely (default: `enabled`).
- `DRM_KEY_ID` – Hex-encoded key identifier (KID). Required when `DRM_MODE=enabled`.
- `DRM_KEY_HEX` – Hex-encoded AES key. Required when `DRM_MODE=enabled`.
- `DRM_IV_HEX` *(optional)* – Initialization vector override; defaults to all zeros when DRM is enabled.

## `shaka_packager.sh`

Creates DASH and HLS outputs using Shaka Packager with raw-key DRM. Expected
variables include:

- `SHAKA_BIN` *(optional)* – Path to the Shaka Packager binary.
- `INPUT_VIDEO` – Video-only input file.
- `INPUT_AUDIO` – Audio-only input file.
- `OUTPUT_DIR` – Target directory for manifests and fragmented MP4 files.
- `STREAM_LABEL` *(optional)* – Label assigned to the video stream (default: `video`).
- `AUDIO_LABEL` *(optional)* – Label assigned to the audio stream (default: `audio`).
- `PACKAGER_BASE_URL` *(optional)* – Base URL advertised in the generated manifests.
- `DRM_MODE` *(optional)* – Set to `disabled` for clear output (default: `enabled`).
- `DRM_KEY_ID` – Hex-encoded key identifier. Required when `DRM_MODE=enabled`.
- `DRM_KEY_HEX` – Hex-encoded AES key. Required when `DRM_MODE=enabled`.
- `DRM_PSSH_BASE64` *(optional)* – Base64 encoded custom PSSH box to embed when DRM is enabled.
- `DRM_CONTENT_ID` *(optional)* – Identifier used in Widevine requests (default: `sprox-demo`).
- `DRM_LICENSE_URL` – URL of the license proxy / DRM provider. Required when `DRM_MODE=enabled`.

Scripts can be invoked directly after exporting the variables or sourcing an
`.env` file. Example:

### Examples

**Encrypted output with FFmpeg**

```bash
export FFMPEG_INPUT=assets/mezzanine.mp4
export FFMPEG_OUTPUT_DIR=./build/ffmpeg
export DRM_KEY_ID=0123456789abcdef0123456789abcdef
export DRM_KEY_HEX=abcdef0123456789abcdef0123456789
./packagers/ffmpeg_packager.sh
```

**Clear output with FFmpeg**

```bash
export FFMPEG_INPUT=assets/mezzanine.mp4
export FFMPEG_OUTPUT_DIR=./build/ffmpeg
export DRM_MODE=disabled
./packagers/ffmpeg_packager.sh
```

**Encrypted output with Shaka Packager**

```bash
export INPUT_VIDEO=assets/video.mp4
export INPUT_AUDIO=assets/audio.m4a
export OUTPUT_DIR=./build/shaka
export DRM_KEY_ID=0123456789abcdef0123456789abcdef
export DRM_KEY_HEX=abcdef0123456789abcdef0123456789
export DRM_LICENSE_URL=https://license.example.com
./packagers/shaka_packager.sh
```

**Clear output with Shaka Packager**

```bash
export INPUT_VIDEO=assets/video.mp4
export INPUT_AUDIO=assets/audio.m4a
export OUTPUT_DIR=./build/shaka
export DRM_MODE=disabled
./packagers/shaka_packager.sh
```

Because the scripts use `set -euo pipefail`, they will fail fast whenever a
required value is missing, preventing partially encrypted artifacts from being
produced.
