use std::str;

use thiserror::Error;
use url::Url;

/// Errors that can occur while rewriting HLS manifests.
#[derive(Debug, Error)]
pub enum HlsError {
    #[error("manifest is not valid UTF-8: {0}")]
    InvalidUtf8(str::Utf8Error),
    #[error("HLS manifest rewriting requires a base_url to be configured")]
    MissingBaseUrl,
    #[error("failed to resolve playlist reference `{uri}`: {source}")]
    ResolveReference {
        uri: String,
        #[source]
        source: url::ParseError,
    },
    #[error("URI attribute on line `{line}` is malformed")]
    MalformedAttribute { line: String },
    #[error("rewriting would emit insecure HTTP segments but allow_insecure_segments is false")]
    InsecureOutput,
}

/// Rewrites playlist references so that keys, segments, and nested playlists
/// point to the configured public base URL.
///
/// When `rewrite_playlist_urls` is disabled the original playlist is returned
/// untouched. Data and blob URIs are always preserved to avoid corrupting
/// non-HTTP references.
pub fn rewrite_playlist(
    manifest_bytes: &[u8],
    manifest_url: &Url,
    base_url: Option<&Url>,
    rewrite_playlist_urls: bool,
    allow_insecure_segments: bool,
) -> Result<Vec<u8>, HlsError> {
    if !rewrite_playlist_urls {
        return Ok(manifest_bytes.to_vec());
    }

    let base_url = base_url.ok_or(HlsError::MissingBaseUrl)?;
    if base_url.scheme() != "https" && !allow_insecure_segments {
        return Err(HlsError::InsecureOutput);
    }

    let manifest = str::from_utf8(manifest_bytes).map_err(HlsError::InvalidUtf8)?;
    let mut output = String::with_capacity(manifest.len() + 32);
    let mut first = true;
    let ends_with_newline = manifest.ends_with('\n');

    for line in manifest.split('\n') {
        let trimmed_line = line.trim_end_matches('\r');
        if !first {
            output.push('\n');
        }
        first = false;

        let rewritten = process_line(
            trimmed_line,
            manifest_url,
            base_url,
            allow_insecure_segments,
        )?;
        output.push_str(&rewritten);
    }

    if ends_with_newline {
        output.push('\n');
    }

    Ok(output.into_bytes())
}

fn process_line(
    line: &str,
    manifest_url: &Url,
    base_url: &Url,
    allow_insecure_segments: bool,
) -> Result<String, HlsError> {
    if line.trim().is_empty() {
        return Ok(line.to_string());
    }

    if line.starts_with('#') {
        return rewrite_uri_attribute(line, manifest_url, base_url, allow_insecure_segments);
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(line.to_string());
    }

    let rewritten = rewrite_reference(trimmed, manifest_url, base_url, allow_insecure_segments)?;
    let start = line.find(trimmed).unwrap_or(0);
    let mut new_line = String::with_capacity(line.len() + rewritten.len());
    new_line.push_str(&line[..start]);
    let end = start + trimmed.len();
    new_line.push_str(&rewritten);
    new_line.push_str(&line[end..]);

    Ok(new_line)
}

fn rewrite_uri_attribute(
    line: &str,
    manifest_url: &Url,
    base_url: &Url,
    allow_insecure_segments: bool,
) -> Result<String, HlsError> {
    let search = "URI=\"";
    if let Some(start) = line.find(search) {
        let value_start = start + search.len();
        if let Some(end_offset) = line[value_start..].find('"') {
            let value_end = value_start + end_offset;
            let value = &line[value_start..value_end];
            let rewritten =
                rewrite_reference(value, manifest_url, base_url, allow_insecure_segments)?;
            let mut new_line = String::with_capacity(line.len() + rewritten.len());
            new_line.push_str(&line[..value_start]);
            new_line.push_str(&rewritten);
            new_line.push_str(&line[value_end..]);
            return Ok(new_line);
        } else {
            return Err(HlsError::MalformedAttribute {
                line: line.to_string(),
            });
        }
    }

    Ok(line.to_string())
}

fn rewrite_reference(
    reference: &str,
    manifest_url: &Url,
    base_url: &Url,
    allow_insecure_segments: bool,
) -> Result<String, HlsError> {
    let resolved = resolve_reference(reference, manifest_url)?;
    if !matches!(resolved.scheme(), "http" | "https") {
        return Ok(reference.to_string());
    }

    if base_url.scheme() != "https" && !allow_insecure_segments {
        return Err(HlsError::InsecureOutput);
    }

    let mut new_url = base_url.clone();
    let base_segments: Vec<String> = base_url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(|segment| segment.to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut resolved_segments = resolved
        .path_segments()
        .map(|segments| normalize_path_segments(segments.filter(|segment| !segment.is_empty())))
        .unwrap_or_default();

    let mut combined = base_segments;
    combined.append(&mut resolved_segments);

    {
        let mut path_builder = new_url
            .path_segments_mut()
            .expect("base URL should support path segments");
        path_builder.clear();
        for segment in &combined {
            path_builder.push(segment);
        }
    }

    if combined.is_empty() {
        new_url.set_path("/");
    }

    let resolved_path = resolved.path();
    let resolved_has_trailing_slash = resolved_path.ends_with('/') && !resolved_path.is_empty();
    let base_had_trailing_slash = base_url.path().ends_with('/');
    if resolved_has_trailing_slash || (resolved_path.is_empty() && base_had_trailing_slash) {
        let mut path = new_url.path().to_string();
        if !path.ends_with('/') {
            path.push('/');
            new_url.set_path(&path);
        }
    }

    new_url.set_query(resolved.query());
    new_url.set_fragment(resolved.fragment());

    if !allow_insecure_segments && new_url.scheme() != "https" {
        return Err(HlsError::InsecureOutput);
    }

    Ok(new_url.to_string())
}

fn normalize_path_segments<'a>(segments: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut normalized = Vec::new();
    for segment in segments {
        match segment {
            "." => continue,
            ".." => {
                normalized.pop();
            }
            other => normalized.push(other.to_string()),
        }
    }
    normalized
}

fn resolve_reference(reference: &str, manifest_url: &Url) -> Result<Url, HlsError> {
    manifest_url
        .join(reference)
        .or_else(|_| Url::parse(reference))
        .map_err(|source| HlsError::ResolveReference {
            uri: reference.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_updates_segments_and_keys() {
        let manifest = b"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-KEY:METHOD=AES-128,URI=\"keys/key.key\"\n#EXTINF:4.0,\nsegment1.ts\n#EXTINF:4.0,\nhttps://origin.example.com/vod/segment2.ts\n";
        let manifest_url = Url::parse("https://origin.example.com/vod/master.m3u8").unwrap();
        let base_url = Url::parse("https://cdn.example.com/hls/").unwrap();

        let rewritten =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), true, true).unwrap();
        let output = String::from_utf8(rewritten).unwrap();

        assert!(output.contains("https://cdn.example.com/hls/vod/segment1.ts"));
        assert!(output.contains("https://cdn.example.com/hls/vod/segment2.ts"));
        assert!(output.contains("https://cdn.example.com/hls/vod/keys/key.key"));
    }

    #[test]
    fn rewrite_normalizes_parent_segments() {
        let manifest = b"#EXTM3U\n#EXTINF:6.0,\n../video/../segment.ts\n";
        let manifest_url = Url::parse("https://origin.example.com/path/sub/master.m3u8").unwrap();
        let base_url = Url::parse("https://cdn.example.com/hls/").unwrap();

        let rewritten =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), true, true).unwrap();
        let output = String::from_utf8(rewritten).unwrap();

        assert!(output.contains("https://cdn.example.com/hls/path/segment.ts"));
        assert!(!output.contains(".."));
    }

    #[test]
    fn rewrite_preserves_key_iv_and_map_attributes() {
        let manifest = b"#EXTM3U\n#EXT-X-MAP:URI=\"init/init.mp4\",BYTERANGE=\"720@0\"\n#EXT-X-KEY:METHOD=AES-128,URI=\"keys/key.key\",IV=0x1234\n";
        let manifest_url = Url::parse("https://origin.example.com/vod/main.m3u8").unwrap();
        let base_url = Url::parse("https://cdn.example.com/assets/").unwrap();

        let rewritten =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), true, true).unwrap();
        let output = String::from_utf8(rewritten).unwrap();

        assert!(output.contains(
            "#EXT-X-MAP:URI=\"https://cdn.example.com/assets/vod/init/init.mp4\",BYTERANGE=\"720@0\""
        ));
        assert!(output.contains(
            "#EXT-X-KEY:METHOD=AES-128,URI=\"https://cdn.example.com/assets/vod/keys/key.key\",IV=0x1234"
        ));
    }

    #[test]
    fn rewrite_updates_variant_playlists_without_touching_metadata() {
        let manifest = b"#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-STREAM-INF:BANDWIDTH=1280000,AVERAGE-BANDWIDTH=1100000,CODECS=\"avc1.640029,mp4a.40.2\"\nvideo/main.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=640000,RESOLUTION=640x360\nhttp://origin.example.com/video/low.m3u8\n";
        let manifest_url = Url::parse("https://origin.example.com/master.m3u8").unwrap();
        let base_url = Url::parse("https://cdn.example.com/hls/").unwrap();

        let rewritten =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), true, false).unwrap();
        let output = String::from_utf8(rewritten).unwrap();

        assert!(output.contains("#EXT-X-STREAM-INF:BANDWIDTH=1280000,AVERAGE-BANDWIDTH=1100000,CODECS=\"avc1.640029,mp4a.40.2\""));
        assert!(output.contains("#EXT-X-STREAM-INF:BANDWIDTH=640000,RESOLUTION=640x360"));
        assert!(output.contains("https://cdn.example.com/hls/video/main.m3u8"));
        assert!(output.contains("https://cdn.example.com/hls/video/low.m3u8"));
        assert!(!output.contains("http://origin.example.com"));
    }

    #[test]
    fn rewrite_preserves_non_http_references() {
        let manifest = b"#EXTM3U\n#EXT-X-MAP:URI=\"data:application/octet-stream;base64,AAAA\"\n";
        let manifest_url = Url::parse("https://origin.example.com/init.m3u8").unwrap();
        let base_url = Url::parse("https://cdn.example.com/hls/").unwrap();

        let rewritten =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), true, true).unwrap();
        let output = String::from_utf8(rewritten).unwrap();

        assert!(output.contains("data:application/octet-stream;base64,AAAA"));
    }

    #[test]
    fn rewrite_errors_when_insecure_segments_disallowed() {
        let manifest = b"#EXTM3U\n#EXTINF:4.0,\nsegment.ts\n";
        let manifest_url = Url::parse("https://origin.example.com/vod/master.m3u8").unwrap();
        let base_url = Url::parse("http://cdn.example.com/hls/").unwrap();

        let error =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), true, false).unwrap_err();

        assert!(matches!(error, HlsError::InsecureOutput));
    }

    #[test]
    fn no_rewrite_when_disabled() {
        let manifest = b"#EXTM3U\n#EXTINF:4.0,\nsegment.ts\n";
        let manifest_url = Url::parse("https://origin.example.com/vod/master.m3u8").unwrap();
        let base_url = Url::parse("https://cdn.example.com/hls/").unwrap();

        let rewritten =
            rewrite_playlist(manifest, &manifest_url, Some(&base_url), false, true).unwrap();

        assert_eq!(rewritten, manifest);
    }
}
