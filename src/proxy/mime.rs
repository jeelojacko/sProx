use url::Url;

/// Guess a sensible content type based on the URL path.
///
/// The function inspects the last path segment of the provided [`Url`]
/// and returns a MIME type for a handful of known media extensions.
/// Unknown or unsupported extensions return `None` so callers can keep
/// the upstream value.
pub fn guess_content_type(url: &Url) -> Option<&'static str> {
    let filename = url
        .path_segments()
        .and_then(|segments| segments.rev().find(|segment| !segment.is_empty()))?;

    let extension = filename
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or("")
        .trim();

    if extension.is_empty() {
        return None;
    }

    match extension.to_ascii_lowercase().as_str() {
        "mp4" | "m4v" => Some("video/mp4"),
        "m4a" => Some("audio/mp4"),
        "mkv" => Some("video/x-matroska"),
        "webm" => Some("video/webm"),
        "mov" => Some("video/quicktime"),
        "mp3" => Some("audio/mpeg"),
        "aac" => Some("audio/aac"),
        "flac" => Some("audio/flac"),
        "wav" => Some("audio/wav"),
        "m3u8" => Some("application/vnd.apple.mpegurl"),
        "ts" => Some("video/mp2t"),
        _ => None,
    }
}

/// Sanitize a filename provided by untrusted input.
///
/// The sanitizer keeps alphanumeric characters, dots and a small set of
/// safe punctuation marks while collapsing any whitespace into
/// underscores. Control characters and potentially dangerous characters
/// such as path separators are removed. The resulting filename is capped
/// to 255 characters, matching typical filesystem limits.
pub fn sanitize_filename(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut sanitized = String::with_capacity(trimmed.len());
    let mut last_was_underscore = false;
    let mut last_was_dot = false;
    let mut has_stem = false;

    for ch in trimmed.chars() {
        let replacement = match ch {
            c if c.is_ascii_alphanumeric() => Some(c),
            '.' => {
                if has_stem && !last_was_dot {
                    Some('.')
                } else {
                    None
                }
            }
            '-' | '_' | '(' | ')' => Some(ch),
            c if c.is_ascii_whitespace() => Some('_'),
            c if c.is_ascii() && !c.is_ascii_control() => Some('_'),
            _ => None,
        };

        if let Some(rep) = replacement {
            if rep == '_' {
                if last_was_underscore {
                    continue;
                }
                last_was_underscore = true;
                last_was_dot = false;
            } else {
                last_was_underscore = false;
                last_was_dot = rep == '.';
            }

            if rep.is_ascii_alphanumeric() {
                has_stem = true;
            }
            sanitized.push(rep);
        }
    }

    let sanitized = sanitized.trim_matches(|c| c == '_' || c == '.');
    if sanitized.is_empty() {
        return None;
    }

    let mut sanitized = sanitized.to_string();
    if let Some((stem, extension)) = sanitized.rsplit_once('.') {
        let trimmed_stem = stem.trim_end_matches('_');
        if trimmed_stem.is_empty() {
            sanitized = extension.trim_matches('_').to_string();
        } else if trimmed_stem.len() != stem.len() {
            sanitized = if extension.is_empty() {
                trimmed_stem.to_string()
            } else {
                format!("{}.{}", trimmed_stem, extension)
            };
        }
    } else {
        let trimmed = sanitized.trim_end_matches('_');
        if trimmed.len() != sanitized.len() {
            sanitized = trimmed.to_string();
        }
    }

    if sanitized.len() > 255 {
        sanitized.truncate(255);
    }

    Some(sanitized)
}

#[cfg(test)]
mod tests {
    use super::{guess_content_type, sanitize_filename};
    use url::Url;

    #[test]
    fn guess_content_type_recognises_common_media_types() {
        let mp4 = Url::parse("https://example.com/video/file.mp4").unwrap();
        assert_eq!(guess_content_type(&mp4), Some("video/mp4"));

        let mkv = Url::parse("https://example.com/movie/final.mkv").unwrap();
        assert_eq!(guess_content_type(&mkv), Some("video/x-matroska"));

        let none = Url::parse("https://example.com/archive").unwrap();
        assert_eq!(guess_content_type(&none), None);
    }

    #[test]
    fn sanitize_filename_removes_dangerous_characters() {
        assert_eq!(
            sanitize_filename("../../secret.mp4"),
            Some("secret.mp4".into())
        );
        assert_eq!(
            sanitize_filename("my cool video!!.mp4"),
            Some("my_cool_video.mp4".into())
        );
        assert!(sanitize_filename("    \t ").is_none());
    }
}
