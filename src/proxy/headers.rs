use std::collections::HashSet;

use url::Url;

/// Builds a set of candidate `Referer` values derived from the redirect chain
/// followed while issuing a request. The returned list is ordered from most
/// specific to least specific and contains at most three entries.
pub fn candidate_referers(chain: &[Url]) -> Vec<String> {
    if chain.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    if chain.len() >= 2 {
        let previous = &chain[chain.len() - 2];
        push_unique(&mut candidates, &mut seen, previous.as_str().to_string());
        push_unique(
            &mut candidates,
            &mut seen,
            previous.origin().ascii_serialization(),
        );
    }

    if let Some(initial) = chain.first() {
        push_unique(
            &mut candidates,
            &mut seen,
            initial.origin().ascii_serialization(),
        );
    }

    candidates.truncate(3);
    candidates
}

fn push_unique(values: &mut Vec<String>, seen: &mut HashSet<String>, candidate: String) {
    if seen.insert(candidate.clone()) {
        values.push(candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_referers_from_single_hop() {
        let url = Url::parse("https://example.com/path").unwrap();
        let candidates = candidate_referers(&[url.clone()]);
        assert_eq!(candidates, vec!["https://example.com".to_string()]);
    }

    #[test]
    fn candidate_referers_include_previous_hop() {
        let chain = vec![
            Url::parse("https://origin.example.com/start").unwrap(),
            Url::parse("https://edge.example.com/hop").unwrap(),
            Url::parse("https://edge.example.com/final").unwrap(),
        ];

        let candidates = candidate_referers(&chain);
        assert_eq!(
            candidates,
            vec![
                "https://edge.example.com/hop".to_string(),
                "https://edge.example.com".to_string(),
                "https://origin.example.com".to_string(),
            ]
        );
    }
}
