use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use crate::AppState;

// ── REPEATS ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TextRequest {
    pub text: String,
}

#[derive(Serialize)]
pub struct RepeatEntry {
    pub phrase: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct RepeatsResponse {
    pub ok: bool,
    pub repeats: Vec<RepeatEntry>,
}

pub async fn repeats_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<TextRequest>,
) -> Json<RepeatsResponse> {
    let text = req.text.to_lowercase();
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '\'' { c } else { ' ' })
        .collect();

    let words: Vec<&str> = cleaned.split_whitespace().collect();
    let mut counts: HashMap<String, usize> = HashMap::new();

    for len in 2..=10usize {
        if words.len() < len {
            break;
        }
        for i in 0..=(words.len() - len) {
            let phrase = words[i..i + len].join(" ");
            *counts.entry(phrase).or_insert(0) += 1;
        }
    }

    let mut dupes: Vec<(String, usize)> = counts
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .collect();

    // Sort by length descending to filter redundant subphrases
    dupes.sort_by(|a, b| b.0.split_whitespace().count().cmp(&a.0.split_whitespace().count()));

    let mut filtered: Vec<(String, usize)> = Vec::new();
    for (phrase, count) in &dupes {
        let redundant = dupes.iter().any(|(p2, c2)| {
            p2 != phrase && p2.contains(phrase.as_str()) && c2 == count
        });
        if !redundant {
            filtered.push((phrase.clone(), *count));
        }
    }

    filtered.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.len().cmp(&a.0.len())));

    let repeats = filtered
        .into_iter()
        .map(|(phrase, count)| RepeatEntry { phrase, count })
        .collect();

    Json(RepeatsResponse { ok: true, repeats })
}

// ── SYMBOLS ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AnomalyEntry {
    pub word: String,
    pub highlighted: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct SymbolsResponse {
    pub ok: bool,
    pub anomalies: Vec<AnomalyEntry>,
}

pub async fn symbols_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<TextRequest>,
) -> Json<SymbolsResponse> {
    let mut anomalies = Vec::new();

    for word in req.text.split_whitespace() {
        if word.is_empty() {
            continue;
        }

        let has_cyr = word.chars().any(|c| matches!(c, 'а'..='я' | 'А'..='Я' | 'ё' | 'Ё'));
        let has_lat = word.chars().any(|c| c.is_ascii_alphabetic());
        let has_special = word.chars().any(|c| {
            !c.is_alphanumeric()
                && !matches!(c, '.' | ',' | '!' | '?' | ':' | ';' | '(' | ')' | '-' | '\'' | '"')
        });

        if (has_cyr && has_lat) || has_special {
            let mut count = 0usize;
            let mut highlighted = String::new();

            for ch in word.chars() {
                let is_anomaly = if has_cyr {
                    ch.is_ascii_alphabetic()
                } else {
                    !ch.is_alphanumeric()
                        && !matches!(ch, '.' | ',' | '!' | '?' | ':' | ';' | '(' | ')' | '-')
                };
                if is_anomaly {
                    count += 1;
                    highlighted.push_str(&format!("<span>{}</span>", escape_html(&ch.to_string())));
                } else {
                    highlighted.push_str(&escape_html(&ch.to_string()));
                }
            }

            if count > 0 {
                anomalies.push(AnomalyEntry {
                    word: word.to_string(),
                    highlighted,
                    count,
                });
            }
        }
    }

    Json(SymbolsResponse { ok: true, anomalies })
}

// ── COMPARE ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CompareRequest {
    pub text_a: String,
    pub text_b: String,
}

#[derive(Serialize)]
pub struct CompareResponse {
    pub ok: bool,
    pub similarity: u32,
    pub uniqueness: u32,
}

pub async fn compare_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CompareRequest>,
) -> Json<CompareResponse> {
    let s1 = req.text_a.to_lowercase();
    let s2 = req.text_b.to_lowercase();

    fn bigrams(s: &str) -> std::collections::HashSet<String> {
        let chars: Vec<char> = s.chars().collect();
        chars.windows(2).map(|w| w.iter().collect()).collect()
    }

    let b1 = bigrams(&s1);
    let b2 = bigrams(&s2);

    if b1.is_empty() || b2.is_empty() {
        return Json(CompareResponse { ok: true, similarity: 0, uniqueness: 100 });
    }

    let intersect = b1.intersection(&b2).count();
    let score = ((2 * intersect * 100) / (b1.len() + b2.len())) as u32;
    let score = score.min(100);

    Json(CompareResponse {
        ok: true,
        similarity: score,
        uniqueness: 100 - score,
    })
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#039;")
}
