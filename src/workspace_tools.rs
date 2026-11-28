use crate::telemetry::Problem;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
const MAX_ENTRIES: usize = 100_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILE: u64 = 32 * 1024 * 1024;
#[derive(Default, serde::Serialize)]
pub struct Search {
    pub hits: Vec<Problem>,
    pub skipped: usize,
    pub truncated: bool,
}
#[derive(serde::Serialize)]
pub struct Node {
    pub key: String,
    pub name: String,
    pub location: Problem,
}
#[derive(Default, serde::Serialize)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<(usize, usize)>,
    pub truncated: bool,
}
fn safe(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.to_string_lossy().contains([':', '\0'])
        && path.components().all(|p| matches!(p, Component::Normal(_)))
}
fn files(root: &Path, cancel: &AtomicBool) -> Result<Vec<PathBuf>, String> {
    let mut queue = vec![root.to_path_buf()];
    let mut result = Vec::new();
    let mut visited = 0;
    while let Some(dir) = queue.pop() {
        for item in fs::read_dir(dir).map_err(|e| e.to_string())? {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let item = item.map_err(|e| e.to_string())?;
            visited += 1;
            if visited > MAX_ENTRIES {
                return Err("workspace entry limit reached".into());
            }
            let kind = item.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                queue.push(item.path());
            } else if kind.is_file() {
                result.push(item.path());
            }
        }
    }
    result.sort();
    Ok(result)
}
pub fn search(
    root: &Path,
    query: &str,
    edited: &[(PathBuf, String)],
    cancel: &AtomicBool,
) -> Result<Search, String> {
    if query.is_empty() || query.len() > 1024 {
        return Err("search query must contain 1..1024 bytes".into());
    }
    let mut result = Search::default();
    let mut budget = 0u64;
    let needle = query.to_lowercase();
    let source = root.join("source");
    for path in files(&source, cancel)? {
        let extension = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        if ![
            "py", "c", "cpp", "h", "hpp", "cs", "java", "js", "ts", "jsx", "tsx", "json", "xml",
            "smali", "rs", "txt", "html", "css",
        ]
        .contains(&extension.as_str())
        {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_path_buf();
        let edited = edited.iter().find(|(p, _)| *p == path);
        let bytes = if let Some((_, text)) = edited {
            text.as_bytes().to_vec()
        } else {
            if fs::metadata(&path).map_err(|e| e.to_string())?.len() > MAX_FILE {
                result.skipped += 1;
                continue;
            }
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .map_err(|e| e.to_string())?
                .take(MAX_FILE + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_FILE {
                result.skipped += 1;
                continue;
            }
            bytes
        };
        budget += bytes.len() as u64;
        if budget > MAX_BYTES {
            result.truncated = true;
            break;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            result.skipped += 1;
            continue;
        };
        for (line, text) in text.lines().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            if text.to_lowercase().contains(&needle) {
                result.hits.push(Problem {
                    file: relative.clone(),
                    line: line + 1,
                    symbol: String::new(),
                    message: text.chars().take(240).collect(),
                });
                if result.hits.len() >= 2000 {
                    result.truncated = true;
                    return Ok(result);
                }
            }
        }
    }
    Ok(result)
}
pub fn graph(root: &Path, cancel: &AtomicBool) -> Result<Graph, String> {
    let mut graph = Graph::default();
    let mut keys = BTreeMap::new();
    let mut pending = Vec::new();
    let mut bytes = 0u64;
    for path in files(root, cancel)? {
        if path
            .file_name()
            .is_none_or(|name| name != "native-report.json")
        {
            continue;
        }
        let length = fs::metadata(&path).map_err(|e| e.to_string())?.len();
        bytes += length;
        if length > MAX_FILE || bytes > MAX_BYTES {
            graph.truncated = true;
            continue;
        }
        let mut raw = Vec::new();
        fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(MAX_FILE + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() as u64 > MAX_FILE {
            return Err("graph report grew beyond limit".into());
        }
        let report: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let parent = path
            .parent()
            .unwrap()
            .strip_prefix(root)
            .map_err(|e| e.to_string())?;
        let source = PathBuf::from(
            report["source_file"]
                .as_str()
                .unwrap_or("source/native_function_index.c"),
        );
        if !safe(&source) {
            return Err("unsafe graph source path".into());
        }
        for function in report["functions"].as_array().into_iter().flatten() {
            if graph.nodes.len() >= 6000 {
                graph.truncated = true;
                break;
            }
            let Some(address) = function["address"].as_str() else {
                continue;
            };
            let key = format!("{}@{}", parent.display(), address.to_ascii_lowercase());
            if keys.contains_key(&key) {
                continue;
            }
            let name = function["name"].as_str().unwrap_or(address).to_string();
            keys.insert(key.clone(), graph.nodes.len());
            graph.nodes.push(Node {
                key,
                name: name.clone(),
                location: Problem {
                    file: parent.join(&source),
                    line: function["line"].as_u64().unwrap_or(1) as usize,
                    symbol: name,
                    message: "static call graph".into(),
                },
            });
        }
        graph.truncated |= report["xref_analysis"]["truncated"].as_bool() == Some(true);
        for edge in report["call_xrefs"]
            .as_array()
            .into_iter()
            .flatten()
            .take(65536)
        {
            if pending.len() >= 65536 {
                graph.truncated = true;
                break;
            }
            if let (Some(from), Some(to)) = (
                edge["from_address"].as_str(),
                edge["target_address"].as_str(),
            ) {
                pending.push((
                    format!("{}@{}", parent.display(), from.to_ascii_lowercase()),
                    format!("{}@{}", parent.display(), to.to_ascii_lowercase()),
                ));
            }
        }
    }
    let mut edges = BTreeSet::new();
    for (from, to) in pending {
        if let (Some(&from), Some(&to)) = (keys.get(&from), keys.get(&to)) {
            edges.insert((from, to));
        }
    }
    graph.edges = edges.into_iter().collect();
    Ok(graph)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unified_search_reads_multiple_languages_and_unsaved_edits() {
        let root = std::env::temp_dir().join(format!("uie-search-{}", std::process::id()));
        fs::create_dir_all(root.join("source/java")).unwrap();
        let py = root.join("source/a.py");
        fs::write(&py, "old\n").unwrap();
        fs::write(
            root.join("source/java/Hi.java"),
            "class Hi { // Привет\n}\n",
        )
        .unwrap();
        let value = search(
            &root,
            "привет",
            &[(py, "# привет unsaved\n".into())],
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(value.hits.len(), 2);
        assert_eq!(value.hits[0].line, 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn call_graph_keeps_modules_separate_and_deduplicates_edges() {
        let root = std::env::temp_dir().join(format!("uie-graph-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("native-report.json"),r#"{"source_file":"source/code.c","functions":[{"address":"1000","name":"start","line":2},{"address":"2000","name":"helper","line":8}],"call_xrefs":[{"from_address":"1000","target_address":"2000"},{"from_address":"1000","target_address":"2000"}]}"#).unwrap();
        let value = graph(&root, &AtomicBool::new(false)).unwrap();
        assert_eq!(value.nodes.len(), 2);
        assert_eq!(value.edges, vec![(0, 1)]);
        assert_eq!(value.nodes[1].location.line, 8);
        fs::remove_dir_all(root).unwrap();
    }
}
