//! Change-field dashboard: single-file HTML rendering of a governor run.
//! Agents on the left, touched artifacts in the middle, verdicts on the right.

pub struct Row {
    pub agent: String,
    pub change_id: String,
    pub verdict: String,      // ACCEPT | REJECT | BLOCKED
    pub badge_class: String,  // accept | reject | blocked
    pub detail: String,        // rule + reason
    pub conflicts: Vec<String>,
    pub seal: String,
    pub status: String,
    pub files: Vec<String>,
    pub invariants: Vec<String>,
}

pub struct Stats {
    pub agents: usize,
    pub changes: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub blocked: usize,
    pub sealed: usize,
}

pub fn render(task: &str, rows: &[Row], stats: &Stats, log: &str) -> String {
    let mut files: Vec<String> = vec![];
    let mut invs: Vec<String> = vec![];
    for r in rows {
        for f in &r.files {
            if !files.contains(f) {
                files.push(f.clone());
            }
        }
        for i in &r.invariants {
            if !invs.contains(i) {
                invs.push(i.clone());
            }
        }
    }

    // SVG layout: changes column x=20, artifacts column x=420, rows spaced 64px.
    let row_h = 64f32;
    let top = 30f32;
    let svg_h = top * 2.0 + row_h * rows.len().max(files.len() + invs.len()) as f32;
    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg width=\"760\" height=\"{}\" viewBox=\"0 0 760 {}\" xmlns=\"http://www.w3.org/2000/svg\">",
        svg_h as u32, svg_h as u32
    ));
    // artifact nodes
    let mut art_y: std::collections::HashMap<String, f32> = Default::default();
    let mut ay = top;
    for f in files.iter().chain(invs.iter()) {
        art_y.insert(f.clone(), ay + 16.0);
        let color = if f.starts_with("AUTH") || f.contains("auth.error") { "#f0a" } else { "#4af" };
        svg.push_str(&format!(
            "<rect x=\"420\" y=\"{}\" width=\"300\" height=\"32\" rx=\"6\" fill=\"#16161e\" stroke=\"{}\"/>",
            ay, color
        ));
        svg.push_str(&format!(
            "<text x=\"432\" y=\"{}\" fill=\"#e8e8f0\" font-size=\"12\" font-family=\"monospace\">{}</text>",
            ay + 20.0,
            esc(f)
        ));
        ay += row_h;
    }
    // change nodes + edges
    for (i, r) in rows.iter().enumerate() {
        let cy = top + i as f32 * row_h + 16.0;
        let (fill, stroke) = match r.badge_class.as_str() {
            "accept" => ("#0d2818", "#2ecc71"),
            "reject" => ("#2c0d0d", "#e74c3c"),
            _ => ("#2c230d", "#f39c12"),
        };
        svg.push_str(&format!(
            "<rect x=\"20\" y=\"{}\" width=\"220\" height=\"32\" rx=\"6\" fill=\"{}\" stroke=\"{}\"/>",
            top + i as f32 * row_h,
            fill,
            stroke
        ));
        svg.push_str(&format!(
            "<text x=\"32\" y=\"{}\" fill=\"#e8e8f0\" font-size=\"12\" font-family=\"monospace\">{} {}</text>",
            cy + 4.0,
            esc(&r.agent),
            esc(&r.verdict)
        ));
        for f in r.files.iter().chain(r.invariants.iter()) {
            if let Some(&ty) = art_y.get(f) {
                let dashed = if r.badge_class == "reject" { " stroke-dasharray=\"4,3\"" } else { "" };
                let ecol = if r.badge_class == "reject" { "#e74c3c" } else { "#555" };
                svg.push_str(&format!(
                    "<line x1=\"240\" y1=\"{}\" x2=\"420\" y2=\"{}\" stroke=\"{}\" stroke-width=\"1.5\"{}/>",
                    cy, ty, ecol, dashed
                ));
            }
        }
    }
    svg.push_str("</svg>");

    let mut table = String::new();
    for r in rows {
        let conf = if r.conflicts.is_empty() {
            "<span class=\"dim\">none</span>".to_string()
        } else {
            r.conflicts.iter().map(|c| format!("<div class=\"conf\">{}</div>", esc(c))).collect::<Vec<_>>().join("")
        };
        table.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td><span class=\"badge {}\">{}</span></td>\
             <td class=\"mono small\">{}</td><td>{}</td><td class=\"mono small\">{}</td><td class=\"mono small\">{}</td></tr>",
            esc(&r.change_id), r.badge_class, esc(&r.verdict),
            esc(&r.detail), conf, esc(&r.seal), esc(&r.status)
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>wreck — change field</title>
<style>
body {{ background:#0b0b10; color:#e8e8f0; font-family:system-ui,sans-serif; margin:0; padding:24px; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h1 .w {{ color:#2ecc71; }}
.sub {{ color:#888; margin-bottom:20px; }}
.cards {{ display:flex; gap:12px; margin-bottom:20px; flex-wrap:wrap; }}
.card {{ background:#14141c; border:1px solid #2a2a3a; border-radius:8px; padding:12px 18px; }}
.card .n {{ font-size:26px; font-weight:700; }} .card .l {{ color:#888; font-size:12px; }}
.badge {{ padding:3px 10px; border-radius:20px; font-size:12px; font-weight:700; }}
.badge.accept {{ background:#0d2818; color:#2ecc71; border:1px solid #2ecc71; }}
.badge.reject {{ background:#2c0d0d; color:#e74c3c; border:1px solid #e74c3c; }}
.badge.blocked {{ background:#2c230d; color:#f39c12; border:1px solid #f39c12; }}
table {{ width:100%; border-collapse:collapse; margin:20px 0; background:#101018; }}
th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #22222e; vertical-align:top; }}
th {{ color:#888; font-size:12px; text-transform:uppercase; }}
.mono {{ font-family:monospace; }} .small {{ font-size:12px; color:#aaa; }}
.dim {{ color:#555; }} .conf {{ font-size:12px; color:#e2a13d; margin:2px 0; }}
pre {{ background:#101018; padding:16px; border-radius:8px; font-size:12px; overflow-x:auto; }}
.panel {{ background:#101018; border:1px solid #2a2a3a; border-radius:8px; padding:16px; margin:20px 0; }}
.panel h2 {{ margin:0 0 12px; font-size:15px; }}
.zero {{ color:#2ecc71; font-weight:700; }}
</style></head><body>
<h1><span class="w">wreck</span> — change field</h1>
<div class="sub">task: {} · every verdict sealed in <span class="mono">lucidota-receipt/1</span>, hash-chained</div>
<div class="cards">
<div class="card"><div class="n">{}</div><div class="l">agents</div></div>
<div class="card"><div class="n">{}</div><div class="l">changes</div></div>
<div class="card"><div class="n" style="color:#2ecc71">{}</div><div class="l">accepted</div></div>
<div class="card"><div class="n" style="color:#e74c3c">{}</div><div class="l">rejected</div></div>
<div class="card"><div class="n" style="color:#f39c12">{}</div><div class="l">blocked</div></div>
<div class="card"><div class="n">{}</div><div class="l">decisions sealed</div></div>
<div class="card"><div class="n zero">0</div><div class="l">human merges</div></div>
</div>
<div class="panel"><h2>change graph — agents × artifacts</h2>{}</div>
<table><tr><th>change</th><th>verdict</th><th>reason</th><th>conflicts</th><th>seal</th><th>status</th></tr>{}</table>
<div class="panel"><h2>baseline git log</h2><pre>{}</pre></div>
<div class="sub">Don't merge agents. Merge proven state transitions.</div>
</body></html>"#,
        esc(task),
        stats.agents, stats.changes, stats.accepted, stats.rejected, stats.blocked, stats.sealed,
        svg, table, esc(log)
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
