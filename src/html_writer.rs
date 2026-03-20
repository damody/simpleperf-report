use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;

use crate::record_data::RecordInfo;

const REPORT_HTML_JS: &str = include_str!("../assets/report_html.js");

const URLS: &[(&str, &str, &str)] = &[
    // (kind, key, url)
    (
        "css",
        "bootstrap4-css",
        "https://stackpath.bootstrapcdn.com/bootstrap/4.1.2/css/bootstrap.min.css",
    ),
    (
        "css",
        "dataTable-css",
        "https://cdn.datatables.net/1.10.19/css/dataTables.bootstrap4.min.css",
    ),
    (
        "js",
        "jquery",
        "https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js",
    ),
    (
        "js",
        "bootstrap4-popper",
        "https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js",
    ),
    (
        "js",
        "bootstrap4",
        "https://stackpath.bootstrapcdn.com/bootstrap/4.1.2/js/bootstrap.min.js",
    ),
    (
        "js",
        "dataTable",
        "https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js",
    ),
    (
        "js",
        "dataTable-bootstrap4",
        "https://cdn.datatables.net/1.10.19/js/dataTables.bootstrap4.min.js",
    ),
    (
        "js",
        "gstatic-charts",
        "https://www.gstatic.com/charts/loader.js",
    ),
];

const INLINE_CSS: &str = r#"
.colForLine { width: 50px; text-align: right; }
.colForCount { width: 100px; text-align: right; }
.tableCell { font-size: 17px; }
.boldTableCell { font-weight: bold; font-size: 17px; }
.textRight { text-align: right; }
"#;

pub fn write_html(output_path: &Path, record_info: &RecordInfo) -> Result<()> {
    let file = std::fs::File::create(output_path)?;
    let mut w = BufWriter::new(file);

    write!(w, "<html><head>")?;

    // CSS links
    for &(kind, _key, url) in URLS {
        if kind == "css" {
            write!(
                w,
                r#"<link rel="stylesheet" type="text/css" href="{}">"#,
                url
            )?;
        }
    }

    // JS scripts (CDN)
    for &(kind, _key, url) in URLS {
        if kind == "js" {
            write!(w, r#"<script src="{}"></script>"#, url)?;
        }
    }

    // Google Charts init
    write!(
        w,
        r#"<script>google.charts.load('current', {{'packages': ['corechart', 'table']}});</script>"#
    )?;

    // Inline CSS
    write!(w, r#"<style type="text/css">{}</style>"#, INLINE_CSS)?;

    write!(w, "</head><body>")?;

    // Inline JS (report_html.js)
    write!(w, "<script>")?;
    w.write_all(REPORT_HTML_JS.as_bytes())?;
    write!(w, "</script>")?;

    // Content div
    write!(w, r#"<div id="report_content"></div>"#)?;

    // Record data JSON
    write!(w, r#"<script id="record_data" type="application/json">"#)?;
    serde_json::to_writer(&mut w, record_info)?;
    write!(w, "</script>")?;

    write!(w, "</body></html>")?;
    w.flush()?;

    Ok(())
}
