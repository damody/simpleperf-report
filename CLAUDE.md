# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

simpleperf-report 是一個 Rust CLI 工具，用於將 Android `perf.data` 效能分析檔案轉換為互動式 HTML flamegraph 報告。它透過 FFI 動態載入 `libsimpleperf_report.dll`（C++ 原生函式庫）來解析 perf 記錄，建構呼叫圖（call graph）與反向呼叫圖，最終生成內嵌 JSON 資料的自包含 HTML 報告。

此工具為 MProfiler 效能分析套件的報告生成組件。

## Build Commands

```bash
# 編譯（debug）
cargo build

# 編譯（release，啟用 LTO）
cargo build --release

# 執行
cargo run --release -- -i perf.data -o report.html

# 檢查編譯
cargo check

# Lint
cargo clippy

# 格式化
cargo fmt

# 測試（目前無測試）
cargo test
```

## Runtime Dependency

執行時需要 `libsimpleperf_report.dll`（Windows x86_64），DLL 搜尋順序：
1. `{exe_dir}/bin/windows/x86_64/`
2. `{exe_dir}/`
3. `{cwd}/bin/windows/x86_64/`
4. `{cwd}/`（fallback）

## Architecture

```
main.rs          CLI 進入點、DLL 搜尋、流程控制
    │
    ├─→ ffi/
    │   ├─ types.rs      C-compatible #[repr(C)] 結構定義（對應 DLL 介面）
    │   └─ bindings.rs   ReportLib：安全包裝 15 個 DLL 函式，libloading 動態載入
    │
    ├─→ record_data.rs   核心邏輯：逐 sample 迭代、建構階層、聚合、過濾、JSON 輸出
    │
    ├─→ model/
    │   ├─ event_scope.rs  EventScope → ProcessScope → ThreadScope 階層
    │   ├─ call_node.rs    CallNode 呼叫圖樹節點（forward + reverse）
    │   ├─ lib_scope.rs    LibScope / FunctionScope（per-library/per-function）
    │   └─ sets.rs         LibSet / FunctionSet 集合（id ↔ name 映射）
    │
    └─→ html_writer.rs    生成自包含 HTML（內嵌 Bootstrap/jQuery/DataTables CDN + report_html.js + JSON 資料）

assets/report_html.js    客戶端 JS，解析內嵌 JSON 並渲染互動式報告 UI
```

### 資料流

1. **載入**：每個 perf.data 檔案建立一個 `ReportLib` 實例，逐 sample 迭代
2. **建構**：每個 sample 歸入 EventScope → ProcessScope → ThreadScope → LibScope 階層，同時建構 call graph 和 reverse call graph 的 `CallNode` 樹
3. **後處理**：遞迴計算 subtree event count、百分比過濾（`limit_percents`）、可選的 thread name 聚合
4. **輸出**：序列化為 JSON（`gen_record_info`），嵌入 HTML 模板（`write_html`）

### 重要模式

- **IndexMap 保序**：所有 children/libs 使用 `IndexMap` 而非 `HashMap`，保留插入順序以確保報告一致性
- **FFI 安全封裝**：所有 unsafe C 呼叫封裝在 `ReportLib` 方法中，`Drop` 自動釋放資源
- **Callstack 上限**：`MAX_CALLSTACK_LENGTH = 750`，防止異常深堆疊
- **遞迴去重**：callstack 處理時跳過單次出現的遞迴呼叫，避免重複計數
- **HTML 跳脫**：`modify_text_for_html()` 替換 `<` / `>` 防止 XSS
- **Serde 命名**：JSON 輸出使用 camelCase（`#[serde(rename_all = "camelCase")]`）
