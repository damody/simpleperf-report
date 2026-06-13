# simpleperf-report

`simpleperf-report` 是 MProfiler 的報告產生器。既有模式可讀 Android `perf.data`；`source` subcommand 可讀 `realtime_profile` 產生的 source profile bundle，輸出 source-line HTML/XLSX/JSON/CSV 報告。

## Source Profile Bundle

```powershell
cargo run --release -- source `
  --bundle D:\path\to\bundle `
  --elf D:\path\to\unstripped.so `
  --source-root D:\path\to\source `
  --path-remap /android/build/path=D:\path\to\source `
  --out D:\path\to\reports `
  --html --xlsx --json --csv --no-browser
```

輸出：

- `SourceLine.html`
- `SourceLine.xlsx`
- `SourceLine.json`
- `csv\AllLines.csv`
- `csv\SampledLines.csv`
- `csv\Files.csv`
- `csv\Functions.csv`

`--elf`、`--source-root`、`--path-remap` 可重複指定。這些參數會和 bundle manifest 內的 hints 合併使用。

## 驗證

```powershell
cargo test
powershell -ExecutionPolicy Bypass -File D:\MProfiler\scripts\validate-source-profile.ps1
```
