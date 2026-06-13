#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;

use super::schema::{
    SourceProfileBuildIds, SourceProfileCapability, SourceProfileEventCatalog,
    SourceProfileEventRuns, SourceProfileLoss, SourceProfileManifest, SourceProfileMaps,
    SourceProfileMetricCatalog, SourceProfileThreads,
};

#[derive(Debug)]
pub struct SourceProfileBundle {
    pub root: PathBuf,
    pub manifest: SourceProfileManifest,
    pub capability: SourceProfileCapability,
    pub maps: SourceProfileMaps,
    pub threads: SourceProfileThreads,
    pub build_ids: SourceProfileBuildIds,
    pub loss: SourceProfileLoss,
    pub event_catalog: SourceProfileEventCatalog,
    pub metric_catalog: SourceProfileMetricCatalog,
    pub event_runs: SourceProfileEventRuns,
    pub pmu_samples_path: Option<PathBuf>,
    pub spe_samples_path: Option<PathBuf>,
}

impl SourceProfileBundle {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.exists() {
            bail!("Source profile bundle '{}' does not exist", root.display());
        }
        if !root.is_dir() {
            bail!(
                "Source profile bundle '{}' is not a directory",
                root.display()
            );
        }

        let manifest: SourceProfileManifest = load_json(&root, "manifest.json")?;
        validate_schema(&manifest)?;

        let bundle = Self {
            capability: load_json(&root, "capability.json")?,
            maps: load_json(&root, "maps.json")?,
            threads: load_json(&root, "threads.json")?,
            build_ids: load_json(&root, "build_ids.json")?,
            loss: load_json(&root, "loss.json")?,
            event_catalog: load_json(&root, "event_catalog.json")?,
            metric_catalog: load_json(&root, "metric_catalog.json")?,
            event_runs: load_json(&root, "event_runs.json")?,
            pmu_samples_path: existing_file(&root, "pmu_samples.bin"),
            spe_samples_path: existing_file(&root, "spe_samples.bin"),
            root,
            manifest,
        };
        bundle.validate_stream_presence()?;
        Ok(bundle)
    }

    fn validate_stream_presence(&self) -> Result<()> {
        if self.manifest.lanes.pmu.enabled
            && self.manifest.lanes.pmu.available
            && self.pmu_samples_path.is_none()
        {
            bail!(
                "Bundle '{}' declares PMU lane enabled and available but pmu_samples.bin is missing",
                self.root.display()
            );
        }
        if self.manifest.lanes.spe.enabled
            && self.manifest.lanes.spe.available
            && self.spe_samples_path.is_none()
        {
            bail!(
                "Bundle '{}' declares SPE lane enabled and available but spe_samples.bin is missing",
                self.root.display()
            );
        }
        Ok(())
    }
}

fn load_json<T: DeserializeOwned>(root: &Path, relative_path: &str) -> Result<T> {
    let path = root.join(relative_path);
    if !path.exists() {
        bail!(
            "Source profile bundle '{}' is missing {}",
            root.display(),
            relative_path
        );
    }
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Failed to parse '{}'", path.display()))
}

fn existing_file(root: &Path, relative_path: &str) -> Option<PathBuf> {
    let path = root.join(relative_path);
    path.is_file().then_some(path)
}

fn validate_schema(manifest: &SourceProfileManifest) -> Result<()> {
    if manifest.schema.name != "mprofiler.source_profile_bundle" {
        bail!(
            "Unsupported source profile schema '{}'",
            manifest.schema.name
        );
    }
    if manifest.schema.version.major != 1 {
        bail!(
            "Unsupported source profile schema major version {}",
            manifest.schema.version.major
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_fixture_bundles() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("source_profile");
        for fixture in [
            "minimal",
            "cache",
            "stall",
            "missing",
            "unresolved",
            "loss",
            "arpg4_like",
        ] {
            SourceProfileBundle::load(root.join(fixture)).unwrap();
        }
    }
}
