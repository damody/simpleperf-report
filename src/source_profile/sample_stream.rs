#![allow(dead_code)]

use std::fs;
use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone)]
pub struct SampleStreamHeader {
    pub stream_kind: u16,
    pub version_major: u16,
    pub version_minor: u16,
    pub record_count: u64,
    pub first_timestamp_ns: u64,
    pub last_timestamp_ns: u64,
}

#[derive(Debug, Clone)]
pub struct PmuSample {
    pub flags: u32,
    pub event_run_ref: u32,
    pub event_key_ref: u32,
    pub sample_kind: u16,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub mapping_id: u64,
    pub timestamp_ns: u64,
    pub ip: u64,
    pub period_or_weight: u64,
    pub callchain_ips: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct SpeSample {
    pub flags: u32,
    pub event_run_ref: u32,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub mapping_id: u64,
    pub timestamp_ns: u64,
    pub pc: u64,
    pub latency_cycles: Option<u32>,
    pub operation_flags: u32,
    pub event_flags: u64,
    pub cache_level: u8,
    pub cache_result: u8,
    pub branch_result: u8,
    pub data_source: u16,
    pub decode_status: u16,
    pub raw_packet_offset: u64,
}

pub fn read_pmu_samples(path: &Path) -> Result<(SampleStreamHeader, Vec<PmuSample>)> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
    let mut cursor = Cursor::new(bytes);
    let header = read_header(&mut cursor)?;
    if header.stream_kind != 1 {
        bail!(
            "Sample stream '{}' has kind {}, expected PMU kind 1",
            path.display(),
            header.stream_kind
        );
    }

    let mut samples = Vec::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        samples.push(read_pmu_record(&mut cursor)?);
    }
    Ok((header, samples))
}

pub fn for_each_pmu_sample(
    path: &Path,
    mut visit: impl FnMut(PmuSample) -> Result<()>,
) -> Result<SampleStreamHeader> {
    let file = File::open(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
    let mut reader = BufReader::new(file);
    let header = read_header_from_reader(&mut reader)?;
    if header.stream_kind != 1 {
        bail!(
            "Sample stream '{}' has kind {}, expected PMU kind 1",
            path.display(),
            header.stream_kind
        );
    }

    for _ in 0..header.record_count {
        let record_type = read_u16(&mut reader)?;
        let record_size = read_u16(&mut reader)?;
        if record_size < 4 {
            bail!("Invalid PMU record size {}", record_size);
        }
        let mut bytes = Vec::with_capacity(record_size as usize);
        bytes.extend_from_slice(&record_type.to_le_bytes());
        bytes.extend_from_slice(&record_size.to_le_bytes());
        let rest_size = usize::from(record_size - 4);
        bytes.resize(record_size as usize, 0);
        reader.read_exact(&mut bytes[4..4 + rest_size])?;
        let mut cursor = Cursor::new(bytes);
        visit(read_pmu_record(&mut cursor)?)?;
    }
    Ok(header)
}

pub fn read_spe_samples(path: &Path) -> Result<(SampleStreamHeader, Vec<SpeSample>)> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read '{}'", path.display()))?;
    read_spe_samples_from_bytes(bytes)
}

pub fn read_spe_samples_from_bytes(bytes: Vec<u8>) -> Result<(SampleStreamHeader, Vec<SpeSample>)> {
    let mut cursor = Cursor::new(bytes);
    let header = read_header(&mut cursor)?;
    if header.stream_kind != 2 {
        bail!(
            "Sample stream has kind {}, expected SPE kind 2",
            header.stream_kind
        );
    }

    let mut samples = Vec::new();
    while (cursor.position() as usize) < cursor.get_ref().len() {
        samples.push(read_spe_record(&mut cursor)?);
    }
    Ok((header, samples))
}

fn read_header(cursor: &mut Cursor<Vec<u8>>) -> Result<SampleStreamHeader> {
    let mut magic = [0_u8; 4];
    cursor.read_exact(&mut magic)?;
    if magic != [b'M', b'P', b'S', b'P'] {
        bail!("Invalid sample stream magic");
    }
    let stream_kind = read_u16(cursor)?;
    let version_major = read_u16(cursor)?;
    let version_minor = read_u16(cursor)?;
    let header_size = read_u16(cursor)?;
    let endian = read_u8(cursor)?;
    let timestamp_unit = read_u8(cursor)?;
    let _reserved = read_u16(cursor)?;
    let record_count = read_u64(cursor)?;
    let first_timestamp_ns = read_u64(cursor)?;
    let last_timestamp_ns = read_u64(cursor)?;

    if endian != 1 {
        bail!("Unsupported sample stream endian {}", endian);
    }
    if timestamp_unit != 1 {
        bail!(
            "Unsupported sample stream timestamp unit {}",
            timestamp_unit
        );
    }
    if header_size < 40 {
        bail!("Invalid sample stream header size {}", header_size);
    }
    cursor.set_position(header_size as u64);

    Ok(SampleStreamHeader {
        stream_kind,
        version_major,
        version_minor,
        record_count,
        first_timestamp_ns,
        last_timestamp_ns,
    })
}

fn read_header_from_reader(reader: &mut impl Read) -> Result<SampleStreamHeader> {
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != [b'M', b'P', b'S', b'P'] {
        bail!("Invalid sample stream magic");
    }
    let stream_kind = read_u16(reader)?;
    let version_major = read_u16(reader)?;
    let version_minor = read_u16(reader)?;
    let header_size = read_u16(reader)?;
    let endian = read_u8(reader)?;
    let timestamp_unit = read_u8(reader)?;
    let _reserved = read_u16(reader)?;
    let record_count = read_u64(reader)?;
    let first_timestamp_ns = read_u64(reader)?;
    let last_timestamp_ns = read_u64(reader)?;

    if endian != 1 {
        bail!("Unsupported sample stream endian {}", endian);
    }
    if timestamp_unit != 1 {
        bail!(
            "Unsupported sample stream timestamp unit {}",
            timestamp_unit
        );
    }
    if header_size < 40 {
        bail!("Invalid sample stream header size {}", header_size);
    }
    if header_size > 40 {
        let mut skipped = vec![0_u8; usize::from(header_size - 40)];
        reader.read_exact(&mut skipped)?;
    }

    Ok(SampleStreamHeader {
        stream_kind,
        version_major,
        version_minor,
        record_count,
        first_timestamp_ns,
        last_timestamp_ns,
    })
}

fn read_pmu_record(cursor: &mut Cursor<Vec<u8>>) -> Result<PmuSample> {
    let start = cursor.position();
    let record_type = read_u16(cursor)?;
    let record_size = read_u16(cursor)?;
    if record_type != 1 {
        cursor.set_position(start + u64::from(record_size));
        bail!("Unsupported PMU record type {}", record_type);
    }
    let flags = read_u32(cursor)?;
    let event_run_ref = read_u32(cursor)?;
    let event_key_ref = read_u32(cursor)?;
    let sample_kind = read_u16(cursor)?;
    let _reserved = read_u16(cursor)?;
    let pid = read_u32(cursor)?;
    let tid = read_u32(cursor)?;
    let cpu = read_u32(cursor)?;
    let mapping_id = read_u64(cursor)?;
    let timestamp_ns = read_u64(cursor)?;
    let ip = read_u64(cursor)?;
    let period_or_weight = read_u64(cursor)?;
    let callchain_count = read_u16(cursor)?;
    let mut callchain_ips = Vec::with_capacity(callchain_count as usize);
    for _ in 0..callchain_count {
        callchain_ips.push(read_u64(cursor)?);
    }
    cursor.set_position(start + u64::from(record_size));
    Ok(PmuSample {
        flags,
        event_run_ref,
        event_key_ref,
        sample_kind,
        pid,
        tid,
        cpu,
        mapping_id,
        timestamp_ns,
        ip,
        period_or_weight,
        callchain_ips,
    })
}

fn read_spe_record(cursor: &mut Cursor<Vec<u8>>) -> Result<SpeSample> {
    let start = cursor.position();
    let record_type = read_u16(cursor)?;
    let record_size = read_u16(cursor)?;
    if record_type != 2 {
        cursor.set_position(start + u64::from(record_size));
        bail!("Unsupported SPE record type {}", record_type);
    }
    let flags = read_u32(cursor)?;
    let event_run_ref = read_u32(cursor)?;
    let pid = read_u32(cursor)?;
    let tid = read_u32(cursor)?;
    let cpu = read_u32(cursor)?;
    let mapping_id = read_u64(cursor)?;
    let timestamp_ns = read_u64(cursor)?;
    let pc = read_u64(cursor)?;
    let raw_latency_cycles = read_u32(cursor)?;
    let operation_flags = read_u32(cursor)?;
    let event_flags = read_u64(cursor)?;
    let cache_level = read_u8(cursor)?;
    let cache_result = read_u8(cursor)?;
    let branch_result = read_u8(cursor)?;
    let data_source = read_u16(cursor)?;
    let decode_status = read_u16(cursor)?;
    let raw_packet_offset = read_u64(cursor)?;
    cursor.set_position(start + u64::from(record_size));

    Ok(SpeSample {
        flags,
        event_run_ref,
        pid,
        tid,
        cpu,
        mapping_id,
        timestamp_ns,
        pc,
        latency_cycles: (raw_latency_cycles != u32::MAX).then_some(raw_latency_cycles),
        operation_flags,
        event_flags,
        cache_level,
        cache_result,
        branch_result,
        data_source,
        decode_status,
        raw_packet_offset,
    })
}

fn read_u8(reader: &mut impl Read) -> Result<u8> {
    let mut bytes = [0_u8; 1];
    reader.read_exact(&mut bytes)?;
    Ok(bytes[0])
}

fn read_u16(reader: &mut impl Read) -> Result<u16> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_minimal_pmu_samples() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/source_profile/minimal/pmu_samples.bin");
        let (header, samples) = read_pmu_samples(&path).unwrap();
        assert_eq!(header.stream_kind, 1);
        assert_eq!(header.record_count, 5);
        assert_eq!(samples.len(), 5);
        assert_eq!(samples[0].event_key_ref, 0);
        assert_eq!(samples[0].period_or_weight, 1000);
        assert_eq!(samples[0].callchain_ips.len(), 1);
    }

    #[test]
    fn streams_minimal_pmu_samples_without_loading_vec() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/source_profile/minimal/pmu_samples.bin");
        let mut count = 0;
        let header = for_each_pmu_sample(&path, |sample| {
            if count == 0 {
                assert_eq!(sample.event_key_ref, 0);
                assert_eq!(sample.period_or_weight, 1000);
            }
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(header.record_count, 5);
        assert_eq!(count, 5);
    }

    #[test]
    fn reads_spe_samples_from_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MPSP");
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&40_u16.to_le_bytes());
        bytes.push(1);
        bytes.push(1);
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&100_u64.to_le_bytes());
        bytes.extend_from_slice(&200_u64.to_le_bytes());

        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&79_u16.to_le_bytes());
        bytes.extend_from_slice(&31_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&4242_u32.to_le_bytes());
        bytes.extend_from_slice(&4242_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&100_u64.to_le_bytes());
        bytes.extend_from_slice(&0x4000_0000_4684_u64.to_le_bytes());
        bytes.extend_from_slice(&42_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u64.to_le_bytes());
        bytes.push(1);
        bytes.push(1);
        bytes.push(2);
        bytes.extend_from_slice(&7_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());

        let (header, samples) = read_spe_samples_from_bytes(bytes).unwrap();
        assert_eq!(header.stream_kind, 2);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].latency_cycles, Some(42));
        assert_eq!(samples[0].cache_result, 1);
        assert_eq!(samples[0].branch_result, 2);
    }
}
