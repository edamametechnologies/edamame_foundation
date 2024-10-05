use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::io::Read;
use std::net::IpAddr;

/// Autonomous System number record.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct Record {
    /// Assigned AS number.
    pub as_number: u32,
    /// Country code of network owner.
    pub country: String,
    /// Network owner information.
    pub owner: String,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.as_number == other.as_number
            && self.country == other.country
            && self.owner == other.owner
    }
}

impl Eq for Record {}

impl PartialOrd for Record {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Record {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.as_number.cmp(&other.as_number) {
            Ordering::Equal => match self.country.cmp(&other.country) {
                Ordering::Equal => self.owner.cmp(&other.owner),
                other_ordering => other_ordering,
            },
            other_ordering => other_ordering,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecordInternal {
    range_start: IpAddr,
    range_end: IpAddr,
    as_number: u32,
    country: String,
    owner: String,
}

impl PartialEq for RecordInternal {
    fn eq(&self, other: &RecordInternal) -> bool {
        self.range_start == other.range_start && self.range_end == other.range_end
    }
}

impl Eq for RecordInternal {}

impl PartialOrd for RecordInternal {
    fn partial_cmp(&self, other: &RecordInternal) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RecordInternal {
    fn cmp(&self, other: &RecordInternal) -> Ordering {
        match self.range_start.cmp(&other.range_start) {
            Ordering::Equal => self.range_end.cmp(&other.range_end),
            other_ordering => other_ordering,
        }
    }
}

pub struct Db(Vec<RecordInternal>);

impl Db {
    /// Loads database from ASN data as provided by IPtoASN.
    pub fn from_tsv(data: impl Read) -> Result<Db> {
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(data);

        let mut records = Vec::new();

        for result in rdr.records() {
            let record = result.context("Failed to read TSV record")?;
            if record.len() < 5 {
                continue;
            }
            let owner = &record[4];
            if owner == "Not routed" || owner == "None" {
                continue;
            }

            let range_start = record[0]
                .parse::<IpAddr>()
                .context("Parsing range_start IP")?;
            let range_end = record[1]
                .parse::<IpAddr>()
                .context("Parsing range_end IP")?;
            let as_number = record[2].parse::<u32>().context("Parsing as_number")?;
            let country = record[3].to_owned();
            let owner = record[4].to_owned();

            // Ensure the IP versions match and range is valid
            match (range_start, range_end) {
                (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => {
                    records.push(RecordInternal {
                        range_start: IpAddr::V4(start),
                        range_end: IpAddr::V4(end),
                        as_number,
                        country: country.clone(),
                        owner: owner.clone(),
                    });
                }
                (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => {
                    records.push(RecordInternal {
                        range_start: IpAddr::V6(start),
                        range_end: IpAddr::V6(end),
                        as_number,
                        country: country.clone(),
                        owner: owner.clone(),
                    });
                }
                _ => {
                    // Skip records where IP versions don't match or range is invalid
                    continue;
                }
            }
        }

        // Sort the records by range_start and range_end
        records.sort();

        Ok(Db(records))
    }

    /// Performs lookup by an IP address and returns a unified `Record`.
    pub fn lookup(&self, ip: IpAddr) -> Option<Record> {
        let records = &self.0;
        let mut low = 0;
        let mut high = records.len();

        while low < high {
            let mid = (low + high) / 2;
            let rec = &records[mid];

            if rec.range_start <= ip && ip <= rec.range_end {
                return Some(Record {
                    as_number: rec.as_number,
                    country: rec.country.clone(),
                    owner: rec.owner.clone(),
                });
            } else if ip < rec.range_start {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        None
    }
}
