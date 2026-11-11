//! IP-to-ASN lookup over an `asn.db` range table.
//!
//! The file is one IP range per line, tab-separated. The 4-column form is
//! `start  end  asn  name`. The 5-column form written by iptoasn.com is
//! `start  end  asn  country  name`. Blank lines and `#` comments are skipped,
//! and rows for ASN 0 (unannounced space) are ignored. Ranges must not overlap.
//!
//! Nothing here reads the disk except `AsnDb::load`, which the adapters call.
//! The core only parses and searches the bytes it is given.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub enum AsnError {
    Io(String),
    Line { line: usize, reason: String },
}

impl fmt::Display for AsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsnError::Io(msg) => write!(f, "{msg}"),
            AsnError::Line { line, reason } => write!(f, "line {line}: {reason}"),
        }
    }
}

impl std::error::Error for AsnError {}

/// The autonomous system that owns an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    pub asn: u32,
    pub name: Arc<str>,
}

/// Sorted range tables for IPv4 and IPv6. Each range carries an index into `names`.
#[derive(Debug, Default)]
pub struct AsnDb {
    v4: Vec<(u32, u32, u32, u32)>,
    v6: Vec<(u128, u128, u32, u32)>,
    names: Vec<Arc<str>>,
}

impl AsnDb {
    /// Reads and parses the file at `path`.
    pub fn load(path: &Path) -> Result<Self, AsnError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| AsnError::Io(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Parses the table text. Errors name the line that failed.
    pub fn parse(text: &str) -> Result<Self, AsnError> {
        let mut db = AsnDb::default();
        let mut interned: HashMap<String, u32> = HashMap::new();

        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let row = raw.trim();
            if row.is_empty() || row.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = row.split('\t').collect();
            let (start, end, asn, name) = match fields.len() {
                4 => (fields[0], fields[1], fields[2], fields[3]),
                5 => (fields[0], fields[1], fields[2], fields[4]),
                n => {
                    return Err(AsnError::Line {
                        line,
                        reason: format!("expected 4 or 5 tab-separated columns, found {n}"),
                    })
                }
            };
            let start: IpAddr = start.parse().map_err(|_| AsnError::Line {
                line,
                reason: format!("bad range start {start:?}"),
            })?;
            let end: IpAddr = end.parse().map_err(|_| AsnError::Line {
                line,
                reason: format!("bad range end {end:?}"),
            })?;
            let asn: u32 = asn.parse().map_err(|_| AsnError::Line {
                line,
                reason: format!("bad ASN {asn:?}"),
            })?;
            if asn == 0 {
                continue;
            }
            let name_index = *interned.entry(name.to_string()).or_insert_with(|| {
                db.names.push(Arc::from(name));
                (db.names.len() - 1) as u32
            });

            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) => {
                    let (s, e) = (u32::from(s), u32::from(e));
                    if s > e {
                        return Err(AsnError::Line { line, reason: "range start is after its end".into() });
                    }
                    db.v4.push((s, e, asn, name_index));
                }
                (IpAddr::V6(s), IpAddr::V6(e)) => {
                    let (s, e) = (u128::from(s), u128::from(e));
                    if s > e {
                        return Err(AsnError::Line { line, reason: "range start is after its end".into() });
                    }
                    db.v6.push((s, e, asn, name_index));
                }
                _ => {
                    return Err(AsnError::Line { line, reason: "start and end are different IP families".into() })
                }
            }
        }

        db.v4.sort_unstable_by_key(|r| r.0);
        db.v6.sort_unstable_by_key(|r| r.0);
        Ok(db)
    }

    /// Number of ranges loaded.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The ASN that owns `ip`, if any range contains it.
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are looked up as IPv4.
    pub fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => self.lookup_v4(v4),
                None => self.lookup_v6(v6),
            },
        }
    }

    fn lookup_v4(&self, ip: Ipv4Addr) -> Option<AsnInfo> {
        let x = u32::from(ip);
        // The last range that starts at or before `x` is the only candidate.
        let idx = self.v4.partition_point(|r| r.0 <= x).checked_sub(1)?;
        let (_, end, asn, name) = self.v4[idx];
        (x <= end).then(|| self.info(asn, name))
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> Option<AsnInfo> {
        let x = u128::from(ip);
        let idx = self.v6.partition_point(|r| r.0 <= x).checked_sub(1)?;
        let (_, end, asn, name) = self.v6[idx];
        (x <= end).then(|| self.info(asn, name))
    }

    fn info(&self, asn: u32, name: u32) -> AsnInfo {
        AsnInfo { asn, name: Arc::clone(&self.names[name as usize]) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_TABLE: &str = "\
# comment line
1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET
1.0.1.0\t1.0.3.255\t0\tNone\tNot routed
203.0.113.0\t203.0.113.255\t16509\tUS\tAMAZON-02
";

    #[test]
    fn parses_five_column_rows_and_skips_comments_and_asn_zero() {
        let db = AsnDb::parse(V4_TABLE).unwrap();
        assert_eq!(db.len(), 2);
        let hit = db.lookup("1.0.0.7".parse().unwrap()).unwrap();
        assert_eq!(hit.asn, 13335);
        assert_eq!(&*hit.name, "CLOUDFLARENET");
    }

    #[test]
    fn parses_four_column_rows() {
        let db = AsnDb::parse("10.0.0.0\t10.0.0.255\t64500\tEXAMPLE-NET\n").unwrap();
        let hit = db.lookup("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(hit.asn, 64500);
        assert_eq!(&*hit.name, "EXAMPLE-NET");
    }

    #[test]
    fn range_boundaries_are_inclusive() {
        let db = AsnDb::parse("10.0.0.10\t10.0.0.20\t64500\tX\n").unwrap();
        assert!(db.lookup("10.0.0.9".parse().unwrap()).is_none(), "one before start");
        assert_eq!(db.lookup("10.0.0.10".parse().unwrap()).unwrap().asn, 64500, "start");
        assert_eq!(db.lookup("10.0.0.20".parse().unwrap()).unwrap().asn, 64500, "end");
        assert!(db.lookup("10.0.0.21".parse().unwrap()).is_none(), "one after end");
    }

    #[test]
    fn unannounced_space_is_not_found() {
        let db = AsnDb::parse(V4_TABLE).unwrap();
        assert!(db.lookup("1.0.2.1".parse().unwrap()).is_none());
    }

    #[test]
    fn ipv6_ranges_and_mapped_ipv4() {
        let db = AsnDb::parse("2001:db8::\t2001:db8::ffff\t64501\tV6-NET\n10.0.0.0\t10.0.0.255\t64500\tV4-NET\n").unwrap();
        assert_eq!(db.lookup("2001:db8::1".parse().unwrap()).unwrap().asn, 64501);
        assert!(db.lookup("2001:db9::1".parse().unwrap()).is_none());
        // ::ffff:10.0.0.7 is the IPv4 address 10.0.0.7.
        assert_eq!(db.lookup("::ffff:10.0.0.7".parse().unwrap()).unwrap().asn, 64500);
    }

    #[test]
    fn malformed_row_reports_its_line_number() {
        let err = AsnDb::parse("# ok\n10.0.0.0\t10.0.0.255\tnot-a-number\tX\n").unwrap_err();
        match err {
            AsnError::Line { line, .. } => assert_eq!(line, 2),
            other => panic!("expected a line error, got {other}"),
        }
    }

    #[test]
    fn wrong_column_count_and_reversed_range_are_errors() {
        assert!(AsnDb::parse("10.0.0.0\t10.0.0.255\n").is_err());
        assert!(AsnDb::parse("10.0.0.9\t10.0.0.1\t64500\tX\n").is_err());
    }

    #[test]
    fn empty_table_finds_nothing() {
        let db = AsnDb::parse("").unwrap();
        assert!(db.is_empty());
        assert!(db.lookup("1.1.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn repeated_names_share_storage() {
        let db = AsnDb::parse("10.0.0.0\t10.0.0.1\t1\tSAME\n10.0.0.2\t10.0.0.3\t1\tSAME\n").unwrap();
        assert_eq!(db.names.len(), 1);
    }
}
