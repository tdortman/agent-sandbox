//! Optional libbpf-loaded live descriptor proof. Pins must come from a fresh
//! load.
use std::{io, os::unix::fs::MetadataExt, path::Path};

use aya::{
    maps::{Array, HashMap, Map, MapData},
    programs::{FEntry, Lsm, RawTracePoint, RawTracePointRunOptions, TestRun},
};

#[derive(Debug)]
pub(super) struct HintPrograms {
    // Keep all observers attached for exactly the query program's lifetime.
    _share: Lsm,

    _new_files: RawTracePoint,
    _connect: FEntry,
    query_program: RawTracePoint,
    queries: Map,
    results: Map,
}

impl HintPrograms {
    pub(super) fn open(pins: &Path) -> io::Result<Self> {
        let map =
            |name: &str| MapData::from_pin(pins.join("maps").join(name)).map_err(io::Error::other);

        // Reusing an eligibility map across an observer outage would be unsafe.
        let clean = Map::LruHashMap(map("clean_files")?);

        let clean = HashMap::<_, u64, [u8; 16]>::try_from(&clean).map_err(io::Error::other)?;

        if clean.keys().next().is_some() {
            return Err(io::Error::other(
                "ownership observers require fresh empty maps",
            ));
        }

        let mut scope = Map::Array(map("scope")?);

        Array::<_, u64>::try_from(&mut scope)
            .map_err(io::Error::other)?
            .set(0, std::fs::metadata("/proc/self/ns/net")?.ino(), 0)
            .map_err(io::Error::other)?;

        let mut share = Lsm::from_pin(pins.join("owner_share_files")).map_err(io::Error::other)?;
        share.attach().map_err(io::Error::other)?;

        let mut new_files =
            RawTracePoint::from_pin(pins.join("owner_new_files")).map_err(io::Error::other)?;

        new_files
            .attach("sched_process_fork")
            .map_err(io::Error::other)?;

        let mut connect = FEntry::from_pin(pins.join("owner_connect")).map_err(io::Error::other)?;
        connect.attach().map_err(io::Error::other)?;

        Ok(Self {
            _share: share,
            _new_files: new_files,
            _connect: connect,
            query_program: RawTracePoint::from_pin(pins.join("owner_hint"))
                .map_err(io::Error::other)?,
            queries: Map::Array(map("queries")?),
            results: Map::Array(map("results")?),
        })
    }

    pub(super) fn resolve(&mut self, query: [u8; 48]) -> io::Result<Option<[u8; 48]>> {
        Array::<_, [u8; 48]>::try_from(&mut self.queries)
            .map_err(io::Error::other)?
            .set(0, query, 0)
            .map_err(io::Error::other)?;

        self.query_program
            .test_run(RawTracePointRunOptions::new())
            .map_err(io::Error::other)?;

        let result = Array::<_, [u8; 48]>::try_from(&self.results)
            .map_err(io::Error::other)?
            .get(&0, 0)
            .map_err(io::Error::other)?;

        if result[..8] != query[..8] || result[44..] != [0; 4] {
            return Err(io::Error::other("invalid ownership hint response"));
        }

        match u32::from_ne_bytes(result[40..44].try_into().expect("record field")) {
            0 => Ok(None),
            1 => Ok(Some(result)),
            _ => Err(io::Error::other("invalid ownership hint status")),
        }
    }
}
