//! One-shot invalidation of experimental file-only network grants.

use std::{io, path::Path, sync::Mutex};

use aya::maps::{Array, Map, MapData, MapType};

/// A trusted publisher's kernel flag: 0 unpublished, 1 eligible, 2 revoked.
/// The daemon only writes 2. Reopening the map never rearms old grants.
// ponytail: any runtime decision disables this file-only snapshot; compile
// runtime state before rearming.
pub struct NetworkPolicyRevocation {
    map: Mutex<Map>,
}

impl NetworkPolicyRevocation {
    /// Open the publisher's pinned, single-entry u64 array.
    ///
    /// # Errors
    /// Returns an error for inaccessible pins or an incompatible map.
    pub fn open(path: &Path) -> io::Result<Self> {
        let data = MapData::from_pin(path).map_err(io::Error::other)?;
        let info = data.info().map_err(io::Error::other)?;
        if info.map_type().map_err(io::Error::other)? != MapType::Array
            || info.key_size() != 4
            || info.value_size() != 8
            || info.max_entries() != 1
        {
            return Err(io::Error::other("invalid network revocation map layout"));
        }
        let map = Map::Array(data);
        let value = Array::<_, u64>::try_from(&map)
            .map_err(io::Error::other)?
            .get(&0, 0)
            .map_err(io::Error::other)?;
        if value > 2 {
            return Err(io::Error::other("invalid network revocation state"));
        }
        Ok(Self {
            map: Mutex::new(map),
        })
    }

    /// Revoke before changing runtime decisions or hostname attribution,
    /// including consumable once grants.
    ///
    /// # Errors
    /// A failed update must prevent the caller from committing its mutation.
    pub fn revoke(&self) -> io::Result<()> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| io::Error::other("network revocation lock poisoned"))?;
        Array::<_, u64>::try_from(&mut *map)
            .map_err(io::Error::other)?
            .set(0, 2, 0)
            .map_err(io::Error::other)
    }
}
