# Identity Grouping + Fingerprint History Migration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate device identity grouping and fingerprint history from the old Database to the new Store, enabling MAC spoofing detection and randomized MAC correlation to work entirely through the new pipeline.

**Architecture:** Two new repository classes (IdentityRepository, FingerprintSnapshotRepository) following the existing Store pattern. Pipeline calls identity correlation on every verdict, writes fingerprint snapshots. Spoofing detector switches reads/writes to new Store.

**Tech Stack:** Python, aiosqlite, existing Store/Repository pattern, pytest

---

### Task 1: IdentityRepository + FingerprintSnapshotRepository

**Files:**
- Create: `src/leetha/store/identities.py`
- Create: `src/leetha/store/snapshots.py`
- Modify: `src/leetha/store/models.py` — add `Identity` dataclass
- Modify: `src/leetha/store/hosts.py` — add `identity_id` column to hosts table

**Step 1: Add Identity model to models.py**

Add after the existing `Host` class (~line 249):

```python
@dataclass
class Identity:
    """A physical device identity, grouping one or more MAC addresses."""
    primary_mac: str
    id: int | None = None
    manufacturer: str | None = None
    device_type: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    confidence: int = 0
    fingerprint: dict = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
```

**Step 2: Create `src/leetha/store/identities.py`**

```python
"""Identity repository -- physical device identity records."""
from __future__ import annotations

import json
from datetime import datetime
from leetha.store.models import Identity


class IdentityRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                primary_mac TEXT UNIQUE NOT NULL,
                manufacturer TEXT,
                device_type TEXT,
                os_family TEXT,
                os_version TEXT,
                hostname TEXT,
                confidence INTEGER DEFAULT 0,
                fingerprint TEXT DEFAULT '{}',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_identities_mac ON identities(primary_mac)")
        await self._conn.commit()

    async def find_or_create(self, primary_mac: str) -> Identity:
        """Get existing identity by primary_mac, or create a new one."""
        existing = await self.find_by_mac(primary_mac)
        if existing:
            return existing
        now = datetime.now().isoformat()
        cursor = await self._conn.execute(
            "INSERT INTO identities (primary_mac, first_seen, last_seen) VALUES (?, ?, ?)",
            (primary_mac, now, now))
        await self._conn.commit()
        return Identity(primary_mac=primary_mac, id=cursor.lastrowid,
                        first_seen=datetime.now(), last_seen=datetime.now())

    async def find_by_mac(self, primary_mac: str) -> Identity | None:
        cursor = await self._conn.execute(
            "SELECT * FROM identities WHERE primary_mac = ?", (primary_mac,))
        row = await cursor.fetchone()
        return self._row_to_identity(row) if row else None

    async def find_by_id(self, identity_id: int) -> Identity | None:
        cursor = await self._conn.execute(
            "SELECT * FROM identities WHERE id = ?", (identity_id,))
        row = await cursor.fetchone()
        return self._row_to_identity(row) if row else None

    async def find_all(self, limit: int = 500) -> list[Identity]:
        cursor = await self._conn.execute(
            "SELECT * FROM identities ORDER BY last_seen DESC LIMIT ?", (limit,))
        return [self._row_to_identity(r) for r in await cursor.fetchall()]

    async def update(self, identity: Identity) -> None:
        """Update identity metadata from latest verdict."""
        await self._conn.execute("""
            UPDATE identities SET
                manufacturer = COALESCE(?, manufacturer),
                device_type = COALESCE(?, device_type),
                os_family = COALESCE(?, os_family),
                os_version = COALESCE(?, os_version),
                hostname = COALESCE(?, hostname),
                confidence = MAX(?, COALESCE(confidence, 0)),
                fingerprint = ?,
                last_seen = ?
            WHERE id = ?
        """, (identity.manufacturer, identity.device_type, identity.os_family,
              identity.os_version, identity.hostname, identity.confidence,
              json.dumps(identity.fingerprint), identity.last_seen.isoformat(),
              identity.id))
        await self._conn.commit()

    async def get_macs_for_identity(self, identity_id: int) -> list[str]:
        """Return all MACs linked to an identity."""
        cursor = await self._conn.execute(
            "SELECT hw_addr FROM hosts WHERE identity_id = ?", (identity_id,))
        return [r[0] for r in await cursor.fetchall()]

    def _row_to_identity(self, row) -> Identity:
        fp = json.loads(row["fingerprint"]) if row["fingerprint"] else {}
        return Identity(
            id=row["id"],
            primary_mac=row["primary_mac"],
            manufacturer=row["manufacturer"],
            device_type=row["device_type"],
            os_family=row["os_family"],
            os_version=row["os_version"],
            hostname=row["hostname"],
            confidence=row["confidence"],
            fingerprint=fp,
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
        )
```

**Step 3: Create `src/leetha/store/snapshots.py`**

```python
"""Fingerprint snapshot repository -- per-MAC identity history for drift detection."""
from __future__ import annotations

from datetime import datetime


class SnapshotRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hw_addr TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                os_family TEXT,
                manufacturer TEXT,
                device_type TEXT,
                hostname TEXT,
                oui_vendor TEXT
            )
        """)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_snapshots_hw ON fingerprint_snapshots(hw_addr)")
        await self._conn.commit()

    async def add(self, hw_addr: str, os_family: str | None = None,
                  manufacturer: str | None = None, device_type: str | None = None,
                  hostname: str | None = None, oui_vendor: str | None = None) -> None:
        await self._conn.execute("""
            INSERT INTO fingerprint_snapshots
                (hw_addr, timestamp, os_family, manufacturer, device_type, hostname, oui_vendor)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (hw_addr, datetime.now().isoformat(), os_family, manufacturer,
              device_type, hostname, oui_vendor))
        await self._conn.commit()

    async def get_latest(self, hw_addr: str, limit: int = 1) -> list[dict]:
        cursor = await self._conn.execute(
            "SELECT * FROM fingerprint_snapshots WHERE hw_addr = ? "
            "ORDER BY timestamp DESC LIMIT ?", (hw_addr, limit))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def prune(self, max_per_mac: int = 50) -> int:
        """Delete old snapshots keeping only the most recent max_per_mac per device."""
        cursor = await self._conn.execute("""
            DELETE FROM fingerprint_snapshots WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (PARTITION BY hw_addr ORDER BY timestamp DESC) as rn
                    FROM fingerprint_snapshots
                ) WHERE rn <= ?
            )
        """, (max_per_mac,))
        await self._conn.commit()
        return cursor.rowcount
```

**Step 4: Add identity_id column to hosts table**

In `src/leetha/store/hosts.py`, update `create_tables()` to add the column via migration:

After the existing CREATE TABLE, add:
```python
# Migration: add identity_id column if missing
try:
    await self._conn.execute(
        "ALTER TABLE hosts ADD COLUMN identity_id INTEGER")
    await self._conn.commit()
except Exception:
    pass  # Column already exists
```

Update `upsert()` to include `identity_id`:
- Add `identity_id` to INSERT VALUES and ON CONFLICT SET
- Update `_row_to_host()` to read `identity_id`

Update the `Host` model to include `identity_id: int | None = None`.

**Step 5: Wire repositories into Store**

In `src/leetha/store/store.py`, import and initialize both new repositories alongside existing ones.

**Step 6: Run tests**

Run: `python -m pytest spec/ -x --timeout=30 -q`
Expected: 511 passed (no regressions — new tables are additive)

**Step 7: Commit**

```
feat: add identity and fingerprint_snapshot repositories to Store
```

---

### Task 2: Wire Identity Correlation Into Pipeline

**Files:**
- Modify: `src/leetha/core/pipeline.py` — add identity resolution after verdict
- Modify: `src/leetha/app.py` — extract correlation signals from sightings

**Step 1: Add identity resolution to Pipeline.process()**

After step 7 (store verdict), before the `_on_verdict` callback, add identity resolution:

```python
# 8. Resolve device identity
try:
    await self._resolve_identity(hw_addr, verdict, host)
except Exception:
    logger.debug("Identity resolution failed for %s", hw_addr, exc_info=True)
```

Add `_resolve_identity` method to Pipeline:

```python
async def _resolve_identity(self, hw_addr: str, verdict, host) -> None:
    """Link this host to a device identity."""
    from leetha.fingerprint.mac_intel import (
        is_randomized_mac, compute_correlation_score,
        extract_correlation_signals, CORRELATION_THRESHOLD,
    )

    if not is_randomized_mac(hw_addr):
        # Non-randomized: identity IS this MAC
        identity = await self.store.identities.find_or_create(hw_addr)
    else:
        # Randomized: try to correlate with existing identities
        # If we already have a real_hw_addr from DHCP opt61, use it
        if host and host.real_hw_addr:
            identity = await self.store.identities.find_or_create(host.real_hw_addr)
        else:
            # Build correlation fingerprint from accumulated sightings
            signals = self._build_correlation_signals(hw_addr)
            identity = await self._correlate_or_create(hw_addr, signals)

    # Update identity metadata from verdict
    identity.manufacturer = verdict.vendor or identity.manufacturer
    identity.device_type = verdict.category or identity.device_type
    identity.os_family = verdict.platform or identity.os_family
    identity.os_version = verdict.platform_version or identity.os_version
    identity.hostname = verdict.hostname or identity.hostname
    identity.confidence = max(verdict.certainty, identity.confidence)
    from datetime import datetime
    identity.last_seen = datetime.now()
    await self.store.identities.update(identity)

    # Link host to identity
    if identity.id:
        host_record = await self.store.hosts.find_by_addr(hw_addr)
        if host_record and getattr(host_record, 'identity_id', None) != identity.id:
            await self.store.connection.execute(
                "UPDATE hosts SET identity_id = ? WHERE hw_addr = ?",
                (identity.id, hw_addr))
            await self.store.connection.commit()
```

Add `_build_correlation_signals` and `_correlate_or_create`:

```python
def _build_correlation_signals(self, hw_addr: str) -> dict:
    """Build correlation fingerprint from evidence buffer."""
    signals = {}
    for ev in self._evidence_buffer.get(hw_addr, []):
        raw = ev.raw or {}
        if ev.hostname and "hostname" not in signals:
            signals["hostname"] = ev.hostname.lower()
        if raw.get("opt60") and "dhcp_opt60" not in signals:
            signals["dhcp_opt60"] = raw["opt60"]
        if raw.get("opt55") and "dhcp_opt55" not in signals:
            signals["dhcp_opt55"] = raw["opt55"]
        if raw.get("name") and "mdns_name" not in signals:
            signals["mdns_name"] = raw["name"].lower()
    return signals

async def _correlate_or_create(self, hw_addr: str, signals: dict):
    """Score against existing identities, link to best match or create new."""
    from leetha.fingerprint.mac_intel import (
        compute_correlation_score, CORRELATION_THRESHOLD,
    )
    if not signals:
        return await self.store.identities.find_or_create(hw_addr)

    best_score = 0.0
    best_identity = None
    all_identities = await self.store.identities.find_all(limit=1000)
    for ident in all_identities:
        if not ident.fingerprint:
            continue
        score = compute_correlation_score(signals, ident.fingerprint)
        if score > best_score:
            best_score = score
            best_identity = ident

    if best_identity and best_score >= CORRELATION_THRESHOLD:
        return best_identity

    # No match — create new identity for this randomized MAC
    identity = await self.store.identities.find_or_create(hw_addr)
    identity.fingerprint = signals
    await self.store.identities.update(identity)
    return identity
```

**Step 2: Run tests**

Run: `python -m pytest spec/ -x --timeout=30 -q`

**Step 3: Commit**

```
feat: wire identity correlation into pipeline for randomized MAC grouping
```

---

### Task 3: Migrate Spoofing Detector to New Fingerprint Snapshots

**Files:**
- Modify: `src/leetha/app.py` — pass Store to spoofing detector, write snapshots to new table
- Modify: `src/leetha/analysis/spoofing.py` — accept Store for snapshot reads/writes

**Step 1: Update `_check_device_spoofing` in app.py**

After calling `process_device_update()`, also write a fingerprint snapshot to the new Store:

```python
# Write fingerprint snapshot to new Store
await self.store.snapshots.add(
    hw_addr=hw_addr,
    os_family=verdict.platform,
    manufacturer=verdict.vendor,
    device_type=verdict.category,
    hostname=verdict.hostname,
    oui_vendor=oui_vendor,
)
```

**Step 2: Update `process_device_update` in spoofing.py to accept an optional snapshot reader**

Add an optional `snapshot_reader` parameter — a callable that returns prior snapshots.
When provided, use it instead of `self._db.get_fingerprint_history()`.
When not provided, fall back to old DB (backward compat).

In app.py `_check_device_spoofing`, pass a lambda:

```python
async def _read_snapshots(mac, limit=1):
    return await self.store.snapshots.get_latest(mac, limit)

alerts = await self.spoofing_detector.process_device_update(
    device, oui_vendor=oui_vendor, snapshot_reader=_read_snapshots)
```

Remove the `add_fingerprint_snapshot` call inside `process_device_update` when the new reader is provided (the caller handles it).

**Step 3: Run tests**

Run: `python -m pytest spec/ -x --timeout=30 -q`

**Step 4: Commit**

```
feat: migrate spoofing detector fingerprint reads/writes to new Store
```

---

### Task 4: API + Pruning

**Files:**
- Modify: `src/leetha/ui/web/app.py` — add identity_id to device dicts, add identity grouping endpoint
- Modify: `src/leetha/app.py` — add snapshot pruning to analysis loop

**Step 1: Update `_build_device_dict` to include identity_id**

Read identity_id from host, include in device dict. Add `identity_id` and `identity_macs` (list of all MACs sharing identity).

**Step 2: Add snapshot pruning to `_analysis_loop`**

Alongside sightings pruning, call `store.snapshots.prune(max_per_mac=50)`.

**Step 3: Run tests**

Run: `python -m pytest spec/ -x --timeout=30 -q`

**Step 4: Commit**

```
feat: expose identity_id in device API, add snapshot pruning
```

---

### Task 5: Verify End-to-End

**Step 1:** Run full test suite: `python -m pytest spec/ -x --timeout=30 -q`

**Step 2:** Verify imports: `python -c "from leetha.store.store import Store; from leetha.store.identities import IdentityRepository; from leetha.store.snapshots import SnapshotRepository; print('OK')"`

**Step 3:** Verify table creation:
```python
python -c "
import asyncio
from leetha.store.store import Store
async def check():
    s = Store(':memory:')
    await s.initialize()
    # Check identities table
    c = await s.connection.execute('SELECT name FROM sqlite_master WHERE type=\"table\"')
    tables = [r[0] for r in await c.fetchall()]
    assert 'identities' in tables, f'Missing identities: {tables}'
    assert 'fingerprint_snapshots' in tables, f'Missing snapshots: {tables}'
    print(f'Tables: {tables}')
    await s.close()
asyncio.run(check())
"
```

**Step 4: Final commit if needed**
