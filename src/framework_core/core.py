__all__ = ["Core"]


import time
import json
import hashlib
from dataclasses import dataclass
from typing import Any


def _hash_dict(d: dict) -> str:
    # Deterministic hashing: JSON with sorted keys
    payload = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LedgerEntry:
    ts: float
    event: str
    action: str
    data: dict[str, Any]
    fingerprint: tuple[int, bool]
    prev_hash: str
    entry_hash: str


class Core:
    """
    Core v1:
    - identity + initialization gate
    - fingerprint reflects state changes
    - ledger is a hash-chained, tamper-detectable history
    - public ledger view is immutable (tuple of frozen entries)
    """

    def __init__(self) -> None:
        self._initialized = True
        self._version = 1
        self._ledger: list[LedgerEntry] = []
        self._record(event="init", action="__init__", data={"initialized": self._initialized})

    def is_initialized(self) -> bool:
        return self._initialized

    def identity(self) -> str:
        return "CORE"

    def initialize(self) -> None:
        self._initialized = True
        self._version += 1
        self._record(event="action", action="initialize", data={"version": self._version})

    def fingerprint(self) -> tuple[int, bool]:
        return (self._version, self._initialized)

    # --- Ledger API (tamper-resistant by design) ---

    def ledger(self) -> tuple[LedgerEntry, ...]:
        # Immutable view: callers can't append/remove/modify entries
        return tuple(self._ledger)

    def validate_ledger(self) -> bool:
        """
        Verifies:
        - each entry_hash matches recomputed hash of its contents
        - each entry's prev_hash matches the previous entry_hash
        """
        prev = "GENESIS"
        for entry in self._ledger:
            expected = self._compute_entry_hash(
                ts=entry.ts,
                event=entry.event,
                action=entry.action,
                data=entry.data,
                fingerprint=entry.fingerprint,
                prev_hash=prev,
            )
            if entry.prev_hash != prev:
                return False
            if entry.entry_hash != expected:
                return False
            prev = entry.entry_hash
        return True

    # --- Internal mechanics ---

    def _record(self, event: str, action: str, data: dict[str, Any]) -> None:
        prev_hash = self._ledger[-1].entry_hash if self._ledger else "GENESIS"
        ts = time.time()
        fp = self.fingerprint()

        entry_hash = self._compute_entry_hash(
            ts=ts,
            event=event,
            action=action,
            data=data,
            fingerprint=fp,
            prev_hash=prev_hash,
        )

        self._ledger.append(
            LedgerEntry(
                ts=ts,
                event=event,
                action=action,
                data=dict(data),
                fingerprint=fp,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
        )

    def _compute_entry_hash(
        self,
        ts: float,
        event: str,
        action: str,
        data: dict[str, Any],
        fingerprint: tuple[int, bool],
        prev_hash: str,
    ) -> str:
        return _hash_dict(
            {
                "ts": ts,
                "event": event,
                "action": action,
                "data": data,
                "fingerprint": list(fingerprint),
                "prev_hash": prev_hash,
            }
        )

    def validate(self) -> None:
                # Basic invariants
        if not isinstance(self._version, int) or self._version < 1:
            raise ValueError(f"Invalid version: {self._version}")

        if not isinstance(self._initialized, bool):
            raise ValueError(f"Invalid initialized flag: {self._initialized}")

        if not isinstance(self._ledger, list):
            raise ValueError("Ledger is not a list")

        if len(self._ledger) == 0:
            raise ValueError("Ledger is empty")

        prev = "GENESIS"
        last_ts = None
        last_version = None

        for i, e in enumerate(self._ledger):
            # --- Genesis rules ---
            if i == 0:
                if e.prev_hash != "GENESIS":
                    raise ValueError("First ledger entry must have prev_hash='GENESIS'")
                if e.action != "__init__":
                    raise ValueError("First ledger entry must be action='__init__'")

            # --- Time coherence ---
            if last_ts is not None and e.ts < last_ts:
                raise ValueError(f"Time moved backwards at index {i}")
            last_ts = e.ts

            # --- Hash chain linkage ---
            if e.prev_hash != prev:
                raise ValueError(f"Ledger broken at index {i}: prev_hash mismatch")

            expected = self._compute_entry_hash(
                ts=e.ts,
                event=e.event,
                action=e.action,
                data=e.data,
                fingerprint=e.fingerprint,
                prev_hash=e.prev_hash,
            )
            if e.entry_hash != expected:
                raise ValueError(f"Tamper detected at index {i}: entry_hash mismatch")

            # --- Version semantics (initialize must bump by 1) ---
            v, init_flag = e.fingerprint
            if not isinstance(v, int) or v < 1:
                raise ValueError(f"Invalid fingerprint version at index {i}")
            if not isinstance(init_flag, bool):
                raise ValueError(f"Invalid fingerprint initialized flag at index {i}")

            if last_version is not None:
                if e.action == "initialize":
                    if v != last_version + 1:
                        raise ValueError(f"initialize must bump version by 1 at index {i}")
                else:
                    # Non-initialize actions should not decrease version
                    if v < last_version:
                        raise ValueError(f"Version decreased at index {i}")

            last_version = v
            prev = e.entry_hash

        # --- Final state must match the last fingerprint ---
        last_fp_version, last_fp_init = self._ledger[-1].fingerprint
        if last_fp_version != self._version:
            raise ValueError("Current version does not match last ledger fingerprint")
        if last_fp_init != self._initialized:
            raise ValueError("Current initialized flag does not match last ledger fingerprint")
