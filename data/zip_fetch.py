"""Selective per-host pcap fetch from the CIC-IDS-2018 archives (decision 001).

The dataset's `pcap.zip` files hold one member per capture host. Instead of
downloading 36-55 GiB per day, this module parses the remote zip's central
directory over HTTP range requests, picks the members that matter (timeline
attacker/victim hosts + a seeded sample of benign hosts) and streams just those
members to disk, inflating on the fly.

    python -m data.zip_fetch --dry-run          # plan + bytes, nothing fetched
    python -m data.zip_fetch                    # fetch every configured day
    python -m data.zip_fetch --day 2018-02-14   # one day

A victim host with no matching member is a hard error (stop-and-ask trigger).
"""

from __future__ import annotations

import argparse
import random
import re
import struct
import sys
import time
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

_EOCD_SIG = b"PK\x05\x06"
_EOCD64_LOC_SIG = b"PK\x06\x07"
_EOCD64_SIG = b"PK\x06\x06"
_CENTRAL_SIG = b"PK\x01\x02"
_LOCAL_SIG = b"PK\x03\x04"
_U16_MAX = 0xFFFF
_U32_MAX = 0xFFFFFFFF
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_CHUNK = 48 * 1024 * 1024  # large ranges amortise per-request TLS/latency overhead


@dataclass
class Member:
    name: str
    method: int
    csize: int
    usize: int
    crc32: int
    local_off: int

    @property
    def host_ip(self) -> str | None:
        match = _IP_RE.search(self.name)
        return match.group(1) if match else None


class HttpRanged:
    """Byte-range reads against one URL, with light retry."""

    def __init__(self, url: str, timeout: int = 120, retries: int = 3):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            self.size = int(resp.headers["Content-Length"])

    def read(self, start: int, length: int) -> bytes:
        end = start + length - 1
        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(
                    self.url, headers={"Range": f"bytes={start}-{end}"}
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read()
            except Exception as exc:  # transient S3/network hiccups
                last_error = exc
                time.sleep(2**attempt)
        raise RuntimeError(f"range read failed after {self.retries} tries: {last_error}")

    def iter_ranges(self, start: int, length: int, chunk: int = _CHUNK):
        offset = start
        remaining = length
        while remaining > 0:
            step = min(chunk, remaining)
            yield self.read(offset, step)
            offset += step
            remaining -= step


class FileRanged:
    """Same interface over a local file — used by the unit tests (offline)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.size = self.path.stat().st_size

    def read(self, start: int, length: int) -> bytes:
        with open(self.path, "rb") as fh:
            fh.seek(start)
            return fh.read(length)

    def iter_ranges(self, start: int, length: int, chunk: int = _CHUNK):
        offset = start
        remaining = length
        while remaining > 0:
            step = min(chunk, remaining)
            yield self.read(offset, step)
            offset += step
            remaining -= step


def _parse_zip64_extra(extra: bytes, usize: int, csize: int, local_off: int):
    pos = 0
    while pos + 4 <= len(extra):
        field_id, field_len = struct.unpack_from("<HH", extra, pos)
        if field_id == 0x0001:
            body = extra[pos + 4 : pos + 4 + field_len]
            cursor = 0
            if usize == _U32_MAX:
                usize = struct.unpack_from("<Q", body, cursor)[0]
                cursor += 8
            if csize == _U32_MAX:
                csize = struct.unpack_from("<Q", body, cursor)[0]
                cursor += 8
            if local_off == _U32_MAX:
                local_off = struct.unpack_from("<Q", body, cursor)[0]
                cursor += 8
            break
        pos += 4 + field_len
    return usize, csize, local_off


def read_index(src) -> list[Member]:
    """Parse the central directory of a (possibly ZIP64) archive via ranged reads."""
    tail_len = min(src.size, 1024 * 1024)
    tail = src.read(src.size - tail_len, tail_len)

    eocd_pos = tail.rfind(_EOCD_SIG)
    if eocd_pos == -1:
        raise ValueError("no end-of-central-directory record found — not a zip?")
    n_entries, cd_size, cd_off = struct.unpack_from("<HII", tail, eocd_pos + 10)

    loc_pos = tail.rfind(_EOCD64_LOC_SIG)
    if _U32_MAX in (cd_size, cd_off) or n_entries == _U16_MAX or loc_pos != -1:
        if loc_pos == -1:
            raise ValueError("zip64 sizes present but no zip64 locator found")
        eocd64_off = struct.unpack_from("<Q", tail, loc_pos + 8)[0]
        eocd64 = src.read(eocd64_off, 56)
        if eocd64[:4] != _EOCD64_SIG:
            raise ValueError("bad zip64 EOCD signature")
        n_entries = struct.unpack_from("<Q", eocd64, 32)[0]
        cd_size = struct.unpack_from("<Q", eocd64, 40)[0]
        cd_off = struct.unpack_from("<Q", eocd64, 48)[0]

    cd = b"".join(src.iter_ranges(cd_off, cd_size))

    members: list[Member] = []
    pos = 0
    while pos + 46 <= len(cd) and cd[pos : pos + 4] == _CENTRAL_SIG:
        method = struct.unpack_from("<H", cd, pos + 10)[0]
        crc = struct.unpack_from("<I", cd, pos + 16)[0]
        csize = struct.unpack_from("<I", cd, pos + 20)[0]
        usize = struct.unpack_from("<I", cd, pos + 24)[0]
        nlen, elen, clen = struct.unpack_from("<HHH", cd, pos + 28)
        local_off = struct.unpack_from("<I", cd, pos + 42)[0]
        name = cd[pos + 46 : pos + 46 + nlen].decode("utf-8", "replace")
        extra = cd[pos + 46 + nlen : pos + 46 + nlen + elen]
        usize, csize, local_off = _parse_zip64_extra(extra, usize, csize, local_off)
        if not name.endswith("/"):
            members.append(Member(name, method, csize, usize, crc, local_off))
        pos += 46 + nlen + elen + clen

    if len(members) == 0:
        raise ValueError("central directory parsed to zero file members")
    return members


def fetch_member(src, member: Member, out_path: Path) -> None:
    """Stream one member to disk (raw-deflate inflated on the fly), verify CRC."""
    header = src.read(member.local_off, 30)
    if header[:4] != _LOCAL_SIG:
        raise ValueError(f"bad local header for {member.name}")
    nlen, elen = struct.unpack_from("<HH", header, 26)
    data_start = member.local_off + 30 + nlen + elen

    out_path.parent.mkdir(parents=True, exist_ok=True)
    crc = 0
    written = 0
    inflater = zlib.decompressobj(-15) if member.method == 8 else None
    with open(out_path, "wb") as out:
        for chunk in src.iter_ranges(data_start, member.csize):
            data = inflater.decompress(chunk) if inflater else chunk
            crc = zlib.crc32(data, crc)
            written += len(data)
            out.write(data)
        if inflater:
            data = inflater.flush()
            crc = zlib.crc32(data, crc)
            written += len(data)
            out.write(data)

    if written != member.usize:
        raise ValueError(f"{member.name}: wrote {written} bytes, expected {member.usize}")
    if crc != member.crc32:
        raise ValueError(f"{member.name}: CRC mismatch after inflate")


def select_members(
    members: list[Member],
    attacker_ips: set[str],
    victim_ips: set[str],
    benign_count: int,
    seed: int,
    date: str,
) -> tuple[list[Member], list[Member]]:
    """(timeline members, seeded benign sample).

    Every INTERNAL victim must have a member — the attack evidence lives in the
    victim's capture, so a missing one is unrecoverable data loss (stop trigger).
    Attacker machines (the separate attacker VPC, or external hosts) have no
    members of their own; their traffic appears inside victim captures, so a
    matching attacker member is fetched when present but never required —
    extraction (M2) asserts attacker IPs actually occur in victim pcaps.
    """
    timeline_ips = attacker_ips | victim_ips
    by_ip: dict[str, list[Member]] = {}
    rest: list[Member] = []
    for m in members:
        ip = m.host_ip
        if ip and ip in timeline_ips:
            by_ip.setdefault(ip, []).append(m)
        else:
            rest.append(m)

    internal_victims = {ip for ip in victim_ips if ip.startswith("172.31.")}
    missing = internal_victims - set(by_ip)
    if missing:
        raise SystemExit(
            f"[{date}] victim host(s) with no pcap member: {sorted(missing)} — "
            "stopping; see decision 001 stop-and-report trigger"
        )

    timeline_members = [m for ms in by_ip.values() for m in ms]
    benign = random.Random(f"{seed}:{date}").sample(rest, min(benign_count, len(rest)))
    return timeline_members, benign


def _day_ip_sets(timeline: dict, date: str) -> tuple[set[str], set[str]]:
    for day in timeline["days"]:
        if day["date"] == date:
            attackers: set[str] = set()
            victims: set[str] = set()
            for attack in day["attacks"]:
                attackers.update(attack["attacker_ips"])
                victims.update(attack["victim_ips"])
            return attackers, victims
    raise KeyError(f"date {date} not present in the attack timeline")


def main(argv: list[str] | None = None) -> int:
    import yaml

    from configs import load_config, resolve_path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--day", help="fetch only this date (YYYY-MM-DD)")
    args = parser.parse_args(argv)

    cfg = load_config("data")
    with open(resolve_path(cfg["dataset"]["timeline"]), encoding="utf-8") as fh:
        timeline = yaml.safe_load(fh)

    raw_dir = resolve_path(cfg["paths"]["raw_dir"])
    base = cfg["dataset"]["s3_https_base"]
    prefix = urllib.parse.quote(cfg["dataset"]["pcap_prefix"])

    days = cfg["dataset"]["days"]
    if args.day:
        days = [d for d in days if d["date"] == args.day]
        if not days:
            print(f"day {args.day} is not configured", file=sys.stderr)
            return 2

    grand_total = 0
    for day in days:
        url = f"{base}/{prefix}/{urllib.parse.quote(day['pcap_dir'])}/{day['pcap_archive']}"
        print(f"[{day['date']}] indexing {url}")
        src = HttpRanged(url)
        members = read_index(src)
        attacker_ips, victim_ips = _day_ip_sets(timeline, day["date"])
        wanted, benign = select_members(
            members,
            attacker_ips,
            victim_ips,
            cfg["dataset"]["benign_hosts_per_day"],
            cfg["dataset"]["host_sample_seed"],
            day["date"],
        )
        selected = wanted + benign
        day_bytes = sum(m.csize for m in selected)
        grand_total += day_bytes
        print(
            f"[{day['date']}] {len(members)} members; selecting "
            f"{len(wanted)} timeline + {len(benign)} benign = {len(selected)} "
            f"({day_bytes / 2**30:.2f} GiB compressed)"
        )

        if args.dry_run:
            continue

        host_dir = raw_dir / day["date"] / "hosts"
        for i, member in enumerate(selected, 1):
            base = Path(member.name).name
            out_path = host_dir / (base if base.endswith(".pcap") else base + ".pcap")
            if out_path.exists() and out_path.stat().st_size == member.usize:
                continue
            print(f"[{day['date']}] ({i}/{len(selected)}) {member.name} "
                  f"({member.csize / 2**20:.0f} MiB)")
            fetch_member(src, member, out_path)
        print(f"[{day['date']}] done -> {host_dir}")

    print(f"TOTAL selected: {grand_total / 2**30:.2f} GiB compressed"
          + (" (dry run, nothing fetched)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
