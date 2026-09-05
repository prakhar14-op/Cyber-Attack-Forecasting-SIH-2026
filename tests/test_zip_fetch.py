"""Ranged zip reader (decision 001 infrastructure): index parse, member fetch
with CRC verification, zip64 handling, and timeline-driven selection — all
against local archives (no network in tests).
"""

from __future__ import annotations

import struct
import zipfile
import zlib

import pytest

from data.zip_fetch import FileRanged, fetch_member, read_index, select_members

HOSTS = {
    "pcap/capUbuntu-172.31.69.25": b"victim capture " * 4000,
    "pcap/capKali-172.31.70.4": b"attacker capture " * 300,
    "pcap/capW10-172.31.64.17": b"benign one " * 500,
    "pcap/capW10-172.31.64.18": b"benign two " * 700,
    "pcap/capW10-172.31.64.19": b"benign three " * 100,
}


def _build_zip(path):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.mkdir("pcap")
        for name, payload in HOSTS.items():
            zf.writestr(zipfile.ZipInfo(name), payload, zipfile.ZIP_DEFLATED)
    return path


@pytest.mark.parametrize("zip64", [False, True])
def test_index_and_fetch_roundtrip_with_crc(tmp_path, monkeypatch, zip64):
    if zip64:
        # Force zip64 records on a small archive so the EOCD64 branch runs.
        monkeypatch.setattr(zipfile, "ZIP64_LIMIT", 128)
    archive = _build_zip(tmp_path / "pcap.zip")
    src = FileRanged(archive)

    members = read_index(src)
    assert {m.name for m in members} == set(HOSTS), "directory entry must be excluded"

    for member in members:
        out = tmp_path / "out" / (member.name.split("/")[-1] + ".pcap")
        fetch_member(src, member, out)
        assert out.read_bytes() == HOSTS[member.name]


def test_fetch_detects_corruption(tmp_path):
    archive = _build_zip(tmp_path / "pcap.zip")
    src = FileRanged(archive)
    member = max(read_index(src), key=lambda m: m.csize)

    header = src.read(member.local_off, 30)
    nlen, elen = struct.unpack_from("<HH", header, 26)
    flip_at = member.local_off + 30 + nlen + elen + member.csize // 2

    blob = bytearray(archive.read_bytes())
    blob[flip_at] ^= 0xFF
    corrupted = tmp_path / "corrupted.zip"
    corrupted.write_bytes(bytes(blob))

    with pytest.raises((ValueError, zlib.error)):
        fetch_member(FileRanged(corrupted), member, tmp_path / "x.pcap")


def test_selection_takes_timeline_hosts_and_seeded_benign_sample(tmp_path):
    members = read_index(FileRanged(_build_zip(tmp_path / "pcap.zip")))
    # Attacker VPC hosts (172.31.70.6) and external attackers have no members of
    # their own — tolerated; 172.31.70.4 has one — fetched.
    attackers = {"172.31.70.4", "172.31.70.6", "18.221.219.4"}
    victims = {"172.31.69.25"}

    wanted, benign = select_members(
        members, attackers, victims, benign_count=2, seed=7, date="d"
    )
    assert {m.host_ip for m in wanted} == {"172.31.69.25", "172.31.70.4"}
    assert len(benign) == 2 and all(m.host_ip.startswith("172.31.64.") for m in benign)

    _, again = select_members(members, attackers, victims, benign_count=2, seed=7, date="d")
    assert [m.name for m in again] == [m.name for m in benign], "sample must be seeded"


def test_selection_fails_loudly_when_internal_victim_member_missing(tmp_path):
    members = read_index(FileRanged(_build_zip(tmp_path / "pcap.zip")))
    with pytest.raises(SystemExit, match="172.31.69.99"):
        select_members(members, set(), {"172.31.69.99"}, benign_count=1, seed=7, date="d")
