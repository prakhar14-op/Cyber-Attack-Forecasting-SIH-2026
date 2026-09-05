"""Node identity anonymisation (M1.7, anti-leakage).

CIC-IDS-2018 attackers are ~15 fixed public IPs; a model keyed on raw identity
memorises them. This module is the only place node identity is handled:

- keyed-HMAC pseudonyms (key from the env var named in configs/data.yaml —
  missing key fails loudly, there is no default);
- per-epoch permutation of integer node ids, so an embedding row never sticks
  to one host across epochs;
- role-only node features: internal/external, hashed /24 bucket, server-like
  port profile — never the address itself;
- a held-out-attacker evaluation mode that re-domains pseudonyms for non-train
  splits, so identity memorised during training stops resolving at eval.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import random
from collections.abc import Iterable

import pandas as pd

_PSEUDONYM_HEX_CHARS = 16


class Anonymizer:
    def __init__(self, key: bytes, cfg_anon: dict):
        if not key:
            raise ValueError("anonymisation key must be non-empty")
        self._key = key
        self._networks = [
            ipaddress.ip_network(net) for net in cfg_anon["internal_networks"]
        ]
        self._n_buckets = int(cfg_anon["n_net24_buckets"])
        self._server_ports = set(int(p) for p in cfg_anon["server_ports"])
        self._heldout = bool(cfg_anon.get("heldout_attacker_ip_eval", False))

    @classmethod
    def from_config(cls, cfg: dict, env: dict | None = None) -> "Anonymizer":
        cfg_anon = cfg["anonymisation"]
        env = os.environ if env is None else env
        var = cfg_anon["key_env_var"]
        key = env.get(var, "")
        if not key:
            raise RuntimeError(
                f"anonymisation key env var '{var}' is unset — refusing to run "
                "with a default key (the key is never committed; see CLAUDE.md)"
            )
        return cls(key.encode("utf-8"), cfg_anon)

    # -- pseudonyms ---------------------------------------------------------

    def _digest(self, domain: str, payload: str) -> bytes:
        return hmac.new(
            self._key, f"{domain}:{payload}".encode("utf-8"), hashlib.sha256
        ).digest()

    def pseudonym(self, ip: str, split: str = "train") -> str:
        """Stable 16-hex pseudonym for an address. In held-out-attacker mode,
        non-train splits get a different HMAC domain, so train-time identities
        do not resolve at evaluation."""
        domain = "node"
        if self._heldout and split != "train":
            domain = "node-heldout"
        return self._digest(domain, ip).hex()[:_PSEUDONYM_HEX_CHARS]

    # -- per-epoch integer ids ---------------------------------------------

    def epoch_node_ids(
        self, ips: Iterable[str], epoch: int, seed: int, split: str = "train"
    ) -> dict[str, int]:
        """Map each address to an integer id, permuted differently every epoch.

        Deterministic for a given (key, epoch, seed); a permutation of
        range(n) for the deduplicated address set.
        """
        pseudonyms = sorted({self.pseudonym(ip, split=split): ip for ip in ips}.items())
        order = list(range(len(pseudonyms)))
        random.Random(f"{seed}:{epoch}:{self._digest('perm', str(epoch)).hex()}").shuffle(order)
        return {ip: order[i] for i, (_, ip) in enumerate(pseudonyms)}

    # -- role-only features -------------------------------------------------

    def is_internal(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._networks)

    def net24_bucket(self, ip: str) -> int:
        """Hashed bucket of the /24 prefix — coarse locality without identity."""
        prefix = ".".join(ip.split(".")[:3])
        return int.from_bytes(self._digest("net24", prefix)[:4], "big") % self._n_buckets

    def role_features(self, flows: pd.DataFrame, host_ip: str) -> dict:
        """Role-only description of one host from canonical flows.

        `flows` uses the canonical schema (src_ip/dst_ip/src_port/dst_port).
        server_port_ratio: share of the host's flows where its OWN port is a
        configured server port (listening-service behaviour).
        """
        as_src = flows[flows["src_ip"] == host_ip]
        as_dst = flows[flows["dst_ip"] == host_ip]
        n = len(as_src) + len(as_dst)
        if n == 0:
            server_ratio = 0.0
        else:
            own_ports = pd.concat([as_src["src_port"], as_dst["dst_port"]])
            server_ratio = float(own_ports.isin(self._server_ports).mean())
        return {
            "internal": int(self.is_internal(host_ip)),
            "net24_bucket": self.net24_bucket(host_ip),
            "server_port_ratio": server_ratio,
        }
