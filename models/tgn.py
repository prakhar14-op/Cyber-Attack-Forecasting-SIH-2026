"""Temporal graph network over anonymised hosts (M5).

Graph: nodes are hosts (integer ids from data.anonymize.epoch_node_ids — keyed
HMAC + per-epoch permutation, never raw IPs); edges are flows with the canonical
numeric flow features as the message.

CAUSALITY (decision-003 discipline): an edge is timestamped at the flow's END
(start + duration). A flow's whole-lifetime statistics are only known once it
completes; stamping them at the start would inject forecast-horizon traffic into
the memory — the exact leak class the M3 audit caught in the window features.

Readout: after processing all events with t < window_end, the TGN memory vector
of a host IS its per-window embedding (output [hosts, windows, memory_dim] via
snapshots). Memory is reset between splits (M5.3) and per epoch (per-epoch node
permutation composes with the reset).

`model: sage` in configs/train_tgn.yaml selects the GraphSAGE-per-window
fallback (M5.4) with the same snapshot interface.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
import torch
from torch import nn

from configs import load_config, set_seed


@dataclass
class TemporalEvents:
    """Flow edges as time-ordered events (the PyG TemporalData fields)."""

    src: torch.Tensor   # [E] long node ids
    dst: torch.Tensor   # [E] long node ids
    t: torch.Tensor     # [E] long, seconds relative to t0 (sorted ascending)
    msg: torch.Tensor   # [E, D] float32 edge features (scaled)
    t0: float           # epoch seconds of the origin
    node_of_host: dict  # real host IP -> node id (for readout; never a feature)
    num_nodes: int


def build_events(
    cfg: dict, flows: pd.DataFrame, anonymizer, epoch: int, msg_scaler
) -> TemporalEvents:
    """Flows -> TemporalEvents. Edge time = flow END; msg = scaled canonical numerics."""
    from data.flow_features import canonical_numeric_columns

    start = flows["timestamp"].map(pd.Timestamp.timestamp).to_numpy(dtype=float)
    end = start + flows["duration"].to_numpy(dtype=float) / 1e6  # duration is in us
    order = np.argsort(end, kind="stable")

    hosts = pd.unique(pd.concat([flows["src_ip"], flows["dst_ip"]], ignore_index=True))
    node_of_host = anonymizer.epoch_node_ids(hosts, epoch=epoch, seed=cfg["seed"])

    src = flows["src_ip"].map(node_of_host).to_numpy(dtype=np.int64)[order]
    dst = flows["dst_ip"].map(node_of_host).to_numpy(dtype=np.int64)[order]
    t0 = float(end[order][0])
    t = (end[order] - t0).astype(np.int64)

    msg_cols = canonical_numeric_columns(load_config("data"))  # schema lives in data.yaml
    msg = msg_scaler.transform(flows[msg_cols].to_numpy(dtype=np.float64))[order]

    return TemporalEvents(
        src=torch.from_numpy(src),
        dst=torch.from_numpy(dst),
        t=torch.from_numpy(t),
        msg=torch.from_numpy(msg.astype(np.float32)),
        t0=t0,
        node_of_host=node_of_host,
        num_nodes=len(node_of_host),
    )


class TGNHostEncoder(nn.Module):
    """TGNMemory + last-neighbour bookkeeping; memory vector = host embedding."""

    def __init__(self, cfg: dict, num_nodes: int, msg_dim: int):
        super().__init__()
        from torch_geometric.nn import TGNMemory
        from torch_geometric.nn.models.tgn import IdentityMessage, LastAggregator

        p = cfg["tgn"]
        self.memory_dim = p["memory_dim"]
        self.memory = TGNMemory(
            num_nodes,
            msg_dim,
            p["memory_dim"],
            p["time_dim"],
            message_module=IdentityMessage(msg_dim, p["memory_dim"], p["time_dim"]),
            aggregator_module=LastAggregator(),
        )
        from torch_geometric.nn.models.tgn import LastNeighborLoader

        self.neighbor_loader = LastNeighborLoader(num_nodes, size=p["num_neighbors"])
        self.link_head = nn.Sequential(
            nn.Linear(2 * p["memory_dim"], p["memory_dim"]),
            nn.ReLU(),
            nn.Linear(p["memory_dim"], 1),
        )
        self.num_nodes = num_nodes

    def reset(self):
        """M5.3: fresh memory + neighbour state (between splits and epochs)."""
        self.memory.reset_state()
        self.neighbor_loader.reset_state()

    def link_logits(self, src, pos_dst, neg_dst):
        # Query memory only for the ids this batch touches (never all nodes).
        n_id = torch.cat([src, pos_dst, neg_dst])
        uniq, inv = n_id.unique(return_inverse=True)
        mem, _ = self.memory(uniq)
        z = mem[inv]
        b = src.size(0)
        z_src, z_pos, z_neg = z[:b], z[b : 2 * b], z[2 * b :]
        pos = self.link_head(torch.cat([z_src, z_pos], dim=-1)).squeeze(-1)
        neg = self.link_head(torch.cat([z_src, z_neg], dim=-1)).squeeze(-1)
        return pos, neg


def train_link_pred(encoder: TGNHostEncoder, events: TemporalEvents, cfg: dict) -> list[float]:
    """Self-supervised link prediction over time-ordered event batches.

    Trains the memory GRU/message modules + link head. Memory is reset at each
    epoch start; state is detached between batches (standard TGN training)."""
    p = cfg["link_pred"]
    opt = torch.optim.Adam(encoder.parameters(), lr=p["lr"])
    loss_fn = nn.BCEWithLogitsLoss()
    n = events.src.size(0)
    losses = []
    g = torch.Generator().manual_seed(cfg["seed"])

    encoder.train()
    for _epoch in range(p["epochs"]):
        encoder.reset()
        epoch_loss = 0.0
        n_batches = 0
        for i in range(0, n, p["batch_size"]):
            sl = slice(i, min(i + p["batch_size"], n))
            src, dst, t, msg = (
                events.src[sl], events.dst[sl], events.t[sl], events.msg[sl],
            )
            neg_dst = torch.randint(0, events.num_nodes, (src.size(0),), generator=g)

            opt.zero_grad()
            pos, neg = encoder.link_logits(src, dst, neg_dst)
            loss = loss_fn(pos, torch.ones_like(pos)) + loss_fn(neg, torch.zeros_like(neg))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(encoder.parameters(), p["grad_clip"])
            opt.step()

            # advance state AFTER the gradient step, then cut the graph
            encoder.memory.update_state(src, dst, t, msg)
            encoder.neighbor_loader.insert(src, dst)
            encoder.memory.detach()
            epoch_loss += float(loss)
            n_batches += 1
        losses.append(epoch_loss / max(n_batches, 1))
    return losses


@torch.no_grad()
def snapshot_embeddings(
    encoder: TGNHostEncoder,
    events: TemporalEvents,
    readouts: pd.DataFrame,
    cfg: dict,
) -> np.ndarray:
    """Per-(host, window) memory embeddings, causally snapshotted.

    `readouts` has columns [host, window_start] (epoch seconds). The embedding
    for a row is the host's memory AFTER every event with end-time strictly
    before that row's window END (window_start + window_seconds) — never after.
    Returns [len(readouts), memory_dim] float32, rows aligned to `readouts`.
    """
    data_cfg = load_config("data")
    window_sec = data_cfg["windows"]["window_seconds"]

    encoder.eval()
    encoder.reset()

    if events.num_nodes > encoder.num_nodes:
        raise ValueError(
            f"split has {events.num_nodes} hosts but the encoder's memory holds "
            f"{encoder.num_nodes} — rebuild/train the encoder with enough node "
            "capacity (a frozen train-sized artifact cannot index new hosts)"
        )

    node_ids = readouts["host"].map(events.node_of_host)
    known = node_ids.notna().to_numpy()
    node_ids = node_ids.fillna(0).to_numpy(dtype=np.int64)
    read_t = readouts["window_start"].to_numpy(dtype=float) + window_sec - events.t0

    out = np.zeros((len(readouts), encoder.memory_dim), dtype=np.float32)
    ev_t = events.t.numpy()
    n_events = len(ev_t)
    batch = int(cfg["link_pred"]["batch_size"])
    ptr = 0

    # Group rows sharing the same readout time: one batched memory query per
    # distinct window end instead of one per row.
    order = np.argsort(read_t, kind="stable")
    i = 0
    while i < len(order):
        j = i
        while j < len(order) and read_t[order[j]] == read_t[order[i]]:
            j += 1
        rows = order[i:j]
        target = read_t[rows[0]]

        while ptr < n_events and ev_t[ptr] < target:
            end = min(ptr + batch, n_events)
            while end > ptr and ev_t[end - 1] >= target:
                end -= 1
            if end == ptr:
                end = ptr + int(np.searchsorted(ev_t[ptr:], target, side="left"))
            sl = slice(ptr, end)
            encoder.memory.update_state(
                events.src[sl], events.dst[sl], events.t[sl], events.msg[sl]
            )
            encoder.neighbor_loader.insert(events.src[sl], events.dst[sl])
            ptr = end

        live = rows[known[rows]]
        if len(live):
            uniq, inv = torch.tensor(node_ids[live]).unique(return_inverse=True)
            mem, _ = encoder.memory(uniq)
            out[live] = mem[inv].numpy()
        i = j
    return out


def build_model(cfg: dict, num_nodes: int = 64, msg_dim: int = 19) -> nn.Module:
    """The M5 model-construction API (used by tests and the harness)."""
    set_seed(cfg["seed"])
    if cfg.get("model", "tgn") == "sage":
        return SAGEHostEncoder(cfg, msg_dim)
    return TGNHostEncoder(cfg, num_nodes=num_nodes, msg_dim=msg_dim)


class SAGEHostEncoder(nn.Module):
    """GraphSAGE-per-window fallback (M5.4): same snapshot interface.

    For each readout window, build the graph of flows that ENDED in the last
    `window_seconds` and run 2-layer SAGE over mean-aggregated edge messages.
    Deliberately simple — it exists so the pipeline never blocks on TGN
    stability (BUILD_PLAN stop condition)."""

    def __init__(self, cfg: dict, msg_dim: int):
        super().__init__()
        from torch_geometric.nn import SAGEConv

        p = cfg["sage"]
        self.memory_dim = p["embed_dim"]
        self.conv1 = SAGEConv(msg_dim, p["hidden_dim"])
        self.conv2 = SAGEConv(p["hidden_dim"], p["embed_dim"])

    def reset(self):  # stateless — interface parity with TGNHostEncoder
        pass
