"""Independent Python implementation of the Jounit wire format (SPEC.md section 13).

This is the same discipline as ``sim/jounit_reference.py`` for the PoW puzzle:
a second implementation written from the *prose* of the specification rather
than from the Rust source, so that a disagreement points at the spec instead of
at either implementation.

Why it matters here. A round-trip test only proves a codec agrees with itself.
If ``VERSION`` encoded ``user_agent`` before ``protocol_version`` and the decoder
read them in the same wrong order, every round-trip test in the crate passes and
two implementations of section 13.5 silently desync -- which looks exactly like a
consensus split. ``tests/vectors/net_vectors.json`` pins the bytes, but that file
is generated *from* the Rust, so it cannot catch a bug that is in both.

    python sim/net_reference.py            # cross-check against the vectors
    python sim/net_reference.py --show     # print the derived bytes

What this can and cannot check. Everything the wire format defines from a spec
constant: the frame envelope, every ``msg_type`` payload, ``VERSION`` for both
profiles, and the section 13.8 bounds. It cannot check ``block1`` or the locator
entries, because those values come from mining blocks on a real chain -- that
needs a Rust node, not a second implementation. Those are named in
``SKIPPED`` so the gap is stated rather than glossed over.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "net_vectors.json"

# --- SPEC.md section 13.5: frozen message numbers -------------------------
MSG_VERSION = 1
MSG_VERACK = 2
MSG_PING = 3
MSG_PONG = 4
MSG_INV = 5
MSG_GETDATA = 6
MSG_BLOCK = 7
MSG_GETBLOCKS = 8
MSG_ADDR = 9

# --- SPEC.md section 13.3: per-profile identity ---------------------------
# A new profile MUST pick a magic no existing profile uses.
NETWORK_MAGIC = {
    "mainnet": bytes([0x6A, 0x4E, 0x54, 0x01]),
    "mini": bytes([0x6A, 0x4E, 0x54, 0x02]),
}
NETWORK_ID = {
    "mainnet": b"jounit/mainnet",
    "mini": b"jounit/mini",
}

# --- SPEC.md section 13.8: resource bounds --------------------------------
MAX_FRAME_BYTES = 4_100_000
MAX_INV_PER_MSG = 500
MAX_ADDR_PER_MSG = 100
MAX_LOCATOR_LEN = 500
MAX_PEERS = 125
MAX_INBOUND = 32
HANDSHAKE_TIMEOUT_S = 20
BAN_SCORE_THRESHOLD = 100
ORPHAN_POOL_MAX = 64

# section 13.5: kind 1 = block in v0.2; 0 reserved for transactions.
INV_TYPE_BLOCK = 1
PROTOCOL_VERSION = 1


# --- encoders, written from the field tables in section 13 ----------------


def u16le(n: int) -> bytes:
    return n.to_bytes(2, "little")


def u32le(n: int) -> bytes:
    return n.to_bytes(4, "little")


def u64le(n: int) -> bytes:
    return n.to_bytes(8, "little")


def frame(magic: bytes, msg_type: int, payload: bytes) -> bytes:
    """frame = magic(4) | msg_type(1) | payload_len(4 LE) | payload"""
    if len(magic) != 4:
        raise ValueError("magic must be 4 bytes")
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError(f"payload {len(payload)} exceeds max_frame_bytes")
    return magic + bytes([msg_type]) + u32le(len(payload)) + payload


def version_payload(
    network: str,
    height: int,
    tip_hash: bytes,
    user_agent: bytes = b"/jnt-net:0.2",
    nonce: int = 0x0123_4567_89AB_CDEF,
    services: int = 1,
) -> bytes:
    """VERSION -- SPEC.md section 13.4, in the order the table lists."""
    network_id = NETWORK_ID[network]
    if len(network_id) > 255:
        raise ValueError("network_id does not fit a 1-byte length prefix")
    if len(user_agent) > 255:
        raise ValueError("user_agent does not fit a 1-byte length prefix")
    if len(tip_hash) != 32:
        raise ValueError("tip_hash must be 32 bytes")
    out = NETWORK_MAGIC[network]
    out += bytes([len(network_id)]) + network_id
    out += u32le(PROTOCOL_VERSION)
    out += u64le(services)
    out += u64le(height)
    out += tip_hash
    out += bytes([len(user_agent)]) + user_agent
    out += u64le(nonce)
    return out


def nonce_payload(nonce: int) -> bytes:
    """VERACK / PING / PONG all carry a bare echoed nonce."""
    return u64le(nonce)


def inv_payload(entries: list[tuple[int, bytes]]) -> bytes:
    """INV / GETDATA: count(2 LE) | count x (kind(1) | hash(32))."""
    if len(entries) > MAX_INV_PER_MSG:
        raise ValueError(f"inv count {len(entries)} exceeds max_inv_per_msg")
    out = u16le(len(entries))
    for kind, h in entries:
        if len(h) != 32:
            raise ValueError("inv hash must be 32 bytes")
        out += bytes([kind]) + h
    return out


def getblocks_payload(locator: list[bytes], stop: bytes) -> bytes:
    """GETBLOCKS: count(2 LE) | count x locator(32) | stop_hash(32)."""
    if len(locator) > MAX_LOCATOR_LEN:
        raise ValueError(f"locator count {len(locator)} exceeds max_locator_len")
    if len(stop) != 32:
        raise ValueError("stop_hash must be 32 bytes")
    return u16le(len(locator)) + b"".join(locator) + stop


def addr_payload(addrs: list[tuple[bytes, int]]) -> bytes:
    """ADDR: count(2 LE) | count x (port(2 LE) | ip(16))."""
    if len(addrs) > MAX_ADDR_PER_MSG:
        raise ValueError(f"addr count {len(addrs)} exceeds max_addr_per_msg")
    out = u16le(len(addrs))
    for ip, port in addrs:
        if len(ip) != 16:
            raise ValueError("addr ip must be 16 bytes (IPv6-mapped IPv4)")
        out += u16le(port) + ip
    return out


def ipv4_mapped(a: str, b: str, c: str, d: str) -> bytes:
    """::ffff:a.b.c.d -- the representation section 13.5 requires."""
    return bytes(10) + bytes([0xFF, 0xFF]) + bytes([a, b, c, d])


# --- the values net_vectors.json pins -------------------------------------

TIP = bytes([0x5A]) * 32


def derived_items() -> dict[str, str]:
    mini = NETWORK_MAGIC["mini"]
    items: dict[str, str] = {}
    items["frame_inv_type7_len3"] = frame(mini, MSG_BLOCK, b"jnt").hex()
    for net in ("mainnet", "mini"):
        items[f"version_{net}"] = version_payload(net, 42, TIP).hex()
    items["msg_verack"] = nonce_payload(0xDEAD).hex()
    items["msg_ping"] = nonce_payload(0xBEEF).hex()
    items["msg_pong"] = nonce_payload(0xFEED).hex()
    items["msg_inv"] = inv_payload(
        [(INV_TYPE_BLOCK, bytes([0x11]) * 32), (INV_TYPE_BLOCK, bytes([0x22]) * 32)]
    ).hex()
    items["msg_getdata"] = inv_payload([(INV_TYPE_BLOCK, bytes([0x33]) * 32)]).hex()
    items["msg_getblocks"] = getblocks_payload(
        [bytes([0x44]) * 32, bytes([0x55]) * 32], bytes([0x66]) * 32
    ).hex()
    items["msg_addr"] = addr_payload([(ipv4_mapped(127, 0, 0, 1), 8333)]).hex()
    return items


def derived_facts() -> dict[str, int]:
    mini = NETWORK_MAGIC["mini"]
    return {
        "version_mainnet_len": len(version_payload("mainnet", 42, TIP)),
        "version_mini_len": len(version_payload("mini", 42, TIP)),
        "verack_len": len(nonce_payload(0xDEAD)),
        "ping_len": len(nonce_payload(0xBEEF)),
        "pong_len": len(nonce_payload(0xFEED)),
        "inv_len": len(
            inv_payload([(INV_TYPE_BLOCK, bytes([0x11]) * 32), (INV_TYPE_BLOCK, bytes([0x22]) * 32)])
        ),
        "getdata_len": len(inv_payload([(INV_TYPE_BLOCK, bytes([0x33]) * 32)])),
        "getblocks_len": len(
            getblocks_payload([bytes([0x44]) * 32, bytes([0x55]) * 32], bytes([0x66]) * 32)
        ),
        "addr_len": len(addr_payload([(ipv4_mapped(127, 0, 0, 1), 8333)])),
        "max_frame_payload": MAX_FRAME_BYTES,
        "max_inv_per_msg": MAX_INV_PER_MSG,
        "max_addr_per_msg": MAX_ADDR_PER_MSG,
        "max_locator_len": MAX_LOCATOR_LEN,
    }


# Chain-derived values: a second implementation cannot produce these without
# mining a real chain, so they are reported as skipped rather than passed over.
SKIPPED = {
    "block1": "a mined block -- needs the Rust puzzle, not a second encoder",
    "locator_N": "derived from a 200-block chain",
    "locator_len_200": "derived from a 200-block chain",
    "inv_from_genesis_first": "derived from a 200-block chain",
    "inv_from_genesis_len": "derived from a 200-block chain",
}


def crosscheck() -> int:
    if not VECTORS.exists():
        print(f"missing {VECTORS}\nregenerate with UPDATE_NET_VECTORS=1 cargo test -p jnt-net")
        return 1
    doc = json.loads(VECTORS.read_text())
    pinned = {e["name"]: e["hex"] for e in doc["items"]}
    pinned_facts = {f["name"]: f["value"] for f in doc["facts"]}

    problems: list[str] = []
    checked = 0

    for name, want in derived_items().items():
        if name not in pinned:
            problems.append(f"{name}: pinned file has no such entry")
            continue
        if pinned[name] != want:
            problems.append(
                f"{name}:\n    rust   {pinned[name]}\n    python {want}"
            )
        else:
            checked += 1

    for name, want in derived_facts().items():
        if name not in pinned_facts:
            problems.append(f"fact {name}: pinned file has no such entry")
            continue
        if pinned_facts[name] != want:
            problems.append(f"fact {name}: rust {pinned_facts[name]} != python {want}")
        else:
            checked += 1

    # section 13.3: the two live profiles MUST differ in both discriminators.
    if NETWORK_MAGIC["mainnet"] == NETWORK_MAGIC["mini"]:
        problems.append("mainnet and mini share a network_magic (13.3)")
    if NETWORK_ID["mainnet"] == NETWORK_ID["mini"]:
        problems.append("mainnet and mini share a network_id (13.3)")
    if NETWORK_MAGIC["mainnet"] == bytes(4) or NETWORK_MAGIC["mini"] == bytes(4):
        problems.append("a profile declares an all-zero magic (13.3)")

    print(f"cross-checked {checked} wire-format values against the Rust vectors")
    print(f"skipped {len(SKIPPED)} chain-derived values (need a real node):")
    for name, why in sorted(SKIPPED.items()):
        if name in pinned or any(k.startswith(name.split("_")[0]) for k in pinned):
            print(f"    - {name}: {why}")

    if problems:
        print(f"\nFAILED ({len(problems)}):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nwire format agrees byte-for-byte with the Rust implementation")
    return 0


def show() -> None:
    for name, h in derived_items().items():
        print(f"{name:<24}{h}")
    print()
    for name, v in derived_facts().items():
        print(f"{name:<24}{v}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--show", action="store_true", help="print derived values and exit")
    args = ap.parse_args()
    if args.show:
        show()
        return 0
    return crosscheck()


if __name__ == "__main__":
    sys.exit(main())
