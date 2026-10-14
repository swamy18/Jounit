//! Jounit node CLI.
//!
//! Commands operate on a chain directory (`--data-dir`, default `./chain`):
//!
//! ```text
//! jnt-node init      --network mini --wallet <name>   create the chain + a miner wallet
//! jnt-node mine      --blocks 100                     mine N blocks
//! jnt-node status                                 height, tip, supply, difficulty
//! jnt-node verify                                 replay the chain and diff the state
//! jnt-node show-block --height 10
//! jnt-node balance  --address jt1...
//! jnt-node send     --to jt1... --amount 1000       build a tx, mine it, keep it
//!                                                   (--amount is in satoshis)
//! jnt-node wallet   --new --label miner
//! jnt-node export   --out chain.json
//! jnt-node serve     --listen 0.0.0.0:8333         relay blocks to and from peers
//! ```
//!
//! A `serve` subcommand runs the P2P node (`jnt-net`); everything else operates
//! on a local chain directory. See `docs/roadmap.md` for what a real node still
//! needs.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use jnt_core::block::Block;
use jnt_core::chain::Chain;
use jnt_core::hash::{
    address_from_hex, address_to_hex, hash512_to_hex, hash_to_hex, Hash512,
};
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::supply::{block_reward_sat, cumulative_supply_sat, halvings, max_issuance_sat};
use jnt_core::tx::{OutPoint, Output, Transaction};
use jnt_core::wallet::Wallet;
use jnt_net::frame::write_frame;
use jnt_net::msg::{Message, MessageType};
use jnt_net::net::{NodeState, P2pConfig, P2pNode};
use jnt_net::peer::{perform_handshake, HandshakeConfig};
use jnt_net::relay::RelayManager;
use jnt_net::syncer::SyncManager;
use jnt_node::l2::NodeL2;
use jnt_store::{AppendOutcome, BlockStore};
use std::io::Write as _;

const USAGE: &str = "\
jnt-node - Jounit base-layer node

USAGE:
  jnt-node <COMMAND> [OPTIONS]

COMMANDS:
  init      Create a chain directory, a miner wallet and the genesis block
  mine      Mine blocks and extend the chain
  send      Spend from a wallet address, local or over P2P
  status    Print chain tip, difficulty, supply and wallet balance
  verify    Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance   List the unspent outputs of an address
  wallet    Create or list wallets
  export    Write the canonical chain to JSON
  serve     Run a P2P node (block relay, multi-peer sync)
  validator Manage checkpoint-signing keys (M5 binding finality)
  help      This text

SEND OPTIONS:
  --to <address>             Recipient (required)
  --amount <sat>             Amount to send (required)
  --relay <host:port>        Hand the signed transaction to a running node
                             instead of mining it here; the node's mempool
                             holds it and relays it to its peers
  --fee <sat>                Override the computed fee

COMMON OPTIONS:
  --network <mainnet|mini>   Default: mini
  --data-dir <path>          Default: ./chain

SERVE OPTIONS:
  --listen <host:port>       TCP address to accept inbound peers (optional)
  --api-listen <host:port>   Start the opt-in REST service API (disabled by
                             default; loopback expected — see SPEC.md §19.2)
  --connect <host:port>      Dial an outbound peer (repeatable via CSV)
  --peers <n>                Max total peers (default: 125)
  --interval <ms>            Serve loop period (default: 250)
  --no-mine                  Relay and validate only, never mine
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Args {
    network: String,
    data_dir: PathBuf,
    flags: BTreeMap<String, String>,
    switches: Vec<String>,
}

impl Args {
    fn parse(raw: &[String]) -> Result<Self, String> {
        let mut out = Args {
            network: "mini".into(),
            data_dir: PathBuf::from("chain"),
            flags: BTreeMap::new(),
            switches: Vec::new(),
        };
        let mut i = 0;
        while i < raw.len() {
            let a = &raw[i];
            if let Some(name) = a.strip_prefix("--") {
                // Flags that take a value; everything else is a boolean switch.
                let takes_value = matches!(
                    name,
                    "network"
                        | "data-dir"
                        | "blocks"
                        | "amount"
                        | "to"
                        | "address"
                        | "wallet"
                        | "label"
                        | "height"
                        | "out"
                        | "from"
                        | "interval"
                        | "fee"
                        | "listen"
                        | "api-listen"
                        | "connect"
                        | "peers"
                        | "relay"
                );
                if takes_value {
                    let value = raw
                        .get(i + 1)
                        .ok_or_else(|| format!("--{name} needs a value"))?;
                    match name {
                        "network" => out.network = value.clone(),
                        "data-dir" => out.data_dir = PathBuf::from(value),
                        _ => {
                            out.flags.insert(name.to_string(), value.clone());
                        }
                    }
                    i += 2;
                } else {
                    out.switches.push(name.to_string());
                    i += 1;
                }
            } else if a == "-h" {
                out.switches.push("help".into());
                i += 1;
            } else {
                return Err(format!("unexpected argument `{a}`"));
            }
        }
        Ok(out)
    }

    fn str(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(|s| s.as_str())
    }

    /// True when the user asked for help rather than for work.
    ///
    /// `--help` parses as a boolean switch, but `-h` is not `--`-prefixed and
    /// would otherwise be rejected as an unexpected argument.
    fn wants_help(&self) -> bool {
        self.switches.iter().any(|s| s == "help")
    }

    fn str_or(&self, name: &str, default: &str) -> String {
        self.str(name).unwrap_or(default).to_string()
    }

    fn num(&self, name: &str, default: u64) -> Result<u64, String> {
        match self.flags.get(name) {
            Some(v) => v.parse().map_err(|_| format!("--{name} must be a number")),
            None => Ok(default),
        }
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    fn params(&self) -> Result<NetworkParams, String> {
        NetworkParams::by_name(&self.network).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

struct Store {
    dir: PathBuf,
    params: NetworkParams,
    /// The append-only block store. Opened lazily alongside the JSON chain
    /// during migration; once present it is the authoritative block data.
    block_store: Option<BlockStore>,
}

impl Store {
    fn open(args: &Args) -> Result<Self, String> {
        let params = args.params()?;
        Ok(Store {
            dir: args.data_dir.clone(),
            params,
            block_store: None,
        })
    }

    fn chain_path(&self) -> PathBuf {
        self.dir.join("blocks.json")
    }

    fn wallets_path(&self) -> PathBuf {
        self.dir.join("wallets.json")
    }

    /// Directory holding validator key files, one per `.json` file. Created on
    /// demand so `validator add` never fails on a fresh data dir, and never
    /// confused with `wallets.json`, which holds *spending* keys.
    fn validator_keys_path(&self) -> PathBuf {
        self.dir.join("validators")
    }

    fn meta_path(&self) -> PathBuf {
        // The jnt-store metadata. blocks.json is legacy; this is what the
        // append-only store reads.
        self.dir.join("meta.json")
    }

    /// Open the append-only store, migrating `blocks.json` if it exists and
    /// the store does not.
    fn ensure_block_store(&mut self) -> Result<&mut BlockStore, String> {
        if self.block_store.is_none() {
            let legacy = self.chain_path();
            let store_dir = self.dir.join("store");
            let fresh = !store_dir.join("blocks.log").exists();
            let (mut bs, recovery) =
                BlockStore::open(&store_dir, &self.params).map_err(|e| e.to_string())?;
            if !recovery.truncated {
                // recovery handled below via bs.recovery()
            }
            if fresh && legacy.exists() {
                // One-time migration: read every block from the JSON chain and
                // append it, then mark the store's tip at the JSON tip. The
                // JSON file is kept until the migration is verified on the
                // next open, then left in place (harmless, and deleting a
                // user's chain file automatically is not a decision a node
                // makes silently).
                let text = fs::read_to_string(&legacy).map_err(|e| e.to_string())?;
                let blocks: Vec<Block> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
                for b in &blocks {
                    bs.append_block(b).map_err(|e| e.to_string())?;
                }
                if let Some(last) = blocks.last() {
                    bs.set_tip(&last.block_hash()).map_err(|e| e.to_string())?;
                }
                bs.sync().map_err(|e| e.to_string())?;
                println!(
                    "migrated {} blocks from blocks.json into the append-only store",
                    blocks.len()
                );
            }
            let rec = bs.recovery();
            if rec.discarded_tail_bytes > 0 {
                println!(
                    "store recovered: {} record(s), dropped {} byte torn tail",
                    rec.records, rec.discarded_tail_bytes
                );
            }
            self.block_store = Some(bs);
        }
        Ok(self.block_store.as_mut().expect("just set"))
    }

    fn load_chain(&mut self) -> Result<Chain, String> {
        // The block store is the source of truth once it exists. Every stored
        // block is re-validated on load by `Chain::submit`, so a store bug that
        // hands the chain a bad block fails here, not silently.
        let params = self.params.clone();
        let mut chain = Chain::new(params).map_err(|e| e.to_string())?;
        {
            let bs = self.ensure_block_store()?;
            let (_tip, height) = bs.tip();
            for h in 1..=height {
                let block = bs
                    .block_at_height(h)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("store has no block at canonical height {h}"))?;
                chain.submit(block).map_err(|e| e.to_string())?;
            }
            // Binding finality (Decision 12) survives restart: restore the
            // persisted point, but only onto the exact canonical block the
            // chain just replayed — `restore_finality` refuses anything else,
            // so a stale or forged metadata row cannot finalize a block the
            // chain does not hold.
            if let Some((fh, fhash)) = bs.finalized() {
                if !chain.restore_finality(fh, fhash) {
                    return Err(format!(
                        "persisted finalized point {fh} does not match the canonical chain"
                    ));
                }
            }
        }
        Ok(chain)
    }

    /// Append new blocks and move the canonical tip. O(new blocks), not O(chain).
    fn save_chain(&mut self, chain: &Chain) -> Result<(), String> {
        let bs = self.ensure_block_store()?;
        let (_, stored_height) = bs.tip();
        for h in stored_height + 1..=chain.height() {
            let block = chain
                .block_at(h)
                .ok_or_else(|| format!("chain has no block at height {h}"))?;
            let outcome = bs.append_block(block).map_err(|e| e.to_string())?;
            match outcome {
                AppendOutcome::Stored | AppendOutcome::Duplicate => {
                    bs.set_tip(&block.block_hash()).map_err(|e| e.to_string())?;
                }
                AppendOutcome::Orphaned => {
                    return Err(format!(
                        "block at height {h} has no stored parent; refusing to advance the tip"
                    ))
                }
            }
        }
        bs.sync().map_err(|e| e.to_string())
    }

    fn load_wallets(&self) -> Result<Vec<Wallet>, String> {
        let path = self.wallets_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }

    fn save_wallets(&self, wallets: &[Wallet]) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let text = serde_json::to_string_pretty(wallets).map_err(|e| e.to_string())?;
        fs::write(self.wallets_path(), text).map_err(|e| e.to_string())
    }

    fn write_meta(&self, chain: &Chain) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let meta = serde_json::json!({
            "network": self.params.name,
            "genesis_hash": hash512_to_hex(&chain.block_hash_at(0).unwrap_or([0u8; 64])),
            "height": chain.height(),
        });
        let text = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
        fs::write(self.meta_path(), text).map_err(|e| e.to_string())
    }

    /// Persist the chain's binding-finalized point if it advanced (Decision 12).
    ///
    /// A checkpoint moves finality without moving the tip, so this runs on its
    /// own condition, not on the height-change condition. Blocks are saved
    /// first — a finalized height must always be provable from stored history.
    /// Idempotent: an unchanged point is a no-op, and the store refuses any
    /// regressing or conflicting write.
    fn persist_finality(&mut self, chain: &Chain) -> Result<(), String> {
        let Some((fh, fhash)) = chain.finalized_point() else {
            return Ok(());
        };
        let bs = self.ensure_block_store()?;
        if bs.finalized() == Some((fh, fhash)) {
            return Ok(());
        }
        if bs.tip().1 < fh {
            // The blocks below the finalized height are not stored yet (a
            // checkpoint arrived in the same batch as the blocks it finalizes).
            // Save them first; `set_finalized` proves against stored history.
            self.save_chain(chain)?;
        }
        let bs = self.ensure_block_store()?;
        bs.set_finalized(fh, fhash).map_err(|e| e.to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn jnt(sat: u64) -> String {
    format!("{}.{:08}", sat / SAT_PER_JNT, sat % SAT_PER_JNT)
}

/// One-line L2 summary shared by every command that moves the tip.
///
/// This is the whole of the node's L2 observability for M1: which height was
/// replayed to, how many payloads applied, how many were refused. The reasons
/// for each refusal live in `NodeL2::skipped` (height, txid, named error); a
/// full REST surface for them belongs to the M3 transport milestone, not here.
fn print_l2_summary(l2: &NodeL2, chain: &Chain) {
    let s = l2.status(chain.height());
    println!(
        "l2             height {}  applied {}  skipped {}{}  deposits {} credited / {} pending / {} ignored",
        s.l2_height,
        s.applied,
        s.skipped,
        if s.clean { "" } else { " (see verify)" },
        s.deposits_applied,
        s.deposits_pending,
        s.deposits_ignored,
    );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn run(raw: &[String]) -> Result<(), String> {
    let command = raw[0].clone();
    let args = Args::parse(&raw[1..])?;

    // `--help` and `-h` anywhere on the line means help, not work. Without
    // this, `mine --help` opened a chain directory and failed on a fresh
    // checkout, which reads like a broken install rather than a help request.
    if args.wants_help() {
        println!("{USAGE}");
        return Ok(());
    }

    match command.as_str() {
        "init" => cmd_init(&args),
        "mine" => cmd_mine(&args),
        "send" => cmd_send(&args),
        "status" => cmd_status(&args),
        "verify" => cmd_verify(&args),
        "show-block" => cmd_show_block(&args),
        "balance" => cmd_balance(&args),
        "wallet" => cmd_wallet(&args),
        "export" => cmd_export(&args),
        "validator" => cmd_validator(&args),
        "serve" => cmd_serve(&args),
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn cmd_init(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    if store.chain_path().exists() || store.dir.join("store/blocks.log").exists() {
        return Err(format!(
            "{} already holds a chain; delete it to start over",
            store.dir.display()
        ));
    }
    let chain = Chain::new(store.params.clone()).map_err(|e| e.to_string())?;

    let mut wallets = Vec::new();
    let label = args.str_or("label", "miner");
    let w = Wallet::new_random(&label);
    println!("wallet `{}`", w.label);
    println!(
        "  address  {}",
        address_to_hex(&w.address().map_err(|e| e.to_string())?)
    );
    println!(
        "  pubkey   {}",
        w.public_key_hex().map_err(|e| e.to_string())?
    );
    wallets.push(w);
    store.save_wallets(&wallets)?;

    store.save_chain(&chain)?;
    store.write_meta(&chain)?;

    println!();
    println!("network        {}", store.params.name);
    println!("genesis        {}", hash512_to_hex(&chain.tip_hash()));
    println!("block time     {} ms", store.params.target_block_time_ms);
    println!(
        "issuance       ladder then a permanent tail; rate-anchored at 1% of issued per halving period (no stock cap, Decision 18)"
    );
    println!(
        "ladder reachable {} JNT",
        max_issuance_sat(&store.params) / SAT_PER_JNT
    );
    println!("data dir       {}", store.dir.display());
    Ok(())
}

fn cmd_mine(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    // The L2 view starts from replaying what is stored, then follows the tip
    // as blocks are mined below. Genesis-funded accounts apply; genuinely
    // unfunded payloads are expected `InsufficientBalance` skips, not errors
    // — the view still advances and still names what it refused.
    let mut l2 = NodeL2::replay_from(&chain, &store.params);
    let wallets = store.load_wallets()?;
    if wallets.is_empty() {
        return Err("no wallet in this data dir".into());
    }
    let miner_label = args.str_or("wallet", &wallets[0].label.clone());
    let miner = wallets
        .iter()
        .find(|w| w.label == miner_label)
        .ok_or_else(|| format!("no wallet labelled `{miner_label}`"))?;
    let address = miner.address().map_err(|e| e.to_string())?;

    let count = args.num("blocks", 1)?;
    let interval = args.num("interval", 0)?;
    let mut mined = 0u64;
    for _ in 0..count {
        let block = chain
            .mine_block(address, vec![], now_ms())
            .map_err(|e| e.to_string())?;
        let hash = block.block_hash();
        let height = block.header.height;
        let difficulty = block.header.difficulty;
        chain.submit(block).map_err(|e| e.to_string())?;
        // `submit` accepted the block, so the L2 view follows it. A block the
        // L1 layer rejects never moves the tip and therefore never reaches the
        // view — that ordering is what keeps rejected blocks from mutating L2
        // state.
        l2.sync(&chain);
        println!(
            "height {:>6}  diff {:>10}  reward {:>12} JNT  {}",
            height,
            difficulty,
            jnt(block_reward_sat(chain.params(), height)),
            &hash512_to_hex(&hash)[..16]
        );
        mined += 1;
        if interval > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval));
        }
    }
    store.save_chain(&chain)?;
    store.write_meta(&chain)?;
    println!("mined {mined} block(s); tip height {}", chain.height());
    print_l2_summary(&l2, &chain);
    Ok(())
}

fn cmd_send(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let mut chain = store.load_chain()?;
    let wallets = store.load_wallets()?;
    if wallets.is_empty() {
        return Err("no wallet in this data dir".into());
    }

    let from_label = args.str_or("wallet", &wallets[0].label.clone());
    let sender = wallets
        .iter()
        .find(|w| w.label == from_label)
        .ok_or_else(|| format!("no wallet labelled `{from_label}`"))?;
    let from = sender.address().map_err(|e| e.to_string())?;

    let to = address_from_hex(args.str("to").ok_or("--to <address> is required")?)
        .map_err(|e| e.to_string())?;
    let amount = args.num("amount", 0)?;
    if amount == 0 {
        return Err("--amount must be greater than zero (in satoshis)".into());
    }

    // Only matured coinbase outputs are spendable in v0.1.
    let candidates: Vec<(OutPoint, u64)> = chain
        .utxo()
        .iter()
        .filter(|(_, u)| u.out.address == from && chain.is_mature(u.height))
        .map(|(op, u)| (op, u.out.value))
        .collect();
    if candidates.is_empty() {
        return Err(format!(
            "no mature outputs for {} (a coinbase needs {} blocks)",
            address_to_hex(&from),
            chain.params().coinbase_maturity
        ));
    }

    let base_fee = chain.expected_base_fee_for_next_block();

    // Gather inputs until `amount + fee` is covered. The fee depends on the
    // number of inputs, and the input count depends on the fee, so this settles
    // by iteration rather than in one guess.
    let fee_override = args.num("fee", 0)?;
    let mut chosen: Vec<OutPoint> = Vec::new();
    let mut total = 0u64;
    for (op, value) in candidates {
        let gas = 16_000 + 1_000 * (chosen.len() + 1) as u64 + 250 * 2;
        let fee = if fee_override > 0 {
            fee_override
        } else {
            base_fee.saturating_mul(gas).saturating_add(1_000)
        };
        if total >= amount + fee {
            break;
        }
        total += value;
        chosen.push(op);
    }
    let gas = 16_000 + 1_000 * chosen.len() as u64 + 250 * 2;
    let fee = if fee_override > 0 {
        fee_override
    } else {
        base_fee.saturating_mul(gas).saturating_add(1_000)
    };
    if total < amount + fee {
        return Err(format!(
            "insufficient funds: have {total} sat, need {} sat",
            amount + fee
        ));
    }

    let change = total - amount - fee;
    let mut outputs = vec![Output {
        value: amount,
        address: to,
    }];
    if change > 0 {
        outputs.push(Output {
            value: change,
            address: from,
        });
    }

    let tx = sender
        .build_tx(&chosen, outputs, fee)
        .map_err(|e| e.to_string())?;
    let txid = jnt_core::hash::hash512_to_hex(&tx.txid());

    // `--relay <addr>` hands the signed transaction to a running node over the
    // real P2P protocol instead of mining it here (SPEC.md §13.14). Without it
    // there was no way to get a locally built transaction into a node's pool at
    // all: this command mined it straight into a block, so the wallet path was
    // "build a transaction, then be your own miner", and the relay path was only
    // reachable from another node. A transaction that never enters the pool
    // cannot be relayed, cannot be replaced by a better fee, and cannot be seen
    // by any peer before it is already confirmed.
    //
    // Mining in place is kept as the default for the ordinary case of a single
    // node with no peers, where there is nothing to relay to and no mempool for
    // anything else to fill.
    if let Some(relay_addr) = args.str("relay") {
        let relay_addr: std::net::SocketAddr = relay_addr
            .parse()
            .map_err(|e| format!("--relay `{relay_addr}`: {e}"))?;
        relay_transaction(relay_addr, &chain, &tx)?;
        println!("txid    {txid}");
        println!("relayed to {relay_addr} (not mined here; the node's mempool holds it)");
        println!("amount  {} JNT", jnt(amount));
        println!("fee     {} JNT", jnt(fee));
        return Ok(());
    }

    let block = chain
        .mine_block(from, vec![tx], now_ms())
        .map_err(|e| e.to_string())?;
    let height = block.header.height;
    let burned = block.header.base_fee_sat * block.txs[1].gas_used();
    chain.submit(block).map_err(|e| e.to_string())?;
    let l2 = NodeL2::replay_from(&chain, &store.params);
    store.save_chain(&chain)?;
    store.write_meta(&chain)?;

    println!("txid    {txid}");
    println!("height  {height}");
    println!("amount  {} JNT", jnt(amount));
    println!("fee     {} JNT", jnt(fee));
    println!("burned  {} JNT (base fee, destroyed)", jnt(burned));
    print_l2_summary(&l2, &chain);
    Ok(())
}

/// Hand a signed transaction to a running node.
///
/// Deliberately the smallest client that can do this: connect, complete the
/// §13.4 handshake, send `TX`, keep the connection open long enough for the node
/// to read the frame, close. No `INV` first — the node admits a `TX` whether or
/// not it asked for it, which is what lets a wallet that was never in the
/// announcement path contribute one.
///
/// It does **not** read a reply, because the protocol has no `TX` acknowledgement
/// to read: admission is silent, and the node announces the txid to *its* peers
/// rather than back to the sender. That is honest about what this can promise —
/// the transaction reached a node, not that the node accepted it. `status` on
/// that node is the check, and the sender still owns the outputs until a block
/// spends them.
fn relay_transaction(
    addr: std::net::SocketAddr,
    chain: &Chain,
    tx: &Transaction,
) -> Result<(), String> {
    use std::io::Write;

    let params = chain.params().clone();
    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10))
            .map_err(|e| format!("relay connect {addr}: {e}"))?;
    let cfg = HandshakeConfig::new(params.clone(), chain.height(), chain.tip_hash());
    perform_handshake(&mut stream, &cfg, true).map_err(|e| format!("relay handshake: {e}"))?;

    let payload = Message::Tx(Box::new(tx.clone())).encode();
    write_frame(&mut stream, &params, MessageType::Tx as u8, &payload)
        .map_err(|e| format!("relay send: {e}"))?;
    stream.flush().map_err(|e| e.to_string())?;

    // Closing immediately after a write is normally safe — TCP delivers what was
    // written before the FIN — but the node's side of this is a thread that may
    // not have been scheduled yet, and a connection that lands in the backlog and
    // is then reset is a transaction the sender believes it sent. One short pause
    // turns "probably delivered" into "delivered".
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn cmd_status(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let report = chain.supply_report();
    let tip = chain.tip();

    println!("network        {}", store.params.name);
    println!("height         {}", chain.height());
    println!("finalized      {}", chain.finalized_height());
    println!("tip            {}", hash512_to_hex(&chain.tip_hash()));
    println!("difficulty     {}", tip.header.difficulty);
    println!("base fee       {} sat", tip.header.base_fee_sat);
    println!(
        "halving        {} (next in {} blocks)",
        halvings(&store.params, tip.header.height),
        store.params.halving_period - (tip.header.height % store.params.halving_period)
    );
    println!(
        "block reward   {} JNT",
        jnt(block_reward_sat(&store.params, tip.header.height + 1))
    );
    println!(
        "puzzle         {} (id {})",
        chain
            .registry()
            .get_opt(tip.header.puzzle_id)
            .map(|p| p.name.clone())
            .unwrap_or_default(),
        tip.header.puzzle_id
    );
    println!();
    println!("live supply    {} JNT", jnt(report.live_sat));
    println!(
        "issued to {}  {} JNT",
        report.height,
        jnt(cumulative_supply_sat(&store.params, report.height))
    );
    println!("reachable max  {} JNT", jnt(report.reachable_sat));
    if report.rate_allowance_sat == u64::MAX {
        println!("rate anchor    ladder era (grandfathered, bounded by the rungs)");
    } else {
        println!(
            "rate anchor    {} JNT max per halving period (1% of issued)",
            jnt(report.rate_allowance_sat)
        );
    }
    println!(
        "removed        {} JNT (base fees burned + PSCB, all usage ever)",
        jnt(report.removed_sat)
    );
    println!(
        "net supply     {} JNT (issued minus removed)",
        jnt(report.net_supply_sat)
    );

    // L2 is derived from the stored chain, so `status` reconstructs it the
    // same way a restart does: replay, no persisted L2 state to go stale.
    let l2 = NodeL2::replay_from(&chain, &store.params);
    let ls = l2.status(chain.height());
    println!();
    println!(
        "l2 height      {} (chain {})",
        ls.l2_height, ls.chain_height
    );
    println!("l2 applied     {}", ls.applied);
    println!("l2 skipped     {}", ls.skipped);
    if !ls.clean {
        println!("l2 replay      not clean (run verify for the named refusals)");
    }
    println!(
        "l2 deposits    {} credited ({} sat) / {} pending / {} ignored",
        ls.deposits_applied, ls.deposited_sat, ls.deposits_pending, ls.deposits_ignored
    );
    println!(
        "l2 exits       {} queued / {} sat released to L1",
        ls.pending_exits, ls.exited_sat
    );

    let wallets = store.load_wallets()?;
    if !wallets.is_empty() {
        println!();
        for w in &wallets {
            let addr = w.address().map_err(|e| e.to_string())?;
            let outputs = chain.utxo().outputs_for_address(&addr);
            let total: u64 = outputs.iter().map(|(_, v)| v).sum();
            let mature: u64 = chain
                .utxo()
                .iter()
                .filter(|(_, u)| u.out.address == addr)
                .filter(|(_, u)| u.height + store.params.coinbase_maturity <= chain.height())
                .map(|(_, u)| u.out.value)
                .sum();
            println!(
                "wallet {:<10} {}  balance {} JNT ({} spendable)",
                w.label,
                address_to_hex(&addr),
                jnt(total),
                jnt(mature)
            );
        }
    }
    Ok(())
}

fn cmd_verify(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    chain.verify_canonical_chain().map_err(|e| e.to_string())?;
    println!(
        "ok: replayed {} block(s) from genesis, UTXO and supply match",
        chain.height() + 1
    );
    // L2 determinism: two independent replays of the same stored blocks must
    // hold equal state, and the incremental following-the-tip path must agree
    // with full replay. Equality is total (`L2State` derives `PartialEq` over
    // all fields), so this is agreement on every L2 fact, not a summary.
    let params = store.params.clone();
    let a = NodeL2::replay_from(&chain, &params);
    let b = NodeL2::replay_from(&chain, &params);
    if a.state() != b.state() || a.skipped() != b.skipped() {
        return Err("l2 replay diverged: two replays of the same chain disagree".into());
    }
    let mut inc = NodeL2::fresh(&params);
    inc.sync(&chain);
    if inc.state() != a.state()
        || inc.applied_count() != a.applied_count()
        || inc.skipped() != a.skipped()
    {
        return Err(
            "l2 replay diverged: incremental application disagrees with full replay".into(),
        );
    }
    println!(
        "ok: l2 replay deterministic to height {} (applied {}, skipped {})",
        a.height(),
        a.applied_count(),
        a.skipped().len()
    );
    // Joint conservation (Decisions 7 and 10, SPEC.md §19.4–§19.5): L2 holds
    // at most genesis plus matured deposits, and L1 live supply plus
    // everything L2 ever held, minus what sits identifiably in the deposit
    // sink, stays under the joint bound — the issuance integral at the tip
    // plus the escrow ceiling (approved M-E). The stock cap is gone entirely
    // (Decision 18): the rate anchor bounds issuance, so there is no sanity
    // ceiling term to report here. The sink term is the M3 correction: sink
    // outputs remain in the L1 UTXO set (unspendable) while their twins live
    // in L2, so counting both sides without subtracting the sink would cry
    // inflation on every deposit. Burns anywhere move the sum down, never up —
    // either check failing means value was created, which must never print
    // "ok".
    // The three conservation checks now live in one tested place; this command
    // only reports the terms it returns.
    let supply =
        jnt_node::conservation::verify_conservation(&chain, &a).map_err(|e| e.to_string())?;
    println!(
        "ok: joint supply conserved (l1 live {} + l2 held {} - sink {} = {} sat of {} bound)\n    bound = l1 issuance integral {} + escrow ceiling {}",
        supply.l1_live_sat,
        supply.l2_held_sat,
        supply.sink_held_sat,
        supply.joint_sat,
        supply.bound_sat(),
        supply.l1_bound_sat,
        supply.escrow_ceiling_sat,
    );
    for s in a.skipped().iter().take(10) {
        println!(
            "  skipped height {:>6}  {}  {}",
            s.height,
            &hash512_to_hex(&s.txid)[..16],
            s.error
        );
    }
    if a.skipped().len() > 10 {
        println!("  ... and {} more", a.skipped().len() - 10);
    }
    for p in a.pending_deposits().iter().take(10) {
        println!(
            "  pending height {:>6}  {}:{}  {} sat (spendable at {})",
            p.deposit.height,
            &hash512_to_hex(&p.deposit.txid)[..16],
            p.deposit.index,
            p.deposit.amount_sat,
            p.matures_at
        );
    }
    if a.pending_deposits().len() > 10 {
        println!("  ... and {} more", a.pending_deposits().len() - 10);
    }
    for ig in a.ignored_deposits().iter().take(10) {
        println!(
            "  ignored height {:>6}  {}:{}  {} sat ({:?})",
            ig.height,
            &hash512_to_hex(&ig.txid)[..16],
            ig.index,
            ig.amount_sat,
            ig.reason
        );
    }
    if a.ignored_deposits().len() > 10 {
        println!("  ... and {} more", a.ignored_deposits().len() - 10);
    }
    Ok(())
}

fn cmd_show_block(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let height = args.num("height", chain.height())?;
    let block = chain
        .block_at(height)
        .ok_or_else(|| format!("no block at height {height}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(block).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn cmd_balance(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let addr = address_from_hex(
        args.str("address")
            .ok_or("--address <jt1...> is required")?,
    )
    .map_err(|e| e.to_string())?;
    let mut total = 0u64;
    let mut mature_total = 0u64;
    let maturity = store.params.coinbase_maturity;
    let next_height = chain.height() + 1;
    for (op, u) in chain.utxo().iter() {
        if u.out.address != addr {
            continue;
        }
        let mature = u.height + maturity <= next_height;
        if mature {
            mature_total += u.out.value;
        }
        total += u.out.value;
        println!(
            "{}:{}  {:>16} JNT  height {:>6}  {}",
            &hash512_to_hex(&op.txid)[..16],
            op.index,
            jnt(u.out.value),
            u.height,
            if mature { "spendable" } else { "immature" }
        );
    }
    if total == 0 {
        println!("no unspent outputs for {}", address_to_hex(&addr));
        return Ok(());
    }
    println!(
        "total {} JNT, of which {} JNT spendable",
        jnt(total),
        jnt(mature_total)
    );
    Ok(())
}

/// Every validator key in the data dir, as one committee.
///
/// `Ok(None)` when the directory holds no key files — the ordinary non-validating
/// node, which verifies and relays checkpoints and signs nothing. A file that
/// fails to load is an error, not a skip: an operator who placed a key file
/// expects it to be used, and silently ignoring it would leave them believing
/// they were validating.
fn load_validator_committee(
    store: &Store,
    params: &NetworkParams,
) -> Result<Option<jnt_core::signing::Committee>, String> {
    let dir = store.validator_keys_path();
    if !dir.exists() {
        return Ok(None);
    }
    let mut committee = jnt_core::signing::Committee::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("validators dir: {e}"))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let key = jnt_core::signing::ValidatorKey::from_bytes(&bytes, &params.network_id)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        committee.add(key).map_err(|e| e.to_string())?;
    }
    if committee.is_empty() {
        return Ok(None);
    }
    Ok(Some(committee))
}

/// `validator` — manage this node's checkpoint-signing keys (M5).
///
/// Keys live in `<data-dir>/validators/*.json`, one file per validator, and are
/// separate from `wallets.json` by design: a wallet holds funds this node spends,
/// a validator key signs consensus messages. Mixing them would make a wallet
/// backup a validator key backup, which is a different risk entirely.
///
/// The scalar is written with mode 0600 where the platform supports it, because
/// the file *is* the key. `validator list` prints public keys only.
fn cmd_validator(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    let params = store.params.clone();
    let dir = store.validator_keys_path();

    if !args.has("add") {
        // List: public keys only, never scalars, never the file contents.
        match load_validator_committee(&store, &params)? {
            Some(c) => {
                for pk in c.public_keys() {
                    println!("{}", hex::encode(pk.as_bytes()));
                }
                println!("{} validator(s)", c.len());
            }
            None => {
                println!("no validator keys in {}", dir.display());
            }
        }
        return Ok(());
    }

    let label = args.str_or("label", "validator");
    // OS entropy, harvested here rather than inside `jnt-core`, so the consensus
    // library stays free of any way to reach for randomness.
    // OS entropy, harvested here rather than inside jnt-core, so the consensus
    // library stays free of any way to reach for randomness.
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let sk = jnt_core::bls::SecretKey::derive(&seed).map_err(|e| e.to_string())?;
    let key = jnt_core::signing::ValidatorKey::new(sk, params.network_id.clone());
    let file = key.to_file();
    let bytes = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;

    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!("{label}.json"));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(&bytes).map_err(|e| e.to_string())?;

    println!("created validator `{label}`");
    println!("  file       {}", path.display());
    println!("  network    {}", params.network_id);
    println!("  public key {}", hex::encode(key.public_key().as_bytes()));
    println!("  committee  public key must be bonded on chain before its signature counts");
    Ok(())
}

fn cmd_wallet(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    let mut wallets = store.load_wallets()?;
    if !args.has("new") {
        if wallets.is_empty() {
            println!("no wallets");
            return Ok(());
        }
        for w in &wallets {
            println!(
                "{:<12} {}",
                w.label,
                address_to_hex(&w.address().map_err(|e| e.to_string())?)
            );
        }
        return Ok(());
    }
    let label = args.str_or("label", &format!("w{}", wallets.len()));
    let w = Wallet::new_random(&label);
    println!("created `{}`", w.label);
    println!(
        "  address  {}",
        address_to_hex(&w.address().map_err(|e| e.to_string())?)
    );
    println!(
        "  pubkey   {}",
        w.public_key_hex().map_err(|e| e.to_string())?
    );
    wallets.push(w);
    store.save_wallets(&wallets)
}

fn cmd_export(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let out = PathBuf::from(args.str_or("out", "chain.json"));
    let mut blocks = Vec::new();
    for h in 0..=chain.height() {
        if let Some(b) = chain.block_at(h) {
            blocks.push(b.clone());
        }
    }
    fs::write(
        &out,
        serde_json::to_string_pretty(&blocks).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("wrote {} block(s) to {}", blocks.len(), out.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// serve — P2P node run loop (§13.1 chain-thread model)
// ---------------------------------------------------------------------------

fn cmd_serve(args: &Args) -> Result<(), String> {
    let mut store = Store::open(args)?;
    let chain = store.load_chain()?;
    let wallets = store.load_wallets()?;

    let listen_addr: Option<std::net::SocketAddr> = args
        .str("listen")
        .map(|s| s.parse().map_err(|e| format!("--listen: {e}")))
        .transpose()?;

    let connect_peers: Vec<std::net::SocketAddr> = args
        .str("connect")
        .map(|s| {
            s.split(',')
                .map(|a| {
                    a.trim()
                        .parse()
                        .map_err(|e| format!("--connect `{a}`: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let max_peers = args.num("peers", 125)? as usize;
    // A relay-only node: it validates, relays and syncs, but does not mine.
    let no_mine = args.has("no-mine");
    let mut config = P2pConfig::new(store.params.clone(), listen_addr);
    config.max_peers = max_peers;
    // Loop period. Without one the loop mined as fast as the CPU allowed and
    // rewrote the whole chain file each time (SPEC.md §13.10 item 4).
    let interval_ms = args.num("interval", 250)?;

    // Opt-in service API (Decision 9): absent unless --api-listen is given,
    // so the default `serve` is exactly the P2P node it always was.
    let api_listen: Option<std::net::SocketAddr> = args
        .str("api-listen")
        .map(|s| s.parse().map_err(|e| format!("--api-listen: {e}")))
        .transpose()?;

    let node =
        P2pNode::start(config, chain.height(), chain.tip_hash()).map_err(|e| e.to_string())?;

    let mut syncer = SyncManager::new();
    // The mempool is in-memory only: a restart begins with an empty pool
    // (see `docs/status.md`).
    let mut relay = RelayManager::new();
    let mut pool_cursor = chain.height();
    let mut relay_seen = (0u64, 0u64);
    // Validator signing (M5). Empty when no key files are loaded, which is the
    // normal case for a non-validating node — it verifies and relays what others
    // produce and signs nothing.
    let validator_committee = load_validator_committee(&store, &store.params.clone())?;
    let mut signed_epochs = std::collections::BTreeSet::new();
    let mut finality_keys_missing_warning =
        validator_committee.is_none() && store.params.finality_activation_height > 0;
    // Fraud arbitration (Decision 21): inbound votes, tallied per dispute. Not
    // persisted — see `jnt_node::mediation` for why losing it costs only the
    // ability to *propose*, never the ability to verify or relay.
    let mut votes = jnt_core::arbitration::VoteBook::new();
    // L2 follows the tip by replay; nothing L2 is persisted.
    let l2 = NodeL2::replay_from(&chain, &store.params);
    let mut l2_skipped_seen = l2.skipped().len();

    println!("network        {}", store.params.name);
    println!("height         {}", chain.height());
    println!("tip            {}", hash512_to_hex(&chain.tip_hash()));
    if let Some(addr) = listen_addr {
        println!("listening      {addr}");
    }

    // Everything mutable now lives behind one lock shared with the API
    // thread: the serve loop takes it once per iteration, handlers take it
    // per request, and no handler holds it across an await (they do not
    // await). The P2P node, the store and the relay cursors stay loop-local:
    // the API must not reach the network or the disk on its own.
    let peers = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Mutex::new(jnt_node::api::SharedNode::new(chain, l2)));
    if let Some(api_addr) = api_listen {
        let bound = jnt_node::api::spawn(Arc::clone(&shared), Arc::clone(&peers), api_addr)?;
        println!("api            {bound}");
    }

    // Dial configured outbound peers.
    for addr in &connect_peers {
        let dialed = {
            let sh = shared
                .lock()
                .map_err(|_| "state lock poisoned".to_string())?;
            node.connect(*addr, &sh.chain)
        };
        match dialed {
            Ok(id) => println!("connected peer {id} -> {addr}"),
            Err(e) => eprintln!("warn: connect {addr}: {e}"),
        }
    }

    // Pick miner address if a wallet exists. `--no-mine` keeps the wallet —
    // it is still the address the node reports balances for.
    let miner_addr = if no_mine {
        None
    } else {
        wallets.first().and_then(|w| w.address().ok())
    };

    println!("press Ctrl-C to stop");

    // Decision 17's alarm half. The state machine (and its rate limit, which
    // exists because this loop can spin with `--interval-ms 0`) lives in
    // `conservation::BreachAlarm` so its timing rule is unit-testable; see the
    // poll below.
    let mut breach_alarm = jnt_node::conservation::BreachAlarm::new();

    // Chain thread: mine + relay loop
    loop {
        // Bind through one `&mut` so the loop's field accesses are disjoint
        // borrows of the shared state rather than repeated reborrows of the
        // guard (which the borrow checker rejects for `chain` + `pool`).
        let mut guard = shared
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        let sh = &mut *guard;

        // What the API accepted since the last iteration. Relayed after the
        // lock drops: announcing needs the P2P node, not the state.
        let relay_now: Vec<Hash512> = std::mem::take(&mut sh.tx_to_relay);

        // Decision 17 — the alarm half: a breached node keeps running but must
        // never be *quiet* about it. The closure is only invoked when the alarm
        // decides a look is due, so the whole-UTXO report is not recomputed on
        // every spin. The refusal half is in the API, on the two funding paths
        // only; reads stay up on purpose.
        match breach_alarm.poll(|| jnt_node::conservation::conservation_report(&sh.chain, &sh.l2)) {
            Some(jnt_node::conservation::BreachNotice::Breach(line)) => eprintln!("{line}"),
            Some(jnt_node::conservation::BreachNotice::Cleared) => {
                println!("conservation   breach cleared — joint supply conserved again")
            }
            None => {}
        }

        // Item 10 / §19.4: advance released escrows whose release has matured
        // under the finality window to Finalized. Pure height math — no coin
        // moves — so it is safe to run on every tick alongside the mine step.
        sh.advance_escrow_finality();

        // Mine one block if we have a miner wallet. `mine_from_pool` selects
        // from the pool and evicts what the *canonical* chain confirms; the
        // L2 queue only matters when the API has actually received L2
        // transactions, because inclusion in a block is the only way L2
        // state changes (SPEC.md §19.1).
        if let Some(addr) = miner_addr {
            // The crank (approved P1, E-2): matured, funded, proven exits are
            // settled permissionlessly. Nobody is privileged here — consensus
            // pays only the destinations the L2 records name. An exit whose
            // funding is not exactly present stays queued, which is a delay,
            // never a wrong payment.
            let exit_claims = sh
                .l2
                .crank_claims(&sh.chain, addr)
                .into_iter()
                // A block over `max_tx_count` claims is refused outright, so the
                // crank stops at the cap rather than making the node unable to
                // mine at all. The rest are simply settled in a later block.
                .take(sh.chain.params().max_tx_count)
                .collect::<Vec<_>>();
            let l2_queue = std::mem::take(&mut sh.l2_to_include);
            // An L2-bearing block must commit the root replay will derive
            // (approved P1). The chain may not consult the L2 view — that is
            // the view the chain exists to authenticate — so the miner derives
            // it from its own view and hands it over. A block that committed
            // nothing would be refused on every peer, so this is not optional.
            let l2_root = if l2_queue.is_empty() {
                None
            } else {
                Some(sh.l2.simulate_root(sh.chain.height() + 1, &l2_queue))
            };
            let mined = if l2_queue.is_empty() && exit_claims.is_empty() {
                sh.chain.mine_from_pool(&mut sh.pool, addr, now_ms())
            } else {
                sh.chain.mine_from_pool_with_exits(
                    &mut sh.pool,
                    addr,
                    now_ms(),
                    l2_queue,
                    exit_claims,
                    l2_root,
                )
            };
            if let Ok(block) = mined {
                let hash = block.block_hash();
                let height = block.header.height;
                store.save_chain(&sh.chain).ok();
                store.write_meta(&sh.chain).ok();
                println!("mined height {height}  {}", &hash512_to_hex(&hash)[..16]);
                node.broadcast_block(hash, None);
            }

            // Sign and broadcast a checkpoint at an epoch boundary (M5,
            // Decisions 12/14). This is the "a quorum produced this" side of the
            // protocol: the node only signs a block it holds canonically as its
            // own tip, so a certificate can never name a hash this node does not
            // have. With no validator keys configured it signs nothing and says
            // so once, rather than looking like a broken validator.
            //
            // Signed against the committee this chain derives for the
            // certificate's epoch — the set a peer verifies against — so the
            // bitmap's indices mean the same thing on both sides. Signing
            // against a locally assembled key list would place this node's key at
            // index 0 of a short bitmap and a peer would read that as a different
            // validator having signed.
            if let Some(committee) = validator_committee.as_ref() {
                let height = sh.chain.height();
                let epoch_blocks = sh.chain.params().checkpoint_interval_blocks.max(1);
                let boundary_height = (height / epoch_blocks) * epoch_blocks;
                if boundary_height > 0
                    && boundary_height <= height
                    && !signed_epochs.contains(&boundary_height)
                {
                    // The set a verifier will use for this epoch: the chain's own
                    // committee keys for that height, in the sorted order
                    // `EpochSet` uses.
                    let epoch = boundary_height / epoch_blocks;
                    let committee_keys = sh.chain.committee_keys();
                    if !committee_keys.is_empty() {
                        let signer = jnt_core::signing::CheckpointSigner::new(
                            &sh.chain.params().network_id,
                            epoch_blocks,
                        );
                        if let Some(Ok(cp)) = signer.sign_for_set(
                            boundary_height,
                            sh.chain.tip_hash(),
                            committee,
                            &committee_keys,
                        ) {
                            debug_assert_eq!(cp.payload.epoch, epoch);
                            if let Ok(()) = sh.chain.apply_checkpoint(&cp, &jnt_core::bls::RealBls)
                            {
                                signed_epochs.insert(boundary_height);
                                node.broadcast_checkpoint(cp.clone());
                                println!(
                                    "checkpoint   height {boundary_height} signed by {} validators",
                                    cp.signer_count
                                );
                            }
                        }
                    }
                }
            } else if finality_keys_missing_warning {
                eprintln!(
                    "note: binding finality is active for this profile but no validator key \
                     files are loaded, so this node cannot sign checkpoints. It will still \
                     verify and relay the ones other validators produce."
                );
                finality_keys_missing_warning = false;
            }
        }

        // Drain inbound P2P events and apply to chain. Inbound arbitration votes
        // are tallied here, against this node's own committee and height.
        let before = sh.chain.height();
        node.poll_events(
            NodeState {
                chain: &mut sh.chain,
                pool: &mut sh.pool,
                syncer: &mut syncer,
                relay: &mut relay,
                votes: &mut votes,
            },
            Some(now_ms()),
        );

        // Keep the L2 view on the tip after both paths above. A reorg that
        // rewrote history takes the full-replay arm inside `sync`.
        let report = sh.l2.sync(&sh.chain);
        match report.outcome {
            jnt_node::l2::SyncOutcome::FullReplay { .. }
                if report.to_height != report.from_height =>
            {
                println!(
                    "l2             full replay to height {} (applied {}, skipped {})",
                    report.to_height,
                    sh.l2.applied_count(),
                    sh.l2.skipped().len()
                );
                l2_skipped_seen = sh.l2.skipped().len();
            }
            _ => {
                if sh.l2.skipped().len() != l2_skipped_seen {
                    println!(
                        "l2             height {} applied {} skipped {}",
                        sh.l2.height(),
                        sh.l2.applied_count(),
                        sh.l2.skipped().len()
                    );
                    l2_skipped_seen = sh.l2.skipped().len();
                }
            }
        }

        // Reconciliation is unconditional: a reorg can land at the same
        // height, and gating on height would skip exactly the case where the
        // pool most needs updating.
        let (cursor, mreport) = sh.chain.reconcile_mempool(&mut sh.pool, pool_cursor);
        pool_cursor = cursor;
        if mreport.evicted > 0 || mreport.readmitted > 0 || mreport.refused > 0 {
            println!(
                "mempool        evicted {} re-admitted {} refused {}",
                mreport.evicted, mreport.readmitted, mreport.refused
            );
        }

        // Relay outcomes, printed on change.
        let (accepted, refused) = (relay.accepted_count(), relay.refused_count());
        if accepted != relay_seen.0 || refused != relay_seen.1 {
            if accepted > relay_seen.0 || refused > relay_seen.1 {
                println!(
                    "relay          accepted {accepted} refused {refused} (pool holds {})",
                    sh.pool.len()
                );
            }
            relay_seen = (accepted, refused);
        }

        // Fraud arbitration (Decision 21). Two halves, in this order:
        //
        // 1. Sign. If this node holds arbitrator keys, derive the canonical
        //    reference for every live dispute and broadcast one signed vote per
        //    key. Deterministic, so every honest arbitrator over the same chain
        //    signs the same bytes.
        // 2. Propose. Any dispute with a reaching quorum becomes a `Settle`
        //    transaction in the L2 include queue, applied by the existing
        //    settlement path - which re-verifies the aggregate from scratch.
        //
        // Signing first so a node's own vote is not waiting on its own relay.
        if let Some(committee) = validator_committee.as_ref() {
            let mine = jnt_node::mediation::votes_for(
                &sh.chain,
                sh.l2.state(),
                committee,
                sh.chain.height(),
            );
            for vote in mine {
                let task = vote.task_id;
                node.broadcast_vote(vote);
                println!(
                    "arbitration    vote signed for task {}",
                    &hash_to_hex(&task)[..16]
                );
            }
        }
        {
            let committee = sh.chain.committee_keys();
            let proposals = jnt_node::mediation::live_proposals(&votes, &committee, sh.l2.state());
            for p in proposals {
                sh.l2_to_include.push(p.tx);
                println!(
                    "arbitration    quorum reached for task {}",
                    &hash_to_hex(&p.task_id)[..16]
                );
            }
        }

        // Blocks from peers are persisted per batch, not per event.
        if sh.chain.height() != before {
            store.save_chain(&sh.chain).ok();
            store.write_meta(&sh.chain).ok();
        }
        // Binding finality can advance without a height change.
        store.persist_finality(&sh.chain).ok();

        // Monitors read this through the API; a plain counter, never a
        // consensus input.
        peers.store(node.peer_count(), Ordering::Relaxed);
        drop(guard);

        // Announce API-accepted transactions to peers. The pool already
        // holds them, so GETDATA is answerable.
        if !relay_now.is_empty() {
            for txid in &relay_now {
                relay.mark_known(*txid);
            }
            node.broadcast_tx(&relay_now, None);
        }

        if interval_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        }
    }
}
