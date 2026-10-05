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
//! ```
//!
//! There is no P2P layer yet: this is a single-node chain. See
//! `docs/roadmap.md` for what a real node still needs.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use jnt_core::block::Block;
use jnt_core::chain::Chain;
use jnt_core::hash::{address_from_hex, address_to_hex, hash_to_hex};
use jnt_core::params::{NetworkParams, SAT_PER_JNT};
use jnt_core::supply::{block_reward_sat, cumulative_supply_sat, halvings, max_issuance_sat};
use jnt_core::tx::{OutPoint, Output};
use jnt_core::wallet::Wallet;

const USAGE: &str = "\
jnt-node - Jounit base-layer node

USAGE:
  jnt-node <COMMAND> [OPTIONS]

COMMANDS:
  init      Create a chain directory, a miner wallet and the genesis block
  mine      Mine blocks and extend the chain
  send      Spend from a wallet address into a new block
  status    Print chain tip, difficulty, supply and wallet balance
  verify    Replay the chain from genesis and diff it against stored state
  show-block  Print one block
  balance   List the unspent outputs of an address
  wallet    Create or list wallets
  export    Write the canonical chain to JSON
  help      This text

COMMON OPTIONS:
  --network <mainnet|mini>   Default: mini
  --data-dir <path>          Default: ./chain
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
}

impl Store {
    fn open(args: &Args) -> Result<Self, String> {
        let params = args.params()?;
        Ok(Store {
            dir: args.data_dir.clone(),
            params,
        })
    }

    fn chain_path(&self) -> PathBuf {
        self.dir.join("blocks.json")
    }

    fn wallets_path(&self) -> PathBuf {
        self.dir.join("wallets.json")
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.json")
    }

    fn load_chain(&self) -> Result<Chain, String> {
        let path = self.chain_path();
        if !path.exists() {
            return Err(format!(
                "no chain at {} - run `jnt-node init` first",
                self.dir.display()
            ));
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let blocks: Vec<Block> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let mut chain = Chain::new(self.params.clone()).map_err(|e| e.to_string())?;
        for block in blocks.iter().skip(1) {
            chain.submit(block.clone()).map_err(|e| e.to_string())?;
        }
        Ok(chain)
    }

    fn save_chain(&self, chain: &Chain) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let mut blocks = Vec::new();
        for h in 0..=chain.height() {
            if let Some(b) = chain.block_at(h) {
                blocks.push(b.clone());
            }
        }
        let text = serde_json::to_string_pretty(&blocks).map_err(|e| e.to_string())?;
        fs::write(self.chain_path(), text).map_err(|e| e.to_string())
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
            "genesis_hash": hash_to_hex(&chain.block_hash_at(0).unwrap_or([0u8; 32])),
            "height": chain.height(),
        });
        let text = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
        fs::write(self.meta_path(), text).map_err(|e| e.to_string())
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
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

fn cmd_init(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    if store.chain_path().exists() {
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
    println!("genesis        {}", hash_to_hex(&chain.tip_hash()));
    println!("block time     {} ms", store.params.target_block_time_ms);
    println!("supply cap     {} JNT", store.params.supply_cap_jnt());
    println!(
        "reachable      {} JNT (the rest is permanently unmintable)",
        max_issuance_sat(&store.params) / SAT_PER_JNT
    );
    println!("data dir       {}", store.dir.display());
    Ok(())
}

fn cmd_mine(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    let mut chain = store.load_chain()?;
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
        println!(
            "height {:>6}  diff {:>10}  reward {:>12} JNT  {}",
            height,
            difficulty,
            jnt(block_reward_sat(chain.params(), height)),
            &hash_to_hex(&hash)[..16]
        );
        mined += 1;
        if interval > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval));
        }
    }
    store.save_chain(&chain)?;
    store.write_meta(&chain)?;
    println!("mined {mined} block(s); tip height {}", chain.height());
    Ok(())
}

fn cmd_send(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
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
    let txid = jnt_core::hash::hash_to_hex(&tx.txid());

    let block = chain
        .mine_block(from, vec![tx], now_ms())
        .map_err(|e| e.to_string())?;
    let height = block.header.height;
    let burned = block.header.base_fee_sat * block.txs[1].gas_used();
    chain.submit(block).map_err(|e| e.to_string())?;
    store.save_chain(&chain)?;
    store.write_meta(&chain)?;

    println!("txid    {txid}");
    println!("height  {height}");
    println!("amount  {} JNT", jnt(amount));
    println!("fee     {} JNT", jnt(fee));
    println!("burned  {} JNT (base fee, destroyed)", jnt(burned));
    Ok(())
}

fn cmd_status(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
    let chain = store.load_chain()?;
    let report = chain.supply_report();
    let tip = chain.tip();

    println!("network        {}", store.params.name);
    println!("height         {}", chain.height());
    println!("finalized      {}", chain.finalized_height());
    println!("tip            {}", hash_to_hex(&chain.tip_hash()));
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
    println!("hard cap       {} JNT", jnt(report.cap_sat));
    println!(
        "unmintable     {} JNT (never issuable)",
        jnt(report.cap_sat - report.reachable_sat)
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
    let store = Store::open(args)?;
    let chain = store.load_chain()?;
    chain.verify_canonical_chain().map_err(|e| e.to_string())?;
    println!(
        "ok: replayed {} block(s) from genesis, UTXO and supply match",
        chain.height() + 1
    );
    Ok(())
}

fn cmd_show_block(args: &Args) -> Result<(), String> {
    let store = Store::open(args)?;
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
    let store = Store::open(args)?;
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
            &hash_to_hex(&op.txid)[..16],
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
    let store = Store::open(args)?;
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
