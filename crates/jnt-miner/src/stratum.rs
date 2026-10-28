//! Stratum-lite v1: minimal JSON-lines job server for pool operators.
//!
//! The node serves one miner via `GET /v1/mine/template`; a pool serves many.
//! This module is that pool side: it hands out jobs (unsolved templates),
//! validates submitted shares, and forwards full-difficulty blocks through a
//! caller-provided submit callback (normally `POST /v1/mine/submit`).
//!
//! Protocol: newline-delimited JSON over TCP.
//!
//! ```text
//! miner -> {"method":"getjob","miner":"<20-byte hex>"}
//! pool  -> {"job_id":7,"height":123,"difficulty":"1000","puzzle_id":1,"block_hex":"..."}
//! miner -> {"method":"submit","job_id":7,"miner":"<20-byte hex>","block_hex":"..."}
//! pool  -> {"accepted":true,"share":true,"block":false}
//! ```
//!
//! Anti-theft rule: the submitted block must match the job's `prev_hash`,
//! `height`, `difficulty`, `puzzle_id` and `merkle_root` exactly — only
//! `nonce`, `extra_nonce` and `timestamp` may differ. A miner that swaps the
//! coinbase (or any transaction) changes the merkle root and the share is
//! refused. Proof validity is re-checked by the pool with the same rule the
//! node uses; the node re-checks again at submit.
//!
//! Share difficulty: the pool accepts proofs meeting a weaker `share_difficulty`
//! (default 1) as shares for accounting, and forwards only proofs that also
//! meet the job's network difficulty as blocks. Share counting is in-memory;
//! payout logic is the pool operator's job, not this crate's.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use jnt_core::block::{Block, Header};
use jnt_core::error::{Error, Result};
use jnt_core::hash::Address;
use jnt_core::hbm_pow::HbmConfig;
use jnt_core::puzzle::{PuzzleKind, PuzzleSolver, PuzzleSpec};

/// A job handed to one miner: an unsolved template plus its id.
#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: u64,
    pub block: Block,
}

/// Per-miner accounting kept by the pool.
#[derive(Debug, Clone, Default)]
pub struct ShareStats {
    /// Shares accepted at share difficulty (includes blocks).
    pub shares: u64,
    /// Shares that also met network difficulty and were forwarded.
    pub blocks_found: u64,
}

/// Outcome of a validated submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitOutcome {
    pub share: bool,
    pub block: bool,
}

/// In-memory pool: job store plus share accounting.
///
/// `template_fn` supplies a fresh unsolved template on every `getjob`
/// (a pool fetches this from its node); `submit_fn` receives solved blocks
/// that meet network difficulty and returns whether the node accepted them.
pub struct Pool {
    inner: Mutex<PoolInner>,
    template_fn: Box<dyn Fn() -> Result<Block> + Send + Sync>,
    submit_fn: Box<dyn Fn(Block) -> Result<bool> + Send + Sync>,
    share_difficulty: u128,
    spec: PuzzleSpec,
    hbm: Option<HbmConfig>,
}

struct PoolInner {
    next_job_id: u64,
    jobs: HashMap<u64, Block>,
    stats: HashMap<Address, ShareStats>,
}

impl Pool {
    /// `share_difficulty` must be non-zero and no harder than any template
    /// the pool will serve (a share can never beat a harder bar it was not
    /// ground against — here the bar only filters, so an unreachable bar
    /// would refuse every share).
    pub fn new(
        spec: PuzzleSpec,
        hbm: Option<HbmConfig>,
        share_difficulty: u128,
        template_fn: impl Fn() -> Result<Block> + Send + Sync + 'static,
        submit_fn: impl Fn(Block) -> Result<bool> + Send + Sync + 'static,
    ) -> Result<Self> {
        if share_difficulty == 0 {
            return Err(Error::InvalidDifficulty(0));
        }
        spec.validate()?;
        if let Some(cfg) = &hbm {
            cfg.validate()?;
        }
        Ok(Pool {
            inner: Mutex::new(PoolInner {
                next_job_id: 1,
                jobs: HashMap::new(),
                stats: HashMap::new(),
            }),
            template_fn: Box::new(template_fn),
            submit_fn: Box::new(submit_fn),
            share_difficulty,
            spec,
            hbm,
        })
    }

    /// Hand out a job. The template is stored under its id so `submit_job`
    /// can pin the submission to it.
    pub fn get_job(&self) -> Result<Job> {
        let block = (self.template_fn)()?;
        if block.header.puzzle_id != self.spec.id
            && !(self.hbm.is_some() && block.header.puzzle_id == 2)
        {
            return Err(Error::BadPuzzleSpec(format!(
                "template names puzzle {} but the pool serves {}",
                block.header.puzzle_id, self.spec.id
            )));
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Error::Malformed("pool lock"))?;
        let job_id = inner.next_job_id;
        inner.next_job_id += 1;
        inner.jobs.insert(job_id, block.clone());
        // Jobs are single-use: a submission consumes its job, so a replayed
        // share cannot be counted twice and a stale template cannot linger.
        // (The store only grows by jobs never submitted; pools rotate
        // templates every block, so this is bounded by submission rate.)
        if inner.jobs.len() > 1024 {
            let oldest = *inner.jobs.keys().min().unwrap();
            inner.jobs.remove(&oldest);
        }
        Ok(Job { job_id, block })
    }

    /// Validate a submission against `job_id`'s template and account it.
    pub fn submit_job(&self, job_id: u64, miner: Address, block: Block) -> Result<SubmitOutcome> {
        let template = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            inner
                .jobs
                .remove(&job_id)
                .ok_or(Error::Malformed("unknown job"))?
        };
        // Anti-theft: everything but the proof fields and timestamp must be
        // byte-identical to the issued template.
        let a = &template.header;
        let b = &block.header;
        if a.prev_hash != b.prev_hash
            || a.merkle_root != b.merkle_root
            || a.height != b.height
            || a.difficulty != b.difficulty
            || a.puzzle_id != b.puzzle_id
            || a.epoch_id != b.epoch_id
        {
            return Err(Error::Malformed("share does not match its job"));
        }
        if block.txs != template.txs {
            return Err(Error::Malformed("share transactions differ from its job"));
        }

        // Share bar first: the proof must meet `share_difficulty`.
        if !self.proof_meets(&block.header, self.share_difficulty)? {
            return Err(Error::Malformed("share below pool difficulty"));
        }
        let is_block = self.proof_meets(&block.header, b.difficulty)?;
        if is_block {
            let accepted = (self.submit_fn)(block)?;
            if !accepted {
                return Err(Error::Malformed("node refused the block"));
            }
        }
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| Error::Malformed("pool lock"))?;
            let stats = inner.stats.entry(miner).or_default();
            stats.shares += 1;
            if is_block {
                stats.blocks_found += 1;
            }
        }
        Ok(SubmitOutcome {
            share: true,
            block: is_block,
        })
    }

    /// Copy of one miner's accounting (zeroes when the miner has no shares).
    pub fn stats_for(&self, miner: &Address) -> ShareStats {
        self.inner
            .lock()
            .map(|inner| inner.stats.get(miner).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Check the header's proof against an arbitrary bar by re-running the
    /// consensus rule with the difficulty field swapped. The header's own
    /// difficulty is untouched, so this never weakens what `submit` enforces.
    fn proof_meets(&self, header: &Header, difficulty: u128) -> Result<bool> {
        if difficulty == 0 {
            return Err(Error::InvalidDifficulty(0));
        }
        // A bar harder than the representable target (u128::MAX) can never
        // be met by any proof: that is a refused share, not an error.
        if jnt_core::u256::target_for_difficulty(difficulty).is_err() {
            return Ok(false);
        }
        let mut probe = header.clone();
        probe.difficulty = difficulty;
        match self.spec.kind {
            PuzzleKind::Hybrid => PuzzleSolver::new(self.spec.clone()).satisfies(&probe),
            PuzzleKind::Hbm => {
                let cfg = self.hbm.as_ref().ok_or_else(|| {
                    Error::BadPuzzleSpec("hbm proof without an hbm config".into())
                })?;
                jnt_core::hbm_pow::hbm_satisfies_cfg(&probe, difficulty, cfg)
            }
        }
    }
}

/// Serve the JSON-lines protocol on `listener` until the process exits.
/// Each connection is handled on its own thread; a malformed line gets a
/// `{"accepted":false,"reason":"..."}` reply and the connection continues.
pub fn serve(listener: TcpListener, pool: Arc<Pool>) -> ! {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let pool = pool.clone();
        std::thread::spawn(move || handle_conn(stream, &pool));
    }
    unreachable!("listener.incoming never returns None");
}

fn reply(stream: &mut TcpStream, value: serde_json::Value) {
    let mut line = value.to_string();
    line.push('\n');
    let _ = stream.write_all(line.as_bytes());
}

fn handle_conn(stream: TcpStream, pool: &Pool) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => return,
        };
        if n == 0 {
            return;
        }
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                reply(
                    &mut writer,
                    serde_json::json!({"accepted": false, "reason": format!("bad json: {e}")}),
                );
                continue;
            }
        };
        match req.get("method").and_then(|m| m.as_str()) {
            Some("getjob") => {
                let Some(miner_hex) = req.get("miner").and_then(|m| m.as_str()) else {
                    reply(
                        &mut writer,
                        serde_json::json!({"accepted": false, "reason": "missing miner"}),
                    );
                    continue;
                };
                if jnt_core::hash::address_from_hex(miner_hex).is_err() {
                    reply(
                        &mut writer,
                        serde_json::json!({"accepted": false, "reason": "bad miner address"}),
                    );
                    continue;
                }
                match pool.get_job() {
                    Ok(job) => reply(
                        &mut writer,
                        serde_json::json!({
                            "job_id": job.job_id,
                            "height": job.block.header.height,
                            "difficulty": job.block.header.difficulty.to_string(),
                            "puzzle_id": job.block.header.puzzle_id,
                            "block_hex": hex::encode(job.block.serialize()),
                        }),
                    ),
                    Err(e) => reply(
                        &mut writer,
                        serde_json::json!({"accepted": false, "reason": e.to_string()}),
                    ),
                }
            }
            Some("submit") => {
                let job_id = req.get("job_id").and_then(|j| j.as_u64());
                let miner_hex = req.get("miner").and_then(|m| m.as_str());
                let block_hex = req.get("block_hex").and_then(|b| b.as_str());
                let (Some(job_id), Some(miner_hex), Some(block_hex)) =
                    (job_id, miner_hex, block_hex)
                else {
                    reply(
                        &mut writer,
                        serde_json::json!({"accepted": false, "reason": "missing job_id/miner/block_hex"}),
                    );
                    continue;
                };
                let miner = match jnt_core::hash::address_from_hex(miner_hex) {
                    Ok(a) => a,
                    Err(e) => {
                        reply(
                            &mut writer,
                            serde_json::json!({"accepted": false, "reason": format!("bad miner address: {e}")}),
                        );
                        continue;
                    }
                };
                let raw = match hex::decode(block_hex.trim().trim_start_matches("0x")) {
                    Ok(raw) => raw,
                    Err(e) => {
                        reply(
                            &mut writer,
                            serde_json::json!({"accepted": false, "reason": format!("bad block hex: {e}")}),
                        );
                        continue;
                    }
                };
                let block = match Block::deserialize(&raw) {
                    Ok(b) => b,
                    Err(e) => {
                        reply(
                            &mut writer,
                            serde_json::json!({"accepted": false, "reason": format!("block decode: {e}")}),
                        );
                        continue;
                    }
                };
                match pool.submit_job(job_id, miner, block) {
                    Ok(out) => reply(
                        &mut writer,
                        serde_json::json!({"accepted": true, "share": out.share, "block": out.block}),
                    ),
                    Err(e) => reply(
                        &mut writer,
                        serde_json::json!({"accepted": false, "reason": e.to_string()}),
                    ),
                }
            }
            _ => reply(
                &mut writer,
                serde_json::json!({"accepted": false, "reason": "unknown method (getjob/submit)"}),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jnt_core::chain::Chain;
    use jnt_core::params::NetworkParams;

    fn test_pool(share_difficulty: u128, submitted: Arc<Mutex<Vec<Block>>>) -> (Pool, Address) {
        let miner = [7u8; 20];
        let chain = Arc::new(Mutex::new(Chain::new(NetworkParams::mini()).unwrap()));
        let pool = Pool::new(
            PuzzleSpec::hybrid_v1(),
            None,
            share_difficulty,
            {
                let chain = chain.clone();
                move || {
                    chain.lock().unwrap().build_template_with(
                        miner,
                        vec![],
                        1_767_225_601_000,
                        Some(1),
                    )
                }
            },
            move |block| {
                submitted.lock().unwrap().push(block);
                Ok(true)
            },
        )
        .unwrap();
        (pool, miner)
    }

    #[test]
    fn job_solve_submit_counts_share_and_block() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted.clone());

        let job = pool.get_job().unwrap();
        assert_eq!(job.block.header.height, 1);
        // Difficulty 1: nonce 0 is already a valid proof.
        let out = pool.submit_job(job.job_id, miner, job.block).unwrap();
        assert_eq!(
            out,
            SubmitOutcome {
                share: true,
                block: true
            }
        );
        assert_eq!(submitted.lock().unwrap().len(), 1);
        let stats = pool.stats_for(&miner);
        assert_eq!(stats.shares, 1);
        assert_eq!(stats.blocks_found, 1);
    }

    #[test]
    fn replay_of_a_consumed_job_is_refused() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted);

        let job = pool.get_job().unwrap();
        pool.submit_job(job.job_id, miner, job.block.clone())
            .unwrap();
        let err = pool.submit_job(job.job_id, miner, job.block).unwrap_err();
        assert_eq!(err, Error::Malformed("unknown job"));
    }

    #[test]
    fn coinbase_swap_is_refused() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(1, submitted.clone());

        let job = pool.get_job().unwrap();
        // Steal the reward: change the coinbase value, keep the old header.
        // The header merkle still matches the job, but the transactions don't.
        let mut stolen = job.block.clone();
        stolen.txs[0].outputs[0].value += 1;
        let err = pool.submit_job(job.job_id, miner, stolen).unwrap_err();
        assert_eq!(
            err,
            Error::Malformed("share transactions differ from its job")
        );

        // Or rewrite the header merkle to match the stolen body: now the
        // header diverges from the issued job instead.
        let job2 = pool.get_job().unwrap();
        let mut forged = job2.block.clone();
        forged.txs[0].outputs[0].value += 1;
        forged.header.merkle_root = forged.merkle_root();
        let err = pool.submit_job(job2.job_id, miner, forged).unwrap_err();
        assert_eq!(err, Error::Malformed("share does not match its job"));
        assert_eq!(submitted.lock().unwrap().len(), 0);
    }

    #[test]
    fn below_share_difficulty_is_refused() {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let (pool, miner) = test_pool(u128::MAX, submitted.clone());

        let job = pool.get_job().unwrap();
        let err = pool.submit_job(job.job_id, miner, job.block).unwrap_err();
        assert_eq!(err, Error::Malformed("share below pool difficulty"));
        assert!(submitted.lock().unwrap().is_empty());
    }

    #[test]
    fn wire_getjob_submit_roundtrip() {
        use std::io::{BufRead, BufReader, Write};

        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitted_clone = submitted.clone();
        let pool = Arc::new(test_pool(1, submitted_clone).0);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(listener, pool));

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let miner_hex = "07".repeat(20);
        let mut line = String::new();
        writeln!(
            stream,
            "{{\"method\":\"getjob\",\"miner\":\"{miner_hex}\"}}"
        )
        .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let job: serde_json::Value = serde_json::from_str(&line).unwrap();
        let job_id = job["job_id"].as_u64().expect("job_id");
        let block_hex = job["block_hex"].as_str().expect("block_hex").to_string();
        assert_eq!(job["height"], 1);

        writeln!(
            stream,
            "{{\"method\":\"submit\",\"job_id\":{job_id},\"miner\":\"{miner_hex}\",\"block_hex\":\"{block_hex}\"}}"
        )
        .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let out: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(out["accepted"], true);
        assert_eq!(out["share"], true);
        assert_eq!(out["block"], true);
        assert_eq!(submitted.lock().unwrap().len(), 1);

        // Unknown method gets a named refusal, connection stays alive.
        writeln!(stream, "{{\"method\":\"bogus\"}}").unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let out: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(out["accepted"], false);
    }
}
