//! Economical micro-payments: batch quotes, stream channels, sponsored fees.
//!
//! Three pure primitives that make per-API-call charging economical without a
//! new transaction type or consensus change:
//!
//! 1. [`BatchQuote`] — N same-payer payments ride one L1 transaction via
//!    `service::aggregate_payments`. This module prices that settlement
//!    (`gas_used`, `required_fee`, per-payment cost, savings vs N separate
//!    transactions) so a service can show the caller the true cost.
//! 2. **Stream channels** — a [`PaymentStream`] opened once, then N off-chain
//!    [`voucher_spec`]s (one per API call / dataset query / robot work unit)
//!    each settling exactly the newly accrued amount. One on-chain payment
//!    carries the final voucher (`reference` = stream id); the rest never
//!    touch the chain. [`StreamBook`] stays the settlement truth.
//! 3. [`SponsoredIntent`] — a third party (faucet, employer, service operator)
//!    signs that it covers the settlement fee for one batch hash. The coin
//!    still moves through the ordinary transaction; the intent is the
//!    auditable fee-attribution record the settler checks before building.
//!
//! Fail-closed: empty batches, mixed payers, over-cap vouchers, and sponsor
//! signatures from anyone but the named sponsor are refused by name.

use crate::hash::{sha256_dom, Address, Hash};
use crate::l2::Auth;
use crate::payment::MachinePayment;
use crate::service::{aggregate_payments, PaymentBatch};
use crate::stream::{PaymentStream, StreamBook, StreamSettleSpec};
use crate::wallet::Wallet;

/// Domain tag for a sponsor's fee-coverage signature.
pub const DOM_SPONSOR_INTENT: &[u8] = b"srct/sponsor-intent/v1";
/// Longest accepted network id (bytes), same bound as the payment layer.
pub const MAX_MICRO_NETWORK_ID_LEN: usize = 64;

/// Why a micro-payment step was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MicroError {
    Malformed(&'static str),
    EmptyBatch,
    MixedPayers,
    Overflow,
    OverCap { accrued: u64, cap: u64 },
    NothingNew,
    WrongNetwork { expected: String, got: String },
    SignerNotSponsor { signer: Address, sponsor: Address },
    SignatureInvalid(&'static str),
}

impl std::fmt::Display for MicroError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MicroError::Malformed(w) => write!(f, "malformed micro-payment: {w}"),
            MicroError::EmptyBatch => write!(f, "payment batch is empty"),
            MicroError::MixedPayers => write!(f, "batch mixes payers"),
            MicroError::Overflow => write!(f, "micro-payment arithmetic overflow"),
            MicroError::OverCap { accrued, cap } => {
                write!(f, "stream voucher {accrued} exceeds cap {cap}")
            }
            MicroError::NothingNew => write!(f, "voucher settles nothing new"),
            MicroError::WrongNetwork { expected, got } => {
                write!(f, "wrong network: expected {expected}, got {got}")
            }
            MicroError::SignerNotSponsor { signer, sponsor } => {
                write!(f, "sponsor signature from {signer:?}, expected {sponsor:?}")
            }
            MicroError::SignatureInvalid(w) => write!(f, "sponsor signature invalid: {w}"),
        }
    }
}

impl std::error::Error for MicroError {}

/// The priced settlement for one [`PaymentBatch`]: what it costs, what each
/// payment effectively pays, and what separate transactions would have cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchQuote {
    pub payments: usize,
    pub distinct_recipients: usize,
    pub total_amount_sat: u64,
    pub gas_used: u64,
    pub required_fee_sat: u64,
    /// `required_fee_sat / payments` (floored). Compare with a single 1-in/1-out
    /// transaction's fee to see the saving.
    pub fee_per_payment_sat: u64,
    /// What N separate 1-in/1-out transactions would cost at this base fee.
    pub separate_total_fee_sat: u64,
    /// `separate_total - required_fee` (saturating). Zero means no saving
    /// (single payment, single recipient).
    pub savings_sat: u64,
}

impl BatchQuote {
    /// Price `batch` at `base_fee_sat_per_gas` assuming `input_count` funding
    /// inputs. Pure arithmetic; refuses overflow rather than wrapping.
    pub fn price(
        batch: &PaymentBatch,
        base_fee_sat_per_gas: u64,
        input_count: usize,
    ) -> Result<Self, MicroError> {
        if batch.payment_ids.is_empty() {
            return Err(MicroError::EmptyBatch);
        }
        let gas = batch.gas_used(input_count);
        let required = base_fee_sat_per_gas
            .checked_mul(gas)
            .ok_or(MicroError::Overflow)?;
        let per_payment = required / batch.payment_ids.len() as u64;
        let single_gas = crate::tx::GAS_TX_BASE
            .checked_add(crate::tx::GAS_PER_INPUT)
            .and_then(|g| g.checked_add(crate::tx::GAS_PER_OUTPUT))
            .ok_or(MicroError::Overflow)?;
        let separate = (batch.payment_ids.len() as u64)
            .checked_mul(single_gas)
            .and_then(|g| g.checked_mul(base_fee_sat_per_gas))
            .ok_or(MicroError::Overflow)?;
        Ok(BatchQuote {
            payments: batch.payment_ids.len(),
            distinct_recipients: batch.output_count(),
            total_amount_sat: batch.total_amount_sat,
            gas_used: gas,
            required_fee_sat: required,
            fee_per_payment_sat: per_payment,
            separate_total_fee_sat: separate,
            savings_sat: separate.saturating_sub(required),
        })
    }
}

/// Verify `payments` and price their shared settlement in one step.
pub fn quote_batch(
    payments: &[MachinePayment],
    network_id: &str,
    height: u64,
    base_fee_sat_per_gas: u64,
    input_count: usize,
) -> Result<(PaymentBatch, BatchQuote), MicroError> {
    if payments.is_empty() {
        return Err(MicroError::EmptyBatch);
    }
    let batch = aggregate_payments(payments, network_id, height).map_err(|e| match e {
        crate::payment::PaymentError::MixedPayers => MicroError::MixedPayers,
        crate::payment::PaymentError::Overflow => MicroError::Overflow,
        _ => MicroError::Malformed("payment verify failed"),
    })?;
    let quote = BatchQuote::price(&batch, base_fee_sat_per_gas, input_count)?;
    Ok((batch, quote))
}

/// Build the exact off-chain voucher spec for `through_height`: the newly
/// accrued amount since `settled_sat`, with the next nonce. One voucher per
/// unit of work; only the last one needs to go on chain.
///
/// Refuses: unknown accrual (`None` = overflow), nothing new, over-cap, or a
/// `through_height` at/past expiry (the stream stops accruing there).
pub fn voucher_spec(
    stream: &PaymentStream,
    settled_sat: u64,
    last_nonce: u64,
    through_height: u64,
    reference: Hash,
) -> Result<StreamSettleSpec, MicroError> {
    let accrued = stream.accrued(through_height).ok_or(MicroError::Overflow)?;
    if accrued > stream.max_total_sat {
        return Err(MicroError::OverCap {
            accrued,
            cap: stream.max_total_sat,
        });
    }
    let amount = accrued
        .checked_sub(settled_sat)
        .ok_or(MicroError::Overflow)?;
    if amount == 0 {
        return Err(MicroError::NothingNew);
    }
    if through_height >= stream.expires_at_height {
        return Err(MicroError::Malformed("voucher at/past stream expiry"));
    }
    Ok(StreamSettleSpec {
        through_height,
        amount_sat: amount,
        nonce: last_nonce.checked_add(1).ok_or(MicroError::Overflow)?,
        reference,
    })
}

/// Read the book's settled total for `stream_id`, defaulting to zero for a
/// stream the caller has not opened locally yet (open still required before
/// `StreamBook::settle`; this helper only sizes the next voucher).
pub fn settled_for(book: &StreamBook, stream: &PaymentStream) -> (u64, u64) {
    match book.state(&stream.signing_hash()) {
        Some(st) => (st.settled_sat, st.last_nonce),
        None => (0, 0),
    }
}

/// A sponsor's signed promise to cover the settlement fee for one batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsoredIntent {
    pub network_id: String,
    pub sponsor: Address,
    /// `PaymentBatch` hash the sponsor covers: `sha256(batch.payment_ids)`.
    pub batch_hash: Hash,
    /// Fee satoshis the sponsor covers (must be >= the quote's required fee).
    pub fee_sat: u64,
    /// Sponsor intent expires at this height (exclusive).
    pub expires_at_height: u64,
}

impl SponsoredIntent {
    pub fn signing_hash(&self) -> Hash {
        sha256_dom(
            DOM_SPONSOR_INTENT,
            &[
                self.network_id.as_bytes(),
                &self.sponsor,
                &self.batch_hash,
                &self.fee_sat.to_le_bytes(),
                &self.expires_at_height.to_le_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), MicroError> {
        if self.network_id.is_empty() || self.network_id.len() > MAX_MICRO_NETWORK_ID_LEN {
            return Err(MicroError::Malformed("network id"));
        }
        if self.fee_sat == 0 {
            return Err(MicroError::Malformed("zero fee coverage"));
        }
        if self.expires_at_height == 0 {
            return Err(MicroError::Malformed("no expiry"));
        }
        Ok(())
    }
}

/// Hash identifying one batch for sponsorship: domain-separated over ids.
pub fn batch_hash(payment_ids: &[Hash]) -> Hash {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(payment_ids.len());
    for id in payment_ids {
        parts.push(id);
    }
    sha256_dom(b"srct/sponsored-batch/v1", &parts)
}

/// Sign a fee-coverage intent with the sponsor's wallet.
pub fn sign_sponsor_intent(
    wallet: &Wallet,
    network_id: &str,
    batch: &PaymentBatch,
    fee_sat: u64,
    expires_at_height: u64,
) -> Result<(SponsoredIntent, crate::sig::Bundle, crate::sig::Bundle), MicroError> {
    let sponsor = wallet
        .address()
        .map_err(|_| MicroError::Malformed("sponsor address"))?;
    let intent = SponsoredIntent {
        network_id: network_id.to_string(),
        sponsor,
        batch_hash: batch_hash(&batch.payment_ids),
        fee_sat,
        expires_at_height,
    };
    intent.validate()?;
    let keys = Auth::keys_for(wallet).map_err(|_| MicroError::Malformed("sponsor keys"))?;
    let sigs = Auth::sigs_for(wallet, &intent.signing_hash())
        .map_err(|_| MicroError::SignatureInvalid("sign"))?;
    Ok((intent, sigs, keys))
}

/// Verify a sponsor intent against the batch it claims to cover.
pub fn verify_sponsor_intent(
    intent: &SponsoredIntent,
    sigs: &crate::sig::Bundle,
    keys: &crate::sig::Bundle,
    batch: &PaymentBatch,
    network_id: &str,
    height: u64,
) -> Result<(), MicroError> {
    intent.validate()?;
    if intent.network_id != network_id {
        return Err(MicroError::WrongNetwork {
            expected: intent.network_id.clone(),
            got: network_id.to_string(),
        });
    }
    if height >= intent.expires_at_height {
        return Err(MicroError::Malformed("sponsor intent expired"));
    }
    if intent.batch_hash != batch_hash(&batch.payment_ids) {
        return Err(MicroError::Malformed("intent covers another batch"));
    }
    if intent.fee_sat < batch.declared_fee_sat {
        // Informational only at this layer (the L1 fee is set by the builder),
        // but an intent that does not even cover the declared fees is a
        // mislabeled intent, not coverage.
        return Err(MicroError::Malformed("intent fee below declared fees"));
    }
    let signer = keys
        .address()
        .map_err(|_| MicroError::Malformed("sponsor keys"))?;
    if signer != intent.sponsor {
        return Err(MicroError::SignerNotSponsor {
            signer,
            sponsor: intent.sponsor,
        });
    }
    crate::sig::verify_bundle(sigs, keys, &intent.signing_hash())
        .map_err(|_| MicroError::SignatureInvalid("verify"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{derive_agent_id, AgentRole, SpendPolicy, POLICY_VERSION};
    use crate::service::{build_signed_request, RequestSpec};
    use crate::stream::build_stream;
    use crate::stream::StreamOpenSpec;

    const NET: &str = "srct/testnet";
    const HEIGHT: u64 = 100;
    const EXPIRES: u64 = 9_000;

    fn wallets() -> (Wallet, Wallet) {
        (
            Wallet::from_private_key_bytes(&[7u8; 32], "micro-payer").unwrap(),
            Wallet::from_private_key_bytes(&[8u8; 32], "micro-provider").unwrap(),
        )
    }

    fn policy_for(
        payer: &Wallet,
        provider: &crate::hash::Address,
        service: [u8; 32],
    ) -> SpendPolicy {
        let owner = payer.address().unwrap();
        SpendPolicy {
            version: POLICY_VERSION,
            network_id: NET.to_string(),
            agent_id: derive_agent_id(NET, AgentRole::Machine, &owner),
            owner,
            role: AgentRole::Machine,
            per_tx_max_sat: 1_000_000,
            window_blocks: 1_000,
            cumulative_max_sat: 100_000_000,
            allowed_recipients: vec![*provider],
            allowed_services: vec![service],
            not_before_height: 0,
            expires_at_height: 10_000,
            revoked: false,
            parent_agent_id: None,
        }
    }

    fn test_payments(n: usize, amount: u64) -> (Vec<MachinePayment>, [u8; 32]) {
        let (payer, provider) = wallets();
        let provider_addr = provider.address().unwrap();
        let service = crate::service::derive_service_id(NET, &provider_addr, b"micro-test");
        let policy = policy_for(&payer, &provider_addr, service);
        let mut book = crate::agent::PolicyBook::default();
        let mut out = Vec::new();
        for i in 0..n {
            let req = build_signed_request(
                &payer,
                RequestSpec {
                    network_id: NET.to_string(),
                    payer_type: AgentRole::Machine,
                    service_id: service,
                    recipient: provider_addr,
                    max_amount_sat: amount,
                    expires_at_height: EXPIRES,
                    policy_hash: policy.hash(),
                },
                &[],
            )
            .unwrap();
            let auth = crate::service::authorize_request(
                &mut book,
                &policy,
                NET,
                &req,
                HEIGHT,
                (i + 1) as u64,
            )
            .unwrap();
            let pay = crate::payment::build_signed_payment(
                &payer,
                &auth,
                NET,
                AgentRole::Machine,
                0,
                EXPIRES,
                req.request_id(),
                &[],
            )
            .unwrap();
            out.push(pay);
        }
        (out, service)
    }

    #[test]
    fn batch_quote_shows_savings() {
        let (payments, _) = test_payments(10, 500);
        let (batch, quote) = quote_batch(&payments, NET, HEIGHT, 10, 1).unwrap();
        assert_eq!(batch.payment_ids.len(), 10);
        assert_eq!(quote.payments, 10);
        // One shared base fee vs ten separate ones.
        assert!(quote.savings_sat > 0);
        assert!(
            quote.fee_per_payment_sat
                < 10 * (crate::tx::GAS_TX_BASE
                    + crate::tx::GAS_PER_INPUT
                    + crate::tx::GAS_PER_OUTPUT)
        );
        assert!(quote_batch(&[], NET, HEIGHT, 10, 1).is_err());
    }

    #[test]
    fn vouchers_accrue_exactly_and_refuse_replay() {
        let (payer, provider) = wallets();
        let provider_addr = provider.address().unwrap();
        let stream = build_stream(
            &payer,
            StreamOpenSpec {
                network_id: NET.to_string(),
                payer_type: AgentRole::Human,
                recipient: provider_addr,
                service: None,
                rate_sat_per_block: 10,
                start_height: 100,
                expires_at_height: 200,
                max_total_sat: 1_000,
                nonce: 1,
                policy_hash: [0u8; 32],
            },
        )
        .unwrap();
        // Blocks 100..=104 accrue 50.
        let spec = voucher_spec(&stream, 0, 0, 104, [9u8; 32]).unwrap();
        assert_eq!(spec.amount_sat, 50);
        assert_eq!(spec.nonce, 1);
        // Same height again settles nothing new.
        assert_eq!(
            voucher_spec(&stream, 50, 1, 104, [9u8; 32]),
            Err(MicroError::NothingNew)
        );
        // Next window accrues the delta only.
        let spec2 = voucher_spec(&stream, 50, 1, 109, [9u8; 32]).unwrap();
        assert_eq!(spec2.amount_sat, 50);
        assert_eq!(spec2.nonce, 2);
    }

    #[test]
    fn sponsor_covers_batch_fee() {
        let (payments, _) = test_payments(3, 500);
        let (batch, quote) = quote_batch(&payments, NET, HEIGHT, 10, 1).unwrap();
        let sponsor = Wallet::from_private_key_bytes(&[9u8; 32], "sponsor").unwrap();
        let (intent, sigs, keys) = sign_sponsor_intent(
            &sponsor,
            NET,
            &batch,
            quote.required_fee_sat.max(batch.declared_fee_sat).max(1),
            500,
        )
        .unwrap();
        verify_sponsor_intent(&intent, &sigs, &keys, &batch, NET, HEIGHT).unwrap();
        // Wrong network, expired, or wrong batch all refuse.
        assert!(
            verify_sponsor_intent(&intent, &sigs, &keys, &batch, "srct/other", HEIGHT).is_err()
        );
        assert!(verify_sponsor_intent(&intent, &sigs, &keys, &batch, NET, 600).is_err());
    }
}
