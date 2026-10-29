//! Fiat / stablecoin on- and off-ramps as auditable quote + intent records.
//!
//! A marketplace dies if users cannot enter or exit: price a service in SRCT
//! but let users fund with fiat or stablecoins and convert back when done.
//! Actual custody and compliance live with the ramp provider (exchange,
//! on-ramp widget, OTC desk) off-protocol; this module is the transparent
//! registry layer:
//!
//! - [`RampQuote`]: provider, direction, asset, amount, fee, locked rate,
//!   expiry — signed by the provider with its SRCT wallet (`Auth`), so the
//!   quote is attributable;
//! - [`RampIntent`]: the user's acceptance (quote id + user + provider sig
//!   over both), the settlement reference the provider fills in, and the
//!   terminal state (awaiting fill, filled, refunded).
//!
//! The node is the quote/intent bulletin board and audit trail, never the
//! custodian. Exchange integrations implement the provider side against
//! `POST /v1/ramp/quote|intent` (see `docs/ramps.md`).

use crate::hash::{sha256_dom, Address, Hash};
use crate::l2::Auth;
use crate::wallet::Wallet;

pub const DOM_RAMP_QUOTE: &[u8] = b"srct/ramp-quote/v1";
pub const DOM_RAMP_INTENT: &[u8] = b"srct/ramp-intent/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RampDirection {
    FiatToSrct,
    SrctToFiat,
    StableToSrct,
    SrctToStable,
}

impl RampDirection {
    pub fn as_u8(self) -> u8 {
        match self {
            RampDirection::FiatToSrct => 0,
            RampDirection::SrctToFiat => 1,
            RampDirection::StableToSrct => 2,
            RampDirection::SrctToStable => 3,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RampDirection::FiatToSrct),
            1 => Some(RampDirection::SrctToFiat),
            2 => Some(RampDirection::StableToSrct),
            3 => Some(RampDirection::SrctToStable),
            _ => None,
        }
    }
}

/// A provider's locked quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RampQuote {
    pub network_id: String,
    pub provider: Address,
    pub direction: RampDirection,
    pub asset: String,
    pub asset_minor: u64,
    pub sat_amount: u64,
    pub fee_sat: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

impl RampQuote {
    pub fn id(&self) -> Hash {
        sha256_dom(
            DOM_RAMP_QUOTE,
            &[
                self.network_id.as_bytes(),
                &self.provider,
                &[self.direction.as_u8()],
                self.asset.as_bytes(),
                &self.asset_minor.to_le_bytes(),
                &self.sat_amount.to_le_bytes(),
                &self.fee_sat.to_le_bytes(),
                &self.expires_height.to_le_bytes(),
                &self.nonce.to_le_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), RampError> {
        if self.network_id.is_empty() || self.network_id.len() > 64 {
            return Err(RampError::Malformed("network id"));
        }
        if self.asset.is_empty() || self.asset.len() > 16 {
            return Err(RampError::Malformed("asset"));
        }
        if self.asset_minor == 0 || self.sat_amount == 0 {
            return Err(RampError::Malformed("zero amounts"));
        }
        if self.expires_height == 0 {
            return Err(RampError::Malformed("no expiry"));
        }
        Ok(())
    }
}

/// A user's acceptance of a quote, countersigned by the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RampIntent {
    pub quote_id: Hash,
    pub user: Address,
    pub provider: Address,
    pub fill_ref: String,
    pub filled: bool,
    pub refunded: bool,
}

impl RampIntent {
    pub fn id(&self) -> Hash {
        sha256_dom(
            DOM_RAMP_INTENT,
            &[
                &self.quote_id,
                &self.user,
                &self.provider,
                self.fill_ref.as_bytes(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), RampError> {
        if self.fill_ref.len() > 128 {
            return Err(RampError::Malformed("fill reference"));
        }
        if self.filled && self.refunded {
            return Err(RampError::Malformed("filled and refunded"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RampError {
    Malformed(&'static str),
    SignerMismatch,
    SignatureInvalid,
}

impl std::fmt::Display for RampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RampError::Malformed(w) => write!(f, "malformed ramp record: {w}"),
            RampError::SignerMismatch => write!(f, "ramp signature is not the provider"),
            RampError::SignatureInvalid => write!(f, "ramp signature invalid"),
        }
    }
}

impl std::error::Error for RampError {}

/// Provider signs its quote (attributable pricing).
pub fn sign_quote(
    provider: &Wallet,
    quote: &RampQuote,
) -> Result<(crate::sig::Bundle, crate::sig::Bundle), RampError> {
    quote.validate()?;
    let addr = provider
        .address()
        .map_err(|_| RampError::Malformed("provider address"))?;
    if addr != quote.provider {
        return Err(RampError::SignerMismatch);
    }
    let keys = Auth::keys_for(provider).map_err(|_| RampError::Malformed("provider keys"))?;
    let sigs = Auth::sigs_for(provider, &quote.id()).map_err(|_| RampError::SignatureInvalid)?;
    Ok((sigs, keys))
}

/// Verify a provider-signed quote.
pub fn verify_quote(
    quote: &RampQuote,
    sigs: &crate::sig::Bundle,
    keys: &crate::sig::Bundle,
    height: u64,
) -> Result<(), RampError> {
    quote.validate()?;
    if height > quote.expires_height {
        return Err(RampError::Malformed("quote expired"));
    }
    let signer = keys
        .address()
        .map_err(|_| RampError::Malformed("provider keys"))?;
    if signer != quote.provider {
        return Err(RampError::SignerMismatch);
    }
    crate::sig::verify_bundle(sigs, keys, &quote.id()).map_err(|_| RampError::SignatureInvalid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_sign_verify_and_expiry() {
        let provider = Wallet::from_private_key_bytes(&[4u8; 32], "ramp").unwrap();
        let quote = RampQuote {
            network_id: "srct/testnet".to_string(),
            provider: provider.address().unwrap(),
            direction: RampDirection::StableToSrct,
            asset: "USDC".to_string(),
            asset_minor: 100,
            sat_amount: 101_500,
            fee_sat: 1_000,
            expires_height: 600,
            nonce: 1,
        };
        let (sigs, keys) = sign_quote(&provider, &quote).unwrap();
        verify_quote(&quote, &sigs, &keys, 500).unwrap();
        assert!(verify_quote(&quote, &sigs, &keys, 601).is_err());
    }
}
