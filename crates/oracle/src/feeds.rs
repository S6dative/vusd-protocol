// crates/oracle/src/feeds.rs
//
// Live BTC/USD price feed adapters for production oracle nodes.
//
// All endpoints are public — no API keys required for ticker data.
// Each adapter implements PriceFeed via a blocking HTTP call.
//
// Exchange endpoints used:
//   Kraken:   https://api.kraken.com/0/public/Ticker?pair=XBTUSD
//   Binance:  https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT
//   Coinbase: https://api.coinbase.com/v2/prices/BTC-USD/spot
//   Bitstamp: https://www.bitstamp.net/api/v2/ticker/btcusd/
//   OKX:      https://www.okx.com/api/v5/market/ticker?instId=BTC-USDT
//
// In production each oracle node should run against all 5 feeds.
// The per-node median + outlier rejection is handled by OracleNode::compute_price().

use crate::{OracleError, PriceFeed};
use std::time::Duration;

/// Shared HTTP client — reuse connections across price polls.
/// Create one per oracle node and pass by reference.
pub struct FeedClient {
    inner: reqwest::blocking::Client,
}

impl FeedClient {
    pub fn new() -> Self {
        FeedClient {
            inner: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .user_agent("vusd-oracle/0.1")
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

impl Default for FeedClient {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// KRAKEN
// ─────────────────────────────────────────────────────────────────────────────

/// Kraken public ticker.
/// Response path: result.XXBTZUSD.c[0]  (last trade closed price)
pub struct KrakenFeed {
    client: reqwest::blocking::Client,
}

impl KrakenFeed {
    pub fn new(client: &FeedClient) -> Self {
        KrakenFeed { client: client.inner.clone() }
    }
}

impl PriceFeed for KrakenFeed {
    fn name(&self) -> &str { "Kraken" }

    fn fetch_price(&self) -> Result<u64, OracleError> {
        #[derive(serde::Deserialize)]
        struct KrakenResponse {
            result: std::collections::HashMap<String, KrakenTicker>,
        }
        #[derive(serde::Deserialize)]
        struct KrakenTicker {
            c: Vec<String>, // [last_trade_price, lot_volume]
        }

        let resp: KrakenResponse = self.client
            .get("https://api.kraken.com/0/public/Ticker?pair=XBTUSD")
            .send()
            .map_err(|e| OracleError::FeedError(format!("Kraken HTTP: {}", e)))?
            .json()
            .map_err(|e| OracleError::FeedError(format!("Kraken JSON: {}", e)))?;

        let ticker = resp.result.values().next()
            .ok_or_else(|| OracleError::FeedError("Kraken: empty result".into()))?;

        parse_price_dollars(&ticker.c[0], "Kraken")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BINANCE
// ─────────────────────────────────────────────────────────────────────────────

pub struct BinanceFeed {
    client: reqwest::blocking::Client,
}

impl BinanceFeed {
    pub fn new(client: &FeedClient) -> Self {
        BinanceFeed { client: client.inner.clone() }
    }
}

impl PriceFeed for BinanceFeed {
    fn name(&self) -> &str { "Binance" }

    fn fetch_price(&self) -> Result<u64, OracleError> {
        #[derive(serde::Deserialize)]
        struct BinanceResponse {
            price: String,
        }

        let resp: BinanceResponse = self.client
            .get("https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT")
            .send()
            .map_err(|e| OracleError::FeedError(format!("Binance HTTP: {}", e)))?
            .json()
            .map_err(|e| OracleError::FeedError(format!("Binance JSON: {}", e)))?;

        parse_price_dollars(&resp.price, "Binance")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COINBASE
// ─────────────────────────────────────────────────────────────────────────────

pub struct CoinbaseFeed {
    client: reqwest::blocking::Client,
}

impl CoinbaseFeed {
    pub fn new(client: &FeedClient) -> Self {
        CoinbaseFeed { client: client.inner.clone() }
    }
}

impl PriceFeed for CoinbaseFeed {
    fn name(&self) -> &str { "Coinbase" }

    fn fetch_price(&self) -> Result<u64, OracleError> {
        #[derive(serde::Deserialize)]
        struct CoinbaseResponse {
            data: CoinbaseData,
        }
        #[derive(serde::Deserialize)]
        struct CoinbaseData {
            amount: String,
        }

        let resp: CoinbaseResponse = self.client
            .get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
            .send()
            .map_err(|e| OracleError::FeedError(format!("Coinbase HTTP: {}", e)))?
            .json()
            .map_err(|e| OracleError::FeedError(format!("Coinbase JSON: {}", e)))?;

        parse_price_dollars(&resp.data.amount, "Coinbase")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BITSTAMP
// ─────────────────────────────────────────────────────────────────────────────

pub struct BitstampFeed {
    client: reqwest::blocking::Client,
}

impl BitstampFeed {
    pub fn new(client: &FeedClient) -> Self {
        BitstampFeed { client: client.inner.clone() }
    }
}

impl PriceFeed for BitstampFeed {
    fn name(&self) -> &str { "Bitstamp" }

    fn fetch_price(&self) -> Result<u64, OracleError> {
        #[derive(serde::Deserialize)]
        struct BitstampResponse {
            last: String,
        }

        let resp: BitstampResponse = self.client
            .get("https://www.bitstamp.net/api/v2/ticker/btcusd/")
            .send()
            .map_err(|e| OracleError::FeedError(format!("Bitstamp HTTP: {}", e)))?
            .json()
            .map_err(|e| OracleError::FeedError(format!("Bitstamp JSON: {}", e)))?;

        parse_price_dollars(&resp.last, "Bitstamp")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OKX
// ─────────────────────────────────────────────────────────────────────────────

pub struct OkxFeed {
    client: reqwest::blocking::Client,
}

impl OkxFeed {
    pub fn new(client: &FeedClient) -> Self {
        OkxFeed { client: client.inner.clone() }
    }
}

impl PriceFeed for OkxFeed {
    fn name(&self) -> &str { "OKX" }

    fn fetch_price(&self) -> Result<u64, OracleError> {
        #[derive(serde::Deserialize)]
        struct OkxResponse {
            data: Vec<OkxTicker>,
        }
        #[derive(serde::Deserialize)]
        struct OkxTicker {
            last: String,
        }

        let resp: OkxResponse = self.client
            .get("https://www.okx.com/api/v5/market/ticker?instId=BTC-USDT")
            .send()
            .map_err(|e| OracleError::FeedError(format!("OKX HTTP: {}", e)))?
            .json()
            .map_err(|e| OracleError::FeedError(format!("OKX JSON: {}", e)))?;

        let ticker = resp.data.first()
            .ok_or_else(|| OracleError::FeedError("OKX: empty data".into()))?;

        parse_price_dollars(&ticker.last, "OKX")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FACTORY
// ─────────────────────────────────────────────────────────────────────────────

/// Build all 5 production feeds for an oracle node.
/// Call once per node, pass the resulting Vec to OracleNode::new().
pub fn production_feeds(client: &FeedClient) -> Vec<Box<dyn PriceFeed>> {
    vec![
        Box::new(KrakenFeed::new(client)),
        Box::new(BinanceFeed::new(client)),
        Box::new(CoinbaseFeed::new(client)),
        Box::new(BitstampFeed::new(client)),
        Box::new(OkxFeed::new(client)),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a price string like "98432.15" into whole dollars (u64).
/// Truncates cents — the oracle's per-feed median and outlier rejection
/// smooths out any truncation bias across 5+ feeds.
fn parse_price_dollars(s: &str, source: &str) -> Result<u64, OracleError> {
    let trimmed = s.trim();
    // Handle "98432.15" or "98432" or "98,432.15"
    let clean: String = trimmed.chars().filter(|c| *c == '.' || c.is_ascii_digit()).collect();

    let dollars = if let Some(dot) = clean.find('.') {
        &clean[..dot]
    } else {
        &clean
    };

    dollars.parse::<u64>()
        .map_err(|_| OracleError::FeedError(format!("{}: cannot parse price {:?}", source, s)))
        .and_then(|p| {
            if p == 0 {
                Err(OracleError::FeedError(format!("{}: zero price", source)))
            } else {
                Ok(p)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_price_whole() {
        assert_eq!(parse_price_dollars("98432", "test").unwrap(), 98432);
    }

    #[test]
    fn test_parse_price_with_cents() {
        assert_eq!(parse_price_dollars("98432.75", "test").unwrap(), 98432);
    }

    #[test]
    fn test_parse_price_high_precision() {
        assert_eq!(parse_price_dollars("100000.00000000", "test").unwrap(), 100000);
    }

    #[test]
    fn test_parse_price_zero_rejected() {
        assert!(parse_price_dollars("0.00", "test").is_err());
    }

    #[test]
    fn test_parse_price_garbage_rejected() {
        assert!(parse_price_dollars("not_a_price", "test").is_err());
    }
}
