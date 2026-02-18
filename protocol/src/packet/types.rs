//the core data types we will be using in our packet structure, like flags, compression types, encryption levels, etc. This is where we define the building blocks of our protocol.
//zero copy, avoid unnecessary copying of data, we will be using references and slices to handle payloads and other data efficiently.
//each connection has a unique id
use std::fmt;

// ============================================================================
// PROTOCOL VERSION
// ============================================================================
// We start at version 1. Future versions can add features while staying compatible
pub const FDP_VERSION: u8 = 1;

// ============================================================================
// INTENT TYPES - What the user WANTS to do
// ============================================================================
// This is REVOLUTIONARY compared to HTTP's GET/POST/PUT/DELETE
// We express SEMANTIC meaning, not just CRUD operations
//
// Each Intent is 1 byte (u8), so we can have 256 different intents
#[repr(u8)]  // This means: store as a single byte
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    // ---------- BASIC OPERATIONS ----------
    /// Ping to check if connection is alive
    Ping = 0x01,
    
    /// Response to a ping
    Pong = 0x02,
    
    /// Establish a new session
    HandshakeInit = 0x03,
    
    /// Acknowledge handshake
    HandshakeAck = 0x04,
    
    /// Gracefully close session
    Close = 0x05,
    
    // ---------- SEARCH OPERATIONS ----------
    /// Perform a search query
    /// Payload: search terms + filters
    Search = 0x10,
    
    /// Get suggested completions as user types
    SearchSuggest = 0x11,
    
    /// Fetch a specific document by hash
    FetchDocument = 0x12,
    
    /// Subscribe to search result updates (real-time)
    SearchStream = 0x13,
    
    // ---------- DATA SYNC ----------
    /// Request specific data by content hash
    DataRequest = 0x20,
    
    /// Push data to receiver
    DataPush = 0x21,
    
    /// Notify about data changes (delta sync)
    DataDelta = 0x22,
    
    /// Verify data integrity
    DataVerify = 0x23,
    
    // ---------- RANKING & PERSONALIZATION ----------
    /// Upload user ranking preferences (encrypted)
    RankingUpdate = 0x30,
    
    /// Request personalized ranking for results
    RankingRequest = 0x31,
    
    // ---------- EDGE/CACHE ----------
    /// Request from edge cache
    CacheQuery = 0x40,
    
    /// Invalidate cached data
    CacheInvalidate = 0x41,
    
    // ---------- ERROR & STATUS ----------
    /// Generic error response
    Error = 0xF0,
    
    /// Success acknowledgment
    Success = 0xF1,
}

impl Intent {
    /// Convert a byte to an Intent
    /// Returns None if the byte doesn't match any known Intent
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Intent::Ping),
            0x02 => Some(Intent::Pong),
            0x03 => Some(Intent::HandshakeInit),
            0x04 => Some(Intent::HandshakeAck),
            0x05 => Some(Intent::Close),
            0x10 => Some(Intent::Search),
            0x11 => Some(Intent::SearchSuggest),
            0x12 => Some(Intent::FetchDocument),
            0x13 => Some(Intent::SearchStream),
            0x20 => Some(Intent::DataRequest),
            0x21 => Some(Intent::DataPush),
            0x22 => Some(Intent::DataDelta),
            0x23 => Some(Intent::DataVerify),
            0x30 => Some(Intent::RankingUpdate),
            0x31 => Some(Intent::RankingRequest),
            0x40 => Some(Intent::CacheQuery),
            0x41 => Some(Intent::CacheInvalidate),
            0xF0 => Some(Intent::Error),
            0xF1 => Some(Intent::Success),
            _ => None,
        }
    }
    
    /// Convert Intent to byte for sending over network
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// COMPRESSION TYPES
// ============================================================================
// Different compression algorithms, ranked by speed vs compression ratio
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// No compression (useful for already compressed data like images)
    None = 0x00,
    
    /// LZ4 - SUPER FAST, decent compression (~2-3x)
    /// Best for: real-time communication, small packets
    Lz4 = 0x01,
    
    /// Zstd - FAST, good compression (~3-5x)
    /// Best for: general purpose, balanced speed/ratio
    Zstd = 0x02,
    
    /// Brotli - SLOWER, best compression (~4-6x)
    /// Best for: static content, one-time transfers
    Brotli = 0x03,
}

impl Compression {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Compression::None),
            0x01 => Some(Compression::Lz4),
            0x02 => Some(Compression::Zstd),
            0x03 => Some(Compression::Brotli),
            _ => None,
        }
    }
    
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// ENCRYPTION LEVEL
// ============================================================================
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionLevel {
    /// NO ENCRYPTION - Only use for testing on localhost!
    /// NEVER use on real network
    None = 0x00,
    
    /// ChaCha20-Poly1305 - Fast, secure, modern
    /// This is what we use by default
    ChaCha20 = 0x01,
    
    /// AES-256-GCM - Industry standard, hardware accelerated on most CPUs
    Aes256 = 0x02,
}

impl EncryptionLevel {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(EncryptionLevel::None),
            0x01 => Some(EncryptionLevel::ChaCha20),
            0x02 => Some(EncryptionLevel::Aes256),
            _ => None,
        }
    }
    
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// SESSION ID - Unique identifier for each connection
// ============================================================================
// 16 bytes = 128 bits = enough for 2^128 unique sessions
// This is more IDs than atoms in the universe, so we'll never run out
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Create a new random session ID
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // For now, use timestamp + random bytes
        // In production, use a proper UUID library
        let mut bytes = [0u8; 16];
        
        // First 8 bytes: timestamp (nanoseconds)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        bytes[0..8].copy_from_slice(&timestamp.to_be_bytes());
        
        // Last 8 bytes: random (in production, use crypto RNG)
        // For now, use timestamp again (NOT SECURE, just for prototype)
        bytes[8..16].copy_from_slice(&timestamp.to_le_bytes());
        
        SessionId(bytes)
    }
    
    /// Create from existing bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        SessionId(bytes)
    }
    
    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Display as hex string: "1a2b3c4d..."
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ============================================================================
// PRIORITY LEVELS
// ============================================================================
// Higher number = higher priority
// This lets urgent packets skip ahead in the queue
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub u8);

impl Priority {
    /// Lowest priority - background tasks
    pub const LOWEST: Priority = Priority(0);
    
    /// Low priority - prefetching, caching
    pub const LOW: Priority = Priority(64);
    
    /// Normal priority - user-initiated actions
    pub const NORMAL: Priority = Priority(128);
    
    /// High priority - important user interactions
    pub const HIGH: Priority = Priority(192);
    
    /// Critical priority - system messages, errors
    pub const CRITICAL: Priority = Priority(255);
}

// ============================================================================
// TESTS - Make sure our types work correctly
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_intent_roundtrip() {
        // Test that we can convert Intent to byte and back
        let intent = Intent::Search;
        let byte = intent.to_u8();
        let recovered = Intent::from_u8(byte).unwrap();
        assert_eq!(intent, recovered);
    }
    
    #[test]
    fn test_session_id_creation() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        
        // Two IDs should be different (probability of collision is astronomically low)
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_priority_ordering() {
        assert!(Priority::CRITICAL > Priority::HIGH);
        assert!(Priority::HIGH > Priority::NORMAL);
        assert!(Priority::NORMAL > Priority::LOW);
        assert!(Priority::LOW > Priority::LOWEST);
    }
    
    #[test]
    fn test_compression_bytes() {
        assert_eq!(Compression::Lz4.to_u8(), 0x01);
        assert_eq!(Compression::from_u8(0x02).unwrap(), Compression::Zstd);
    }
}