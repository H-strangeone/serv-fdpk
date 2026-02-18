//this is the packet format showing how the data actually looks like on the wire
//the layout is like this:
// byte 0    | version (1 byte) -protocol version
// byte 1-16 | session id 16 bytes -who is talking
// byte 17   | intent (1 byte) -what do you want to do
// byte 18   | priority (1 byte) -how important is this packet and how urgent
// byte 19   | flags (1 byte) -extra info about the packet like compression encryption and all
// byte 20-23| sequence number (4 bytes) -to keep track of packets
// byte 24-27| payload length (4 bytes) -how much data is in the payload
// byte 28-35| timestamp (8 bytes) -when was this packet sent
// byte 36+  | payload (variable length) -the actual data being sent
// last 32   | hash (32 bytes) -to verify data integrity

//total header size is 36 bytes


use super::types::*;//importing types from types module

use std::time::{SystemTime, UNIX_EPOCH};//for timestamp generation





//constants
pub const HEADER_SIZE: usize = 36;
pub const HASH_SIZE: usize = 32;
pub const MIN_PACKET_SIZE: usize = HEADER_SIZE + HASH_SIZE;//minimum size of a valid packet since payload can be zero length
pub const MAX_PAYLOAD_SIZE: usize = 10,485,760;//taking 10MB as max packet size for now
pub const MAX_PACKET_SIZE:usize = HEADER_SIZE + MAX_PAYLOAD_SIZE + HASH_SIZE;//max packet size




// ============================================================================
// Flags - 1 byte
// ============================================================================
// Using bit flags to pack multiple booleans into 1 byte
//
// Bit layout:
// 7 6 5 4 3 2 1 0 
//           _____ Compression (3 bits(1,2,3) = 8 options)
//       ___ Encryption (2 bits(4,5) = 4 options)
//     _ Fragmented (1 bit(6))
//   _ Ack Required (1 bit(7))
//_ I am leaving this for future atp

pub struct Flags(pub u8);// Doinng this for type safety, so we don't mix flags with other u8 values, voila newtype pattern

impl Flags {
    // New flags with default values
    pub fn new() -> Self {
        Flags(0)// Initial state with all flags cleared
    }
    // 8 states we are getting from 000 to 111
    // compression type (bits 0-2)
    pub fn set_compression(&mut self, compression: Compression) {// compression => enum
        // Clear compression bits
        self.0 &= 0b11111000;
        // Set new compression
        self.0 |= compression.to_u8() & 0b00000111;
    }
    
    // Get compression type
    pub fn compression(&self) -> Compression {
        let comp_bits = self.0 & 0b00000111;
        Compression::from_u8(comp_bits).unwrap_or(Compression::None)
    }

    // Set encryption level (bits 3-4)
    pub fn set_encryption(&mut self, encryption: EncryptionLevel) {
        // Clear encryption bits
        self.0 &= 0b11100111;
        // Set new encryption (shifted left 3 bits)
        self.0 |= (encryption.to_u8() & 0b00000011) << 3; // why shift left 3? because 
                                                          // bits 3 and 4 are for encryption and encryption.to_u8() gives us value not the position
    }
    
    // Get encryption level
    pub fn encryption(&self) -> EncryptionLevel {
        let enc_bits = (self.0 >> 3) & 0b00000011;
        EncryptionLevel::from_u8(enc_bits).unwrap_or(EncryptionLevel::None)
    }
    
    // fragmented flag (bit 5)
    // True if this packet is part of a larger message
    pub fn set_fragmented(&mut self, fragmented: bool) {
        if fragmented {
            self.0 |= 0b00100000;
        } else {
            self.0 &= 0b11011111;
        }
    }
    
    // to check if packet is fragmented cause then we need to handle reassembly
    pub fn is_fragmented(&self) -> bool {
        (self.0 & 0b00100000) != 0
    }
    
    // ack required flag (bit 6)
    // True if sender expects acknowledgment
    pub fn set_ack_required(&mut self, required: bool) {
        if required {
            self.0 |= 0b01000000;
        } else {
            self.0 &= 0b10111111;
        }
    }
    
    // Check if ack is required
    pub fn ack_required(&self) -> bool {
        (self.0 & 0b01000000) != 0
    }
}
#[derive(Debug, Clone)]
pub struct Packet{
    pub version: u8 // maybe i will use a wrapper later if we add anything else which is also if type u8
    
    pub session_id: SessionId, // session identifier
    
    pub intent: Intent, // what this packet wants to do
    
    pub priority: Priority, // some might have less priority so we dont always have to hash them 

    pub flags: Flags,

    pub sequence: Sequence, // for reordering and duplicate detection

    pub timestamp: u64, // timestamp of when this was created to hash and also to see if its a replay attack or any old session

    pub payload: Vec<u8> // the actual data that the packet holds

    pub hash: [u8; 32]
}
impl Packet {
    pub fn new(session_id: SessionId, intent: Intent, payload: Vec<u8>) -> Self {
        let mut flags = Flags::new();
        flags.set_compression(Compression::Lz4);
        flags.set_encryption(EncryptionLevel::ChaCha20);
        let mut packet=Packet{
            version:FDP_Version,
            session_id,
            intent,
            priority: Priority::Normal,//sane default priority, we can change it later based on intent or other factors
            flags,
            sequence: 0, // sequence will be set by the connection manager when sending
            timestamp:Self::current_timestamp(),
        }   
    }
    /// Get current timestamp in milliseconds
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    
    /// Calculate SHA256 hash of packet (except the hash field itself)
    fn calculate_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        
        // Hash all fields except the hash itself
        hasher.update(&[self.version]);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&[self.intent.to_u8()]);
        hasher.update(&[self.priority.0]);
        hasher.update(&[self.flags.0]);
        hasher.update(&self.sequence.to_be_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&(self.payload.len() as u32).to_be_bytes());
        hasher.update(&self.payload);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Verify packet integrity
    pub fn verify(&self) -> bool {
        let calculated_hash = self.calculate_hash();
        calculated_hash == self.hash
    }
    
    /// Serialize packet to bytes for sending over network
    /// 
    /// This is THE critical function - it converts our struct to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_size = HEADER_SIZE + self.payload.len() + HASH_SIZE;
        let mut buffer = Vec::with_capacity(total_size);
        
        // Byte 0: Version
        buffer.push(self.version);
        
        // Bytes 1-16: Session ID
        buffer.extend_from_slice(self.session_id.as_bytes());
        
        // Byte 17: Intent
        buffer.push(self.intent.to_u8());
        
        // Byte 18: Priority
        buffer.push(self.priority.0);
        
        // Byte 19: Flags
        buffer.push(self.flags.0);
        
        // Bytes 20-23: Sequence number (big-endian)
        buffer.extend_from_slice(&self.sequence.to_be_bytes());
        
        // Bytes 24-27: Payload length (big-endian)
        buffer.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        
        // Bytes 28-35: Timestamp (big-endian)
        buffer.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // Bytes 36+: Payload
        buffer.extend_from_slice(&self.payload);
        
        // Last 32 bytes: Hash
        buffer.extend_from_slice(&self.hash);
        
        buffer
    }
    
    /// Deserialize bytes back into a Packet
    /// 
    /// This is the reverse - turn raw bytes into our struct
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PacketError> {
        // Minimum size check
        if bytes.len() < MIN_PACKET_SIZE {
            return Err(PacketError::TooSmall);
        }
        
        // Maximum size check
        if bytes.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge);
        }
        
        // Parse header
        let version = bytes[0];
        
        // Check version compatibility
        if version != FDP_VERSION {
            return Err(PacketError::UnsupportedVersion(version));
        }
        
        // Session ID
        let mut session_bytes = [0u8; 16];
        session_bytes.copy_from_slice(&bytes[1..17]);
        let session_id = SessionId::from_bytes(session_bytes);
        
        // Intent
        let intent = Intent::from_u8(bytes[17])
            .ok_or(PacketError::InvalidIntent(bytes[17]))?;
        
        // Priority
        let priority = Priority(bytes[18]);
        
        // Flags
        let flags = Flags(bytes[19]);
        
        // Sequence
        let mut seq_bytes = [0u8; 4];
        seq_bytes.copy_from_slice(&bytes[20..24]);
        let sequence = u32::from_be_bytes(seq_bytes);
        
        // Payload length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[24..28]);
        let payload_len = u32::from_be_bytes(len_bytes) as usize;
        
        // Timestamp
        let mut time_bytes = [0u8; 8];
        time_bytes.copy_from_slice(&bytes[28..36]);
        let timestamp = u64::from_be_bytes(time_bytes);
        
        // Verify payload length matches actual data
        let expected_total = HEADER_SIZE + payload_len + HASH_SIZE;
        if bytes.len() != expected_total {
            return Err(PacketError::LengthMismatch);
        }
        
        // Extract payload
        let payload = bytes[36..36 + payload_len].to_vec();
        
        // Extract hash
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[36 + payload_len..]);
        
        let packet = Packet {
            version,
            session_id,
            intent,
            priority,
            flags,
            sequence,
            timestamp,
            payload,
            hash,
        };
        
        // Verify integrity
        if !packet.verify() {
            return Err(PacketError::InvalidHash);
        }
        
        Ok(packet)
    }
    
    /// Get the size of this packet in bytes
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.payload.len() + HASH_SIZE
    }
}

#[derive(Debug)]
pub enum PacketError {
    TooSmall,
    TooLarge,
    UnsupportedVersion(u8),
    InvalidIntent(u8),
    LengthMismatch,
    InvalidHash,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PacketError::TooSmall => write!(f, "Packet too small"),
            PacketError::TooLarge => write!(f, "Packet too large"),
            PacketError::UnsupportedVersion(v) => write!(f, "Unsupported version: {}", v),
            PacketError::InvalidIntent(i) => write!(f, "Invalid intent: {}", i),
            PacketError::LengthMismatch => write!(f, "Payload length mismatch"),
            PacketError::InvalidHash => write!(f, "Hash verification failed"),
        }
    }
}

impl std::error::Error for PacketError {}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_roundtrip() {
        // Create a packet
        let session = SessionId::new();
        let payload = b"Hello, FDP!".to_vec();
        let packet = Packet::new(session, Intent::Search, payload.clone());
        
        // Serialize to bytes
        let bytes = packet.to_bytes();
        
        // Deserialize back
        let recovered = Packet::from_bytes(&bytes).unwrap();
        
        // Verify everything matches
        assert_eq!(packet.version, recovered.version);
        assert_eq!(packet.session_id, recovered.session_id);
        assert_eq!(packet.intent, recovered.intent);
        assert_eq!(packet.payload, recovered.payload);
        assert_eq!(packet.hash, recovered.hash);
    }
    
    #[test]
    fn test_flags() {
        let mut flags = Flags::new();
        
        // Set compression
        flags.set_compression(Compression::Zstd);
        assert_eq!(flags.compression(), Compression::Zstd);
        
        // Set encryption
        flags.set_encryption(EncryptionLevel::Aes256);
        assert_eq!(flags.encryption(), EncryptionLevel::Aes256);
        
        // Set fragmented
        flags.set_fragmented(true);
        assert!(flags.is_fragmented());
        
        // Set ack required
        flags.set_ack_required(true);
        assert!(flags.ack_required());
        
        // Make sure compression didn't change when we set other flags
        assert_eq!(flags.compression(), Compression::Zstd);
    }
    
    #[test]
    fn test_hash_verification() {
        let session = SessionId::new();
        let packet = Packet::new(session, Intent::Ping, vec![1, 2, 3]);
        
        // Should verify correctly
        assert!(packet.verify());
        
        // Tamper with payload
        let mut tampered = packet.clone();
        tampered.payload[0] = 99;
        
        // Should fail verification
        assert!(!tampered.verify());
    }
    
    #[test]
    fn test_packet_size() {
        let session = SessionId::new();
        let payload = vec![0u8; 1000]; // 1KB payload
        let packet = Packet::new(session, Intent::DataPush, payload);
        
        let expected_size = HEADER_SIZE + 1000 + HASH_SIZE;
        assert_eq!(packet.size(), expected_size);
    }
}