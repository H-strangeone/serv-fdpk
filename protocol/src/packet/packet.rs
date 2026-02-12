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
            priority: Priority::Normal,
            flags,
        }   
    }
}