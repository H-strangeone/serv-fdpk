use serde::{serialize, Deserialize};
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Payloadformat{
    rawbinary =0x00;
    
}