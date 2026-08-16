use serde::{serialize, Deserialize};
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Payloadformat{
    Rawbinary =0x00;
    Json=0x01;
    Messasgepack=0x02;
    Bson=0x03;
    Protobuf=0x04;
    Custom=0xFF;

}

impl Payloadformat{
    pub fn from_u8(byte: u8)-> Option<Self>{
        match byte{
            0x00 => Some(Payloadformat::Rawbinary),
            0x01 => Some(Payloadformat::Json),
            0x02 => Some(Payloadformat::Messasgepack),
            0x03 => Some(Payloadformat::Bson),
            0x04 => Some(Payloadformat::Protobuf),
            0xFF => Some(Payloadformat::Custom),
            _ => None,
        }
    }
}