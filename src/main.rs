#![feature(int_roundings)]
use bytes::{BytesMut, BufMut, Bytes, Buf};
use bytes_cast::{BytesCast, unaligned};
//https://gitlab.nist.gov/gitlab/qsg/hw-ipcores/packetizer/-/blob/master/doc/packetformat.md

const HEADER_MAGIC: u32  = 0x810b00ff;
const HEADER_VERSION: u8 = 1u8;

struct PacketMaker {
    srcid: u32,
    seqno: u32,
    tlvs: Vec<TLV> // this should be only static tlvs
}

impl PacketMaker {
    fn new(srcid: u32, tlvs: Vec<TLV>) -> PacketMaker {
        PacketMaker { srcid: srcid, seqno: 0, tlvs: tlvs }
    }

    // this should take dynamic tlvs, like timestamp
    fn make(mut self: &mut PacketMaker, payload: Vec<u8>) -> Bytes {
        let len_tlvs: usize = self.tlvs.iter().map(|x| x.len()).sum();
        let headerlength = len_tlvs + HeaderNoTLV::len(); 
        let payloadlength: u16 = payload.len().try_into().unwrap();       
        let header_no_tlv = HeaderNoTLV{
            version: HEADER_VERSION,
            headerlength: headerlength.try_into().unwrap(),
            payloadlength: payloadlength.into(),
            magic: HEADER_MAGIC.into(),
            srcid: self.srcid.into(),
            seqno: self.seqno.into()
        };           
        let mut buf = BytesMut::with_capacity(headerlength+payload.len());
        buf.put_slice(header_no_tlv.as_bytes());
        for tlv in self.tlvs.iter() {
            tlv.write_to(&mut buf)
        }
        buf.put_slice(payload.as_bytes());
        self.seqno +=1;
        return buf.freeze()
    }

}

#[derive(Debug, BytesCast, Clone, Copy, PartialEq)]
#[repr(C)]
struct HeaderNoTLV {
version: u8,
headerlength: u8,
payloadlength: unaligned::U16Be,
magic: unaligned::U32Be,
srcid: unaligned::U32Be,
seqno: unaligned::U32Be
}

impl HeaderNoTLV {
    // fn new_with_next_seqno (mut self: HeaderNoTLV) -> HeaderNoTLV {
    //     self.seqno = (self.seqno.get() + 1).into();
    //     self
    // }
    fn len() -> usize {
        16
    }
    // fn write_to(self: &HeaderNoTLV, buf: &mut BytesMut) {
    //     buf.put_slice(&self.as_bytes());
    // }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
struct Header {
    header_no_tlv: HeaderNoTLV,
    tlvs: Vec<TLV>
}

impl Header{
    fn len(self: &Header) -> usize {
        let len_tlvs: usize = self.tlvs.iter().map(|x| x.len()).sum();
        len_tlvs + HeaderNoTLV::len()
    }
    fn write_to(self: &Header, buf: &mut BytesMut) {
        let mut header_no_tlv_correct_len = self.header_no_tlv.clone();
        header_no_tlv_correct_len.headerlength = u8::try_from(self.len()).unwrap();
        buf.put_slice(header_no_tlv_correct_len.as_bytes());
        for tlv in self.tlvs.iter() {
            tlv.write_to(buf)
        }
    }
    fn as_bytes(self: &Header) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to(&mut buf);
        return buf.to_vec()
    }   
    fn from_bytes(buf: &[u8]) -> Header {
        let mut header_no_tlv: HeaderNoTLV;
        let result = HeaderNoTLV::from_bytes(buf);
        let (header_no_tlv, rest) = result.unwrap();
        let tlv_len = usize::from(header_no_tlv.headerlength)-HeaderNoTLV::len();
        let tlvs = TLV::vec_from_bytes(&rest[..tlv_len]);
        Header{header_no_tlv: *header_no_tlv, tlvs: tlvs}
    }

}

#[derive(Debug, Clone, PartialEq)]
enum TLV {
    Timestamp(u64),
    Null,
    Payloadshape([u16;3]),
    ChannelOffset(u32),
    PayloadLabel6Char([u8;6])
}

impl TLV {
    fn len8bytes(self: &TLV) -> u8 {
        let len8bytes: u8 = match self {
            TLV::Timestamp(_) => 1,
            TLV::Null => 1,
            TLV::Payloadshape(_) => 1,
            TLV::ChannelOffset(_) => 1,
            TLV::PayloadLabel6Char(_) => 1,
        };
        return len8bytes
    }

    fn len(self: &TLV) -> usize {
        return (self.len8bytes()*8).into()
    }

    fn tag (self: &TLV) -> u8 {
        return  match self {
            TLV::Timestamp(_) => 0x11,
            TLV::Null => 0x00,
            TLV::Payloadshape(_) => 0x22,
            TLV::ChannelOffset(_) => 0x23,
            TLV::PayloadLabel6Char(_) => 0x29
            }       
    }

    // promises to write a multiple of 8 bytes
    fn write_to(self: &TLV, buf: &mut BytesMut) {
        buf.put_u8(self.tag());
        buf.put_u8(self.len8bytes());
        match self {
            TLV::Timestamp(x) => {
                let x = unaligned::U64Be::from(*x);
                let b = x.as_bytes();
                buf.put_slice(&b[2..8]);
            },
            TLV::Null => {
                buf.put_bytes(0u8,6);
            },
            TLV::Payloadshape(shape) => {
                for (i,x) in shape.iter().enumerate() {
                    let y : unaligned::U16Be = (*x).into();
                    let y = y.as_bytes();
                    buf.put_u8(y[0]);
                    buf.put_u8(y[1]);
                }               
            },
            TLV::ChannelOffset(x) => {
                buf.put_bytes(0u8,2);
                buf.put_u32(*x);
            },
            TLV::PayloadLabel6Char(x) => {
                buf.put_slice(x.as_bytes());
            }

        }
    }

    fn try_from_bytes(buf: &[u8]) -> (Option<TLV>, &[u8]) {
        if buf.len() < 8 {
            return (None, buf)
        }
        let tag = buf[0];
        let mut bytes = Bytes::copy_from_slice(&buf[..8]);
        let tlv =  match tag {
            0x00 => TLV::Null,
            0x11 => {
                let x = bytes.get_u64();
                let x = x & 0x0000FFFFFFFFFFFF; // ignore the tag and tlv length
                TLV::Timestamp(x)
            },
            0x22 => {
                bytes.advance(2);
                let x = [bytes.get_u16(), bytes.get_u16(), bytes.get_u16()];
                TLV::Payloadshape(x)
            },
            0x23 => {
                bytes.advance(4);
                TLV::ChannelOffset(bytes.get_u32())
            },
            0x29 => {
                let nbytes = buf[1];// check len in bytes
                if nbytes == 1 {
                    let a: [u8;6] = buf[2..8].try_into().unwrap();
                    TLV::PayloadLabel6Char(a)} 
                else {
                    panic!("TLVS longer than 1 byte not supported")
                    }
            }
            x => panic!("tlv tag 0x{:x?} not implemented",x),
        };
        return (Some(tlv), &buf[8..])
    }

    fn vec_from_bytes(buf: &[u8]) -> Vec<TLV> {
        let mut v = Vec::new();
        let mut tlv: Option<TLV>;
        let mut buf = buf;
        loop {
            (tlv, buf) = TLV::try_from_bytes(buf);
            match tlv {
                None => break,
                Some(x) => v.push(x)
            }
        };
        v
    }

    #[allow(dead_code)]
    fn as_bytes(self: &TLV) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to(&mut buf);
        return buf.to_vec()
    }

}



fn main() {
    println!("Hello, world!");
    // let tlv = TLV::Timestamp(3u64);
    // let header_no_tlv = HeaderNoTLV{
    //     version: 1u8,
    //     headerlength: 0u8,
    //     payloadlength: 0u16.into(),
    //     magic: HEADER_MAGIC.into(),
    //     srcid: 0u32.into(),
    //     seqno: 0u32.into()
    // };
    // let header = Header{ header_no_tlv,
    // tlvs: vec![TLV::Timestamp(3), TLV::Null, TLV::Payloadshape([0u16,8,0])]};
    // println!("header {:?}",header.as_bytes());
    // let buf = header.as_bytes();
    // let (header_no_tlv2, rest) = HeaderNoTLV::from_bytes(&buf).unwrap();
    // println!("header_no_tlv {:?}", header_no_tlv.as_bytes());
    // println!("header_no_tlv2 {:?}", header_no_tlv2.as_bytes());
    // assert!(header_no_tlv2.headerlength == u8::try_from(header.as_bytes().len()).unwrap());
    // let (tlv, _) = TLV::try_from_bytes(&TLV::Timestamp(3).as_bytes());
    // let tlv = tlv.unwrap();
    // println!("read this tlv {:?}", tlv);
    // let header2 = Header::from_bytes(&header.as_bytes());
    // println!("header2 {:?}", header2.as_bytes());
    // assert!(header2.as_bytes() == header.as_bytes())
    let tlvs = vec![TLV::Timestamp(3), TLV::Null, TLV::Payloadshape([0u16,8,0])];
    let mut maker = PacketMaker::new(0, tlvs);
    println!("header {:x?}",maker.make(vec![255u8]).as_bytes());
    println!("header {:x?}",maker.make(vec![255u8]).as_bytes());
    println!("header {:x?}",maker.make(vec![255u8]).as_bytes());


   


}

#[test]
fn test_tlv_to_bytes() {
    let tlv = TLV::Timestamp(3u64);
    assert!(tlv.as_bytes() == [0x11, 1,0,0,0,0,0,3]);
    let tlv = TLV::Payloadshape([0u16,8,0]);
    assert!(tlv.as_bytes() == [0x22,1,0,0,0,8,0,0]);
    let tlv = TLV::Null;
    assert!(tlv.as_bytes() == [0x0,1,0,0,0,0,0,0]);
    let tlv = TLV::ChannelOffset(16);
    assert!(tlv.as_bytes() == [0x23,1,0,0,0,0,0,16u8]);
}

#[test]
fn test_header_to_bytes() {
    let header_no_tlv = HeaderNoTLV{
        version: 1u8,
        headerlength: 0u8,
        payloadlength: 0u16.into(),
        magic: HEADER_MAGIC.into(),
        srcid: 0u32.into(),
        seqno: 0u32.into()
    };
    assert!(header_no_tlv.as_bytes() == [0x1, 0, 0, 0, 0x81, 0x0b, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0])   ;
    let header = Header{ header_no_tlv,
        tlvs: vec![TLV::Timestamp(3), TLV::Null, TLV::Payloadshape([0u16,8,0])]}; 
    assert!(header.as_bytes() == [1u8, 40, 0, 0, 129, 11, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 
    17, 1, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 34, 1, 0, 0, 0, 8, 0, 0]);
}