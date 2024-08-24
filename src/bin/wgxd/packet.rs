use std::net::Ipv4Addr;

pub struct IpPacketView<'a> {
    data: &'a [u8],
}

impl<'a> IpPacketView<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    #[cfg(test)]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    #[cfg(test)]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    #[cfg(test)]
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    pub fn source(&self) -> Ipv4Addr {
        [self.data[12], self.data[13], self.data[14], self.data[15]].into()
    }

    pub fn destination(&self) -> Ipv4Addr {
        [self.data[16], self.data[17], self.data[18], self.data[19]].into()
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.data[IP_HEADER_LEN], self.data[IP_HEADER_LEN + 1]])
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.data[IP_HEADER_LEN + 2], self.data[IP_HEADER_LEN + 3]])
    }
}

pub struct IpPacket {
    data: Vec<u8>,
}

impl IpPacket {
    pub fn new_udp(data: &[u8]) -> Self {
        let mut data2 = vec![0_u8; IP_HEADER_LEN + UDP_HEADER_LEN];
        data2.extend_from_slice(data);
        Self { data: data2 }
    }

    pub fn set_id(&mut self, id: u16) {
        let bytes = id.to_be_bytes();
        self.data[4] = bytes[0];
        self.data[5] = bytes[1];
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.data[8] = ttl;
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.data[9] = protocol;
    }

    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.data[12..16].copy_from_slice(&source.octets());
    }

    pub fn set_destination(&mut self, destination: Ipv4Addr) {
        self.data[16..20].copy_from_slice(&destination.octets());
    }

    pub fn set_source_port(&mut self, port: u16) {
        let bytes = port.to_be_bytes();
        self.data[IP_HEADER_LEN] = bytes[0];
        self.data[IP_HEADER_LEN + 1] = bytes[1];
    }

    pub fn set_destination_port(&mut self, port: u16) {
        let bytes = port.to_be_bytes();
        self.data[IP_HEADER_LEN + 2] = bytes[0];
        self.data[IP_HEADER_LEN + 3] = bytes[1];
    }

    pub fn update_ip_checksum(&mut self) {
        self.data[10] = 0;
        self.data[11] = 0;
        let sum = internet_checksum(&self.data[..IP_HEADER_LEN]).to_be_bytes();
        self.data[10] = sum[0];
        self.data[11] = sum[1];
    }

    pub fn update_udp_checksum(&mut self) {
        self.data[IP_HEADER_LEN + 6] = 0;
        self.data[IP_HEADER_LEN + 7] = 0;
        let mut sum = Checksum::new();
        sum.add(&self.data[12..20]); // src, dst
        sum.add(&[
            0_u8,
            self.data[9],
            self.data[IP_HEADER_LEN + 4],
            self.data[IP_HEADER_LEN + 5],
        ]); // zeroes, protocol, udp length
        sum.add(&self.data[IP_HEADER_LEN..]);
        let sum = sum.get();
        let sum = sum.to_be_bytes();
        self.data[IP_HEADER_LEN + 6] = sum[0];
        self.data[IP_HEADER_LEN + 7] = sum[1];
    }

    pub fn into_udp(mut self) -> Vec<u8> {
        self.set_version();
        self.set_protocol(17);
        self.update_ip_checksum();
        self.update_udp_checksum();
        self.data
    }

    fn set_version(&mut self) {
        let version: u8 = 4;
        let ihl: u8 = 5;
        self.data[0] = ihl | (version << 4);
        let total_length: u16 = self.data.len() as u16;
        let total_length = total_length.to_be_bytes();
        self.data[2] = total_length[0];
        self.data[3] = total_length[1];
        let udp_length: u16 = (self.data.len() - IP_HEADER_LEN) as u16;
        let udp_length = udp_length.to_be_bytes();
        self.data[IP_HEADER_LEN + 4] = udp_length[0];
        self.data[IP_HEADER_LEN + 5] = udp_length[1];
        //self.data[6] = 64; // dont fragment
    }
}

const IP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

struct Checksum {
    sum: u32,
}

impl Checksum {
    fn new() -> Self {
        Self { sum: 0 }
    }

    fn add(&mut self, data: &[u8]) {
        for i in (1..data.len()).step_by(2) {
            let w = u16::from_be_bytes([data[i - 1], data[i]]) as u32;
            self.sum += w;
        }
        if data.len() % 2 == 1 {
            let w = u16::from_be_bytes([data[data.len() - 1], 0]) as u32;
            self.sum += w;
        }
    }

    fn get(self) -> u16 {
        let mut sum = self.sum;
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

// https://en.wikipedia.org/wiki/Internet_checksum
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for i in (1..data.len()).step_by(2) {
        sum += u16::from_be_bytes([data[i - 1], data[i]]) as u32;
    }
    if data.len() % 2 == 1 {
        sum += u16::from_be_bytes([data[data.len() - 1], 0]) as u32;
    }
    !(((sum & 0xffff) + (sum >> 16)) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://stackoverflow.com/questions/3987603/how-to-calculate-internet-checksum
    #[test]
    fn test_internet_checksum() {
        let data = [
            0x45_u8, 0x00, 0x00, 0x34, 0x5F, 0x7C, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8,
            0xB2, 0x14, 0xC6, 0xFC, 0xCE, 0x19,
        ];
        assert_eq!(0xD374, internet_checksum(&data));
    }

    #[test]
    fn udp() {
        let expected: [u8; 32] = [
            0x45, 0x00, 0x00, 0x1e, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xf9, 0x40, 0xc0, 0xa8,
            0x00, 0x1f, 0xc0, 0xa8, 0x00, 0x1e, 0x00, 0x14, 0x00, 0x0a, 0x00, 0x0a, 0x35, 0xc5,
            0x48, 0x69, 0x00, 0x00,
        ];
        let len = 30;
        let packet = IpPacketView::new(&expected[..len]);
        assert_eq!(len, packet.total_length() as usize);
        let mut ip_packet = IpPacket::new_udp(&expected[(IP_HEADER_LEN + UDP_HEADER_LEN)..len]);
        ip_packet.set_id(packet.id());
        ip_packet.set_ttl(packet.ttl());
        ip_packet.set_source(packet.source());
        ip_packet.set_destination(packet.destination());
        ip_packet.set_source_port(packet.source_port());
        ip_packet.set_destination_port(packet.destination_port());
        let mut packet = ip_packet.into_udp();
        while packet.len() % 16 != 0 {
            packet.push(0);
        }
        assert_eq!(
            &expected[..IP_HEADER_LEN],
            &packet[..IP_HEADER_LEN],
            "ip headers do not match"
        );
        assert_eq!(
            &expected[..(IP_HEADER_LEN + UDP_HEADER_LEN)],
            &packet[..(IP_HEADER_LEN + UDP_HEADER_LEN)],
            "udp headers do not match"
        );
        assert_eq!(expected, packet.as_slice());
    }
}
