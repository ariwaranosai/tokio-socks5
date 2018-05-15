#[macro_use]
extern crate log;
extern crate env_logger;
extern crate tokio;
extern crate tokio_io;
extern crate trust_dns;
extern crate futures;

use std::{env, str};
use std::time::{Duration, Instant};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use trust_dns::udp::UdpClientStream;
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::op::{ResponseCode, DnsResponse};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

use tokio_io::io;
use futures::future;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;


fn main() {
    drop(env_logger::init());

    let addr = env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());
    let addr = addr.parse::<SocketAddr>().unwrap();

    let listener = TcpListener::bind(&addr).unwrap();

    let dns = "114.114.114.114:53".parse().unwrap();

    let (stream, sender) = UdpClientStream::new(dns);
    let dns_client = ClientFuture::new(stream, sender, None);

    println!("Listening for socks5 proxy connections on {}", addr);

    let server = dns_client.then(move |res| {
        match res {
            Ok(dns) =>  {
                 let tcp_listener = listener.incoming().for_each(move |tcp| {
                     let addr = tcp.peer_addr().unwrap();
                     println!("connected from {}", &addr);
                     let client = (Client {
                         dns: dns.clone()
                     }).serve(tcp).then(move |res| {
                         match res {
                             Ok((a, b)) => {
                                 println!("proxied {}/{} bytes for {}", a, b, addr)
                             }
                             Err(e) => println!("error for {}: {}", addr, e),
                         }
                         Ok(())
                     }).map_err(|e| e);
                     tokio::spawn(client);
                     Ok(())
                 }).map_err(|err| {
                     println!("server error {:?}", err);
                 });

                tokio::spawn(tcp_listener);
            }
            Err(e) => println!("dns error {:?}", e)
        }

        Ok(())
    });

    tokio::run(server);
}

struct Client {
    dns: BasicClientHandle,
}

impl Client {
    fn serve(self, conn: TcpStream) -> impl Future<Item=(u64, u64), Error=std::io::Error> + Send {
        io::read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            match buf[0] {
                v5::VERSION => self.serve_v5(conn),
                v4::VERSION => self.serve_v4(conn),
                _ => Box::new(future::err(other("unknown version")))
            }
        })
    }

    fn serve_v4(self, _conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=std::io::Error> + Send> {
        Box::new(future::err(other("unimplemented")))
    }

    fn serve_v5(self, conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=std::io::Error> + Send> {
        let num_methods = io::read_exact(conn, [0u8]);

        let authenticated = Box::new(num_methods.and_then(|(conn, buf)| {
            io::read_exact(conn, vec![0u8; buf[0] as usize])
        }).and_then(|(conn, buf)| {
            if buf.contains(&v5::METH_NO_AUTH) {
                Ok(conn)
            } else {
                Err(other("no supported method given"))
            }
        }));

        let part1 = Box::new(authenticated.and_then(|conn| {
            io::write_all(conn, [v5::VERSION, v5::METH_NO_AUTH])
        }));

        let ack = Box::new(part1.and_then(|(conn, _)| {
            io::read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0]  == v5::CMD_CONNECT {
                    Ok(conn)
                } else {
                    Err(other("didn't confirm with v5 version"))
                }
            })
        }));

        let command = Box::new(ack.and_then(|conn| {
            io::read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::CMD_CONNECT {
                    Ok(conn)
                } else {
                    Err(other("unsupported command"))
                }
            })
        }));

        let mut dns = self.dns.clone();
        let resv = command.and_then(|c| io::read_exact(c, [0u8]).map(|c| c.0));
        let atyp = resv.and_then(|c| io::read_exact(c, [0u8]));

        let addr = mybox( atyp.and_then(move |(c, buf)| {
            match buf[0] {
                v5::ATYP_IPV4 => {
                    mybox(io::read_exact(c, [0u8; 6]).map(|(c, buf)| {
                        let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                        let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let addr = SocketAddrV4::new(addr, port);
                        (c, SocketAddr::V4(addr))
                    }))
                }

                v5::ATYP_IPV6 => {
                    mybox(io::read_exact(c, [0u8; 18]).map(|(conn, buf)| {
                        let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                        let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                        let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                        let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                        let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                        let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                        let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                        let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                        let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                        let addr = SocketAddrV6::new(addr, port, 0, 0);
                        (conn, SocketAddr::V6(addr))
                    }))
                }

                v5::ATYP_DOMAIN => {
                    mybox(io::read_exact(c, [0u8]).and_then(|(conn, buf)| {
                        io::read_exact(conn, vec![0u8; buf[0] as usize + 2])
                    }).and_then(move |(conn, buf)| {
                        let (name, port) = match name_port(&buf) {
                            Ok(UrlHost::Name(name, port)) => (name, port),
                            Ok(UrlHost::Addr(addr)) => {
                                return mybox(future::ok((conn, addr)))
                            }
                            Err(e) => return mybox(future::err(e))
                        };

                        let ipv4 = dns.query(name, DNSClass::IN, RecordType::A)
                            .map_err(|e| other(&format!("dns error: {}", e)))
                            .and_then(move |r| get_addr(r, port));
                        mybox(ipv4.map(|addr| (conn, addr)))
                    }))
                }

                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                }
            }})
        );

        let connected = mybox(addr.and_then(move |(c, addr)| {
            debug!("proxying to {}", addr);
            TcpStream::connect(&addr).then(move |c2| Ok((c, c2, addr)))
        }));

        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            let mut resp = [0u8; 32];

            resp[0] = 5;

            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            resp[2] = 0;


            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) |
                Err(..) => addr,
            };
            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };

            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;


            let mut w = io::Window::new(resp);
            let timeout = Instant::now() + Duration::from_secs(10);
            w.set_end(pos + 2);
            io::write_all(c1, w).deadline(timeout)
                .map_err(|_| other("timeout during handshake"))
                .and_then(|(c1, _)| {
                    c2.map(|c2|(c1, c2))
                })
        }));

        mybox( handshake_finish.and_then(|(c1, c2)| {
            let (c1_reader, c1_writer) = c1.split();
            let (c2_reader, c2_writer) = c2.split();

            let half1 = io::copy(c1_reader, c2_writer);
            let half2 = io::copy(c2_reader, c1_writer);

            half1.join(half2).map(|((n1, _, _), (n2, _, _))| (n1, n2))
        }))
    }

}

fn mybox<F: Future + 'static + Send>(f: F) -> Box<Future<Item=F::Item, Error=F::Error> + Send> {
    Box::new(f)
}

fn other(desc: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, desc)
}

enum UrlHost {
    Name(Name, u16),
    Addr(SocketAddr),
}

fn name_port(addr_buf: &[u8]) -> std::io::Result<UrlHost> {
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = str::from_utf8(hostname).map_err(|_e| {
        other("hostname buffer provided was not valid utf-8")
    })?;
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(UrlHost::Addr(SocketAddr::new(ip, port)))
    }
    let name = Name::parse(hostname, Some(&Name::root())).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    })?;
    Ok(UrlHost::Name(name, port))
}

fn get_addr(response: DnsResponse, port: u16) -> std::io::Result<SocketAddr> {
    if response.response_code() != ResponseCode::NoError {
        return Err(other("resolution failed"));
    }

    let addr = response.answers().iter().filter_map(|ans| {
        match *ans.rdata() {
            RData::A(addr) => Some(IpAddr::V4(addr)),
            RData::AAAA(addr) => Some(IpAddr::V6(addr)),
            _ => None
        }
    }).next();

    match addr {
        Some(addr) => Ok(SocketAddr::new(addr, port)),
        None => Err(other("no address records in response")),
    }
}

// Various constants associated with the SOCKS protocol

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

#[allow(dead_code)]
mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}
