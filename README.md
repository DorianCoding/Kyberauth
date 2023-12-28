# Kyberauth
[![License](https://img.shields.io/crates/l/pqc_kyber)](https://github.com/DorianCoding/Kyberauth/blob/main/LICENSE-MIT)
[![dependency status](https://deps.rs/repo/github/DorianCoding/Kyberauth/status.svg)](https://deps.rs/repo/github/DorianCoding/Kyberauth)

A rust implementation of the Kyber algorithm, a KEM standardised by the NIST Post-Quantum Standardization Project, combined with a verification of keys and use of encapsulated key in AES-GCM in TCP sockets.

This library:
* Is fully written in Rust.
* Is compatible for Windows, Unix.
* Compatible with i383 and x86_64 architectures.


Please read the [**security considerations**](#security-considerations) before use.

**Minimum Supported Rust Version: 1.73.0**

---

## Installation

```shell
cargo add kyberauth
```
OR on Cargo.toml

```rust
[dependencies]
regex = { git = "https://github.com/DorianCoding/Kyberauth.git" }
```

## Usage 

```rust
use kyberauth::*;
```
---
### KEM generation

```rust
fn createkeys() -> Result<KeyPair, KyberError> {
    let mut rng = rand::thread_rng();
    let mut keys = keypair(&mut rng)?;
    Ok(keys)
}
```
### Server and client interface

#### Client

```rust
async fn server() -> Result<(), KyberError> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
    let listener = server::startlistener(addr).await;
    let listener = match listener {
        Ok(listener) => listener,
        Err(_) => {
            return Err(KyberError::InvalidInput);
        }
    };
    let _ = match server::listener(&keys, listener, false).await {
        Ok(mut elem) => {
            elem.senddata(TEST.as_bytes()).await.unwrap();
            return Ok(());
        }
        Err(e) => {
            return Err(KyberError::InvalidInput);
        }
    };
}
```
#### Server

```rust
async fn client() -> Result<(), KyberError> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 43050);
    let _ = match client::connecter(&keys, addr).await {
        Ok(mut elem) => {
            let text = elem.receivedata().await.unwrap();
            if text.len() == 0 {
                eprintln!("Invalid response!");
                return Err(KyberError::InvalidInput);
            }
            let info = String::from_utf8(text).unwrap();
            assert_eq!(info, TEST);
            println!("The peer is {} and public key is {}",elem.getpeer(),String::from_utf8(elem.getpeerkey(false).unwrap()).unwrap());
            ()
        }
        Err(e) => {
            eprintln!("Error is {}", e);
            return Err(KyberError::InvalidInput);
        }
    };
    Ok(())
}
```

---
## Testing

There is some tests to verify that the library is working fine, you can try them using :

```bash
# This example runs the tests
cargo test
```

---

## Security Considerations 

This library is using some not-verified cryptographic crates. It also uses alone quantum-resistant algorithms based on lattices. It should be used with another KEM that is not implemented here.

Therefore, this library should not be used for safety uses and is given without any warranty.

---

## About

This library uses [KYBER library](https://github.com/Argyle-Software/kyber#about) in Rust, as well as [AES-GCM](https://docs.rs/aes-gcm/latest/aes_gcm/) as cryptographic algorithms.

## Contributing 

Contributions are welcome. Feel free to pull requests or to share any ideas.

## License

This library is shared under Apache2-0 OR MIT, you can use the one you please.

<details>

<summary>Protocol sent messages and timeline</summary>

```
interface: any
filter: ( port 43050 ) and (ip || ip6)
####
//Key handshake 1 (Client public key)
T +5.770679 127.0.0.1:56968 -> 127.0.0.1:43050 [AP] #4
  0b 34 bc 66 75 40 82 60    56 aa bc 50 95 76 9a f2    .4.fu@.`V..P.v..
  67 9f b0 7c 7a a1 dc 0f    19 97 72 9e 39 8e 8f 28    g..|z.....r.9..(
  2f d3 52 19 fb 97 80 dc    27 8e 40 14 15 7d 07 cc    /.R.....'.@..}..
  08 a3 48 33 00 b0 77 e8    64 72 aa 0c 27 78 32 f3    ..H3..w.dr..'x2.
  39 c4 ac 67 83 fa e0 8b    3a e7 44 af 55 21 69 c8    9..g....:.D.U!i.
  a0 00 26 c7 3f 31 9b 07    f5 02 49 d4 c6 0e 3c 35    ..&.?1....I...<5
  52 53 07 c0 da 68 a2 19    76 bc 86 3b 2e a6 5e 48    RS...h..v..;..^H
  15 7d b4 32 1a 31 0a 90    79 9a c7 24 d2 50 91 b3    .}.2.1..y..$.P..
  74 7f 71 76 45 75 9f 81    14 61 c8 e5 11 d1 55 99    t.qvEu...a....U.
  c3 c7 6d ab 94 03 e2 56    9d fe d7 a4 39 db 55 b9    ..m....V....9.U.
  93 8f 9c b4 6b 22 9b 10    e2 86 76 da da 9d 80 e7    ....k"....v.....
  7b 14 53 0f 55 b1 c9 10    c2 39 86 e0 90 1d 25 90    {.S.U....9....%.
  ec fa 16 1a 29 0e 1b 39    87 60 e4 18 2c aa cd 88    ....)..9.`..,...
  67 8f 07 10 46 34 b2 bb    7c 44 6e ca 91 0f 2e 79    g...F4..|Dn....y
  ac 95 66 9d 69 88 39 b4    b2 0e 69 f1 8c b8 32 47    ..f.i.9...i...2G
  74 bc 1b 55 e4 73 cc 00    91 29 33 ae 1c 65 09 4b    t..U.s...)3..e.K
  43 ce 90 48 2d 14 22 2f    41 35 c0 7e dc 55 ec 89    C..H-."/A5.~.U..
  57 ac 17 b2 22 e2 14 d8    48 05 0a 8c 10 51 39 57    W..."...H....Q9W
  73 80 01 e0 12 60 8c c8    5f 75 97 55 41 9b ab 2e    s....`.._u.UA...
  e2 6a 44 d4 3d 37 e6 7b    ea d9 ae 71 35 8e 6f 28    .jD.=7.{...q5.o(
  03 cb d1 59 59 d1 99 be    96 45 e7 74 2a 8b c9 cc    ...YY....E.t*...
  87 bc 00 f2 09 58 76 e5    02 3b 5b 82 6a 4a 41 a3    .....Xv..;[.jJA.
  b5 1e 18 46 c9 4c b2 4e    3e a2 75 d9 b2 87 63 82    ...F.L.N>.u...c.
  5c 6f 1c 05 09 18 69 8e    72 67 48 68 a4 e9 f2 8a    \o....i.rgHh....
  bf f1 c6 d0 c8 4f 4d f1    48 40 b9 c8 0a e0 79 b6    .....OM.H@....y.
  62 61 f0 40 c6 25 e1 9d    86 72 74 f3 55 7e de 3c    ba.@.%...rt.U~.<
  af 60 8b b3 f1 71 22 73    e3 88 be c2 bd 42 47 4f    .`...q"s.....BGO
  0a 17 49 77 08 2a e8 4a    ba 75 98 19 48 bc 76 54    ..Iw.*.J.u..H.vT
  62 a3 84 38 85 55 44 bb    33 7b 96 8f 72 8f 69 e9    b..8.UD.3{..r.i.
  b5 43 7b 54 44 64 55 68    d8 05 27 c2 2a 34 30 be    .C{TDdUh..'.*40.
  0f c1 62 ef 93 4d 5d 91    97 83 a7 29 d6 91 88 77    ..b..M]....)...w
  37 99 d2 12 06 0c f3 27    b1 53 07 18 0b 4c 53 53    7......'.S...LSS
  06 a8 28 9c 10 25 09 77    09 1b 6f e6 bf fb 3a 59    ..(..%.w..o...:Y
  35 d0 ac 0d fc 9f 11 64    1a da 89 b3 16 29 2d 5e    5......d.....)-^
  5b 26 22 d3 92 7b 3c bc    35 da 5b 03 9b 36 06 fa    [&"..{<.5.[..6..
  c8 d0 f8 a9 e8 38 0c c0    e6 78 04 0c 56 28 66 0f    .....8...x..V(f.
  59 9a 8d d5 92 a4 64 52    43 a9 99 c9 60 4b 08 7a    Y.....dRC...`K.z
  79 56 ff 81 50 58 b2 6f    80 12 0d e6 77 9e 6c 0c    yV..PX.o....w.l.
  5d 6d a1 36 67 30 b5 5a    60 cb 45 00 1b 76 10 89    ]m.6g0.Z`.E..v..
  9f 7c ac 42 43 0a 25 91    4f 02 47 c7 9e e5 60 e2    .|.BC.%.O.G...`.
  db 87 d3 e6 12 04 58 89    92 08 60 18 53 37 75 9a    ......X...`.S7u.
  7c 50 b5 86 72 69 09 f8    c5 6b 4d 11 2a 0d 6c 77    |P..ri...kM.*.lw
  e9 08 59 ae a1 b3 de 7b    4e 05 c4 0a 17 b0 52 c0    ..Y....{N.....R.
  c9 06 2e 4c 52 3d ea 68    bb e1 02 46 e0 1f cc 95    ...LR=.h...F....
  b3 b4 68 1c 97 01 90 96    d7 aa 60 20 2b a9 63 8e    ..h.......` +.c.
  4a e6 13 04 50 be f2 41    c9 28 62 4d 22 c4 3b 02    J...P..A.(bM".;.
  e8 36 a5 18 3d b1 f3 b4    1b 60 b7 a5 42 4f 26 97    .6..=....`..BO&.
  5f 30 f4 b1 4e 11 3f 75    42 55 dd 33 a5 45 56 41    _0..N.?uBU.3.EVA
  91 9c 09 70 e1 3f 37 c9    30 a9 82 4c 24 0c 2c 18    ...p.?7.0..L$.,.
  e9 10 15 88 61 dd 36 41    28 d4 b8 49 58 4f 9e b1    ....a.6A(..IXO..
  5f 94 d9 4f f0 17 9f e8    5b 7f 32 74 c4 0b 91 20    _..O....[.2t... 
  a3 6a ac 0b 47 b5 83 04    cc 53 da 21 cf 53 2b 9a    .j..G....S.!.S+.
  27 80 53 f0 38 53 c4 b5    11 b4 1f 4b ab 3c 2a c3    '.S.8S.....K.<*.
  95 18 42 cd 26 18 b0 22    c9 93 fe 3b 77 55 22 78    ..B.&.."...;wU"x
  74 f7 71 b9 82 bc 9d ec    5e 71 71 09 4b 5b 73 c0    t.q.....^qq.K[s.
  b0 4b 05 6a 96 a8 8c af    b9 29 99 a3 07 20 c2 d9    .K.j.....)... ..
  2f 4e fc 24 dd 11 52 cd    09 66 9d ec 02 f6 39 b7    /N.$..R..f....9.
  ee 48 13 11 46 0e f0 b8    53 23 0b 22 58 63 7d af    .H..F...S#."Xc}.
  b4 3b 03 69 aa 9a 4c 69    77 b9 60 c5 c5 a7 47 32    .;.i..Liw.`...G2
  73 fe a0 5d 82 f4 40 18    2c 00 53 e7 04 f3 84 46    s..]..@.,.S....F
  e0 40 91 f3 db 15 43 d3    c2 4e 93 1f e4 e5 0e 0a    .@....C..N......
  e4 9b 01 e0 c4 df 85 49    16 a1 65 c7 f3 1b a7 d1    .......I..e.....
  22 ec 61 b1 0e 57 93 12    96 84 14 3b 18 27 fa 7b    ".a..W.....;.'.{
  12 18 7e bc 05 a3 8c f5    5e 29 d9 0f fe 99 83 bf    ..~.....^)......
  63 60 fc a6 c3 65 b6 bd    4f 92 b0 fc 9a 3d 73 bb    c`...e..O....=s.
  60 95 68 0f d2 39 0d a9    5c 09 8e c9 8e 7f c3 8f    `.h..9..\.......
  cb dc 52 53 d8 9f 26 0c    ab 2b 32 5c df 28 28 2e    ..RS..&..+2\.((.
  a0 2a f0 76 91 ed 00 9e    d8 59 11 6c 12 54 1f b7    .*.v.....Y.l.T..
  54 33 81 51 2a 63 43 b1    98 40 e0 a3 aa bf 89 2d    T3.Q*cC..@.....-
  82 42 cf 11 e0 7b 71 d5    01 1a f3 64 cf a7 28 e7    .B...{q....d..(.
  2a 3f ef 83 42 b7 78 ce    00 d3 0c c9 91 36 ce 2c    *?..B.x......6.,
  8b d4 a8 1e 35 09 01 d1    ac 0d 55 d3 09 83 06 2e    ....5.....U.....
  89 2a 23 64 7c fe ef 49    99 5d e6 9d ac a9 28 a0    .*#d|..I.]....(.
  e4 a4 7b 2b 19 d0 f0 4e    43 08 9b b6 44 d3 6a 3e    ..{+...NC...D.j>
##
//Key handshake 2 (server key)
T +0.000047 127.0.0.1:43050 -> 127.0.0.1:56968 [AP] #6
  c7 3b b0 5b b1 4a e5 2c    a9 8b 68 0a 48 cb 4e 00    .;.[.J.,..h.H.N.
  34 72 ad 28 b7 59 ab 31    d2 8a 67 5a b6 65 d0 c2    4r.(.Y.1..gZ.e..
  5b f9 74 2b d5 56 ce 0d    92 30 98 f6 a5 76 0c 3e    [.t+.V...0...v.>
  0f 49 21 a2 12 ac 5a 99    75 ca 81 46 48 5a bf d5    .I!...Z.u..FHZ..
  2a 26 63 3a bb 86 0b 00    cb 01 0e 3f b3 b8 a6 21    *&c:.......?...!
  54 fe eb be ac 28 a4 48    d6 1a 6d 27 1c 59 20 4a    T....(.H..m'.Y J
  ce e7 9f 88 c5 43 f6 77    36 b3 35 72 be b7 6b a0    .....C.w6.5r..k.
  c0 a8 5e d0 c7 6c 93 85    71 75 a9 71 a9 65 7c 5b    ..^..l..qu.q.e|[
  74 0c 1b ba 31 82 39 53    22 84 73 ab 7d 6d 99 c9    t...1.9S".s.}m..
  6e c3 66 97 b3 86 85 7a    68 3e c1 75 a9 01 0f 57    n.f....zh>.u...W
  f2 24 2d ba 3b 18 96 1d    5b 3b a5 29 13 ca 7a 74    .$-.;...[;.)..zt
  79 3d b4 2e 56 56 15 ef    19 35 6a f6 23 bf 98 61    y=..VV...5j.#..a
  aa e2 c6 a5 80 03 ae 58    01 1d 8a 6e b2 f8 be fa    .......X...n....
  7b ac c7 47 78 93 db 79    2f 24 15 ce 69 9f 85 50    {..Gx..y/$..i..P
  69 d9 a1 44 7e 90 62 95    52 09 21 db 8e c8 06 83    i..D~.b.R.!.....
  b8 43 a7 05 68 45 74 63    29 81 58 60 e1 84 76 7f    .C..hEtc).X`..v.
  04 7a 0c 25 80 b6 e7 4b    65 b1 94 09 ab 80 3b 31    .z.%...Ke.....;1
  95 ed f9 48 41 57 63 ad    49 17 7c c2 b1 00 ec 2a    ...HAWc.I.|....*
  70 79 65 2c c8 42 f3 90    c2 18 2a 9a 1c c4 2b d9    pye,.B....*...+.
  60 bf 17 11 c7 6e bb c2    de ab c2 41 c0 9d d1 e8    `....n.....A....
  9c b1 73 47 78 bb 66 dc    34 3a 9b 43 20 54 c1 7f    ..sGx.f.4:.C T..
  a3 33 4e 05 0a 84 4e d6    64 27 2a 57 d8 72 18 c2    .3N...N.d'*W.r..
  72 54 51 f5 1a c7 aa 57    56 ba 56 ed 6a 20 d4 b3    rTQ....WV.V.j ..
  02 0b 27 3b dc 62 04 14    61 9e c8 83 86 3f 06 1a    ..';.b..a....?..
  3a 2c b0 2b c5 13 08 6c    79 7a e7 1c d4 ba 5b 23    :,.+...lyz....[#
  fc 30 78 cc 6c a4 c5 6e    41 f3 42 26 28 57 77 41    .0x.l..nA.B&(WwA
  59 7e b1 25 6d e5 4d c5    15 22 13 2c 16 ed 77 38    Y~.%m.M..".,..w8
  b3 84 a0 8f 54 7a 88 31    09 6b 9c ac 8f a7 28 8f    ....Tz.1.k....(.
  38 ce c7 97 7d 67 60 85    03 b9 3b 72 12 39 62 ba    8...}g`...;r.9b.
  41 4f c2 cb a7 63 6b 58    3c 55 6a 39 a3 fa ba 30    AO...ckX<Uj9...0
  8e c9 ae 8c e4 37 d0 01    a6 80 29 bc 28 b3 96 35    .....7....).(..5
  e2 35 32 5a 79 fc ea cb    72 f2 34 25 37 2a ba 55    .52Zy...r.4%7*.U
  7c 44 9a 7f 9d 10 c2 9f    28 97 45 95 50 93 25 46    |D......(.E.P.%F
  dc 59 97 f8 0c 61 24 9a    c3 e8 29 bc 2b f9 22 41    .Y...a$...).+."A
  d0 74 02 04 a9 3f 6a ba    85 b7 33 a2 1c 35 6a 59    .t...?j...3..5jY
  45 c1 68 af 2c d3 3f 6b    9a aa 95 9a 4e 74 34 4b    E.h.,.?k....Nt4K
  f7 28 17 9e 83 62 4c 18    b0 7a b0 a9 28 76 9a a0    .(...bL..z..(v..
  fc 18 7e ec 12 ad cb 92    c5 03 52 38 d1 ae ae 65    ..~.......R8...e
  6a 12 a3 4b cb b6 9f 4b    60 1c 52 84 cf 91 e7 94    j..K...K`.R.....
  3e 54 ae 0f e0 6e 15 00    62 ea c4 36 06 47 31 9b    >T...n..b..6.G1.
  b5 73 d5 fb a7 30 4c 5e    a0 b4 22 62 a0 4b 69 57    .s...0L^.."b.KiW
  01 09 45 66 5b a0 45 4b    59 85 68 47 7a ca 07 70    ..Ef[.EKY.hGz..p
  22 b7 13 60 cb aa 79 28    6a 9e b8 46 46 61 70 8b    "..`..y(j..FFap.
  c7 59 7e 35 9e 8b 90 87    33 43 5e 77 0b 0f 84 d3    .Y~5....3C^w....
  8e 99 c5 cb 76 b2 3d 05    b7 4f c0 eb 17 96 51 2e    ....v.=..O....Q.
  7b 25 ca b7 fa 81 65 c0    09 d3 80 14 ab 0c 7b 2e    {%....e.......{.
  48 c5 1e 13 36 61 e6 23    35 06 86 89 2c 1a d3 60    H...6a.#5...,..`
  20 8b 08 af c0 f6 1f 90    23 35 e4 11 0d 1c f3 aa     .......#5......
  1e fb ca d8 6c 94 84 a9    3b 79 c8 19 c3 83 04 20    ....l...;y..... 
  a3 a0 cd ea 1c 98 77 c1    bf c2 81 ee 81 4e 26 f7    ......w......N&.
  7e 01 97 a2 f0 8b a5 e3    17 6c f3 da ad 5f 23 00    ~........l..._#.
  fc 4b 85 e5 0a a8 95 78    cf 7c 02 81 62 ea 7c ac    .K.....x.|..b.|.
  c6 1a 43 58 8c 8e 10 5a    34 e0 1d de 18 5c 74 f5    ..CX...Z4....\t.
  5d 25 46 49 bf fa 3f 5b    7a 20 05 35 40 e2 80 a8    ]%FI..?[z .5@...
  7b 1b 13 87 66 28 cd 3c    bb 76 27 a4 5d 93 0b d6    {...f(.<.v'.]...
  02 2a 73 c2 b1 9f 0b 4a    1c d7 c7 79 aa cc b0 1b    .*s....J...y....
  c9 d3 ab 1a 52 96 38 c9    70 55 b0 13 01 6b 71 53    ....R.8.pU...kqS
  96 17 af 3c 76 55 4e 68    71 bc 53 00 c7 c3 cd cb    ...<vUNhq.S.....
  c0 83 92 35 a9 61 2b 67    36 84 b9 74 d9 bb 6e 21    ...5.a+g6..t..n!
  63 55 99 54 c6 8a 61 ce    86 0b f3 4b af 59 8a 2f    cU.T..a....K.Y./
  f7 09 43 67 11 a0 e0 99    5e 74 16 9e f5 d9 93 83    ..Cg....^t......
  9a 9f 6a 75 76 61 d7 16    27 d0 0d ff 21 96 0b 58    ..juva..'...!..X
  17 e6 b7 82 1a e7 1a e5    27 a6 b6 f0 88 93 a9 b1    ........'.......
  a5 bc 3e 4f 5b 71 30 89    80 b7 28 20 95 79 3e 6f    ..>O[q0...( .y>o
  71 ba f5 18 1b e2 a8 80    59 95 66 cc f1 5b 9a 90    q.......Y.f..[..
  3c 46 44 07 ff 14 27 5a    3c b4 17 18 9c 56 a9 b3    <FD...'Z<....V..
  df ac 0e 79 0a cb 85 39    0d 3a a5 b8 7b 05 b0 6c    ...y...9.:..{..l
  f2 bd 44 80 2f c5 64 1b    55 cc 87 32 fb 49 e3 96    ..D./.d.U..2.I..
  2f 0a 9c 14 bf 14 5e 71    b2 64 ca 9a c5 95 e5 c1    /.....^q.d......
  d6 ac 62 82 a3 1a 29 c4    50 1e 54 2f 0c e2 4d 4c    ..b...).P.T/..ML
  89 3b 27 ca bb 31 d7 8f    d3 b9 b4 06 f4 24 91 b2    .;'..1.......$..
  8c 7e 21 73 42 09 12 17    68 40 6f 83 ce 66 09 b2    .~!sB...h@o..f..
  b5 56 7e 7c 76 02 cc de    47 19 ea 9e b7 53 5e a5    .V~|v...G....S^.
  6f 7b 77 d3 ac a4 3e c9    56 e5 33 c2 1e 96 c1 44    o{w...>.V.3....D
## //Client initialization
T +0.001910 127.0.0.1:56968 -> 127.0.0.1:43050 [AP] #8
  d4 25 a8 bd 29 cf 06 64    2a 84 fa 28 b2 2c 49 23    .%..)..d*..(.,I#
  37 bd 7c e2 23 d7 7c 3f    be 08 7e a7 8c 2e 76 47    7.|.#.|?..~...vG
  7e b8 8a 0a cf 72 b3 26    05 ce 1f aa 67 6f 0b 33    ~....r.&....go.3
  a6 d9 2b 1d 02 8d 46 21    30 96 c5 4a df e7 34 93    ..+...F!0..J..4.
  97 8c 03 86 29 a2 b5 a1    44 4b 4f be 9c 57 e2 a7    ....)...DKO..W..
  3b 99 79 9a 03 ab 0d 14    e3 c6 42 6a 31 81 e3 0f    ;.y.......Bj1...
  e2 ea 34 10 46 a2 01 6c    6c d8 28 a4 5d b8 bc 18    ..4.F..ll.(.]...
  00 16 0c aa 29 1a 73 06    bf e4 8d 4d 46 b5 44 00    ....).s....MF.D.
  b5 e0 55 8b 5a c7 02 c8    77 7d dc 7c 67 97 07 3f    ..U.Z...w}.|g..?
  0c d3 48 d3 3c 6e da e9    b2 e4 13 ae f1 f7 14 46    ..H.<n.........F
  95 4e 47 a3 51 ca 7b 8e    1d c2 1e 95 c4 46 05 91    .NG.Q.{......F..
  a0 54 41 73 68 48 a2 5e    52 7f 77 2b 2b 67 25 8e    .TAshH.^R.w++g%.
  5d 15 57 89 b2 27 db d4    33 45 56 b9 b7 4c a6 3b    ].W..'..3EV..L.;
  2c 52 6f 62 c3 f5 97 7c    db 32 3a b3 49 75 25 fc    ,Rob...|.2:.Iu%.
  0b 35 19 9e a0 60 60 55    68 93 8b f3 25 22 4b a8    .5...``Uh...%"K.
  5b ba 6e 91 85 a6 1a 19    2f 54 26 46 48 46 8d ad    [.n...../T&FHF..
  f8 4e 98 40 41 86 f0 1e    45 0a be e5 ea 83 ce 9c    .N.@A...E.......
  79 a0 65 6e a7 07 4b 11    77 4d 20 ca 25 9f 08 34    y.en..K.wM .%..4
  bd 85 7c c3 64 b2 8f 47    58 90 55 7a 3f 10 7c 17    ..|.d..GX.Uz?.|.
  8c 60 7c 8b 83 d7 f9 5d    f0 72 be 7d 2a 1e 85 d6    .`|....].r.}*...
  36 57 34 31 b3 71 bc 4c    c7 7b 3c da 2a a5 96 9b    6W41.q.L.{<.*...
  50 96 9c 16 01 16 92 6c    18 0c b9 6b 8f f2 a9 45    P......l...k...E
  63 a3 b1 02 c6 9f 1a 10    ca a6 0d a8 0a b2 2f 89    c............./.
  69 ad 64 39 c8 fc cd b8    74 c6 ec f4 37 83 80 47    i.d9....t...7..G
  b3 57 1e 2c b7 b2 30 56    c6 e1 f9 0d 30 1b 7a f0    .W.,..0V....0.z.
  6b bf 47 47 a3 ea 85 5f    c3 78 08 d6 d3 ad 96 26    k.GG..._.x.....&
  9e 64 9a b3 97 75 c6 0a    64 7a c5 81 1d dc 04 91    .d...u..dz......
  cc 89 2b 66 03 31 b4 d6    30 46 02 81 10 44 1e a0    ..+f.1..0F...D..
  d0 15 03 76 9c f1 12 9e    d1 82 85 4d 6b 2f 3a 73    ...v.......Mk/:s
  6e c8 10 85 ea 02 34 65    e7 09 78 4a 6e 6f 2b a8    n.....4e..xJno+.
  f3 1b 9c ab 25 ac fc 99    14 ca a0 8c 6b 62 76 51    ....%.......kbvQ
  b8 1f f6 79 00 66 43 27    2a b3 c7 24 9b 86 17 b5    ...y.fC'*..$....
  ac 52 96 26 56 2a b3 1e    66 2b 9e db 16 9b b0 2a    .R.&V*..f+.....*
  a7 bb 6a 81 1b 0b 03 58    29 20 83 54 14 dc 1b 6f    ..j....X) .T...o
  ea 56 38 64 ae 0f 66 74    f1 2b 74 35 c1 27 a6 67    .V8d..ft.+t5.'.g
  52 9f d3 02 a2 f2 4a fb    b3 04 2a 16 02 47 64 56    R.....J...*..GdV
  c5 d2 05 2a 79 77 f5 06    53 68 29 c7 7d 62 a4 df    ...*yw..Sh).}b..
  48 80 d9 42 17 2f a6 62    97 07 3b dc ac 40 a8 85    H..B./.b..;..@..
  a4 fd 0a 30 b2 fc a2 a5    4b 60 53 03 84 76 c4 b6    ...0....K`S..v..
  00 92 63 b1 12 05 0b 85    2d 36 44 51 4f 29 04 eb    ..c.....-6DQO)..
  b6 45 d3 86 40 c5 f6 19    f9 00 95 a1 8c 42 42 a9    .E..@........BB.
  48 7e a2 36 3f db 54 1b    09 33 d8 7a 77 95 48 8f    H~.6?.T..3.zw.H.
  b4 01 1d 9c d4 8d 8c 10    cd 11 65 a0 00 c6 1e 8e    ..........e.....
  59 c5 6e 43 75 49 db 69    8f 30 cb 13 f6 3b 5d 00    Y.nCuI.i.0...;].
  c6 bd 96 8a 29 27 66 c7    0b 21 b8 a3 a7 3a db 6a    ....)'f..!...:.j
  82 b5 6b 10 ea 36 3a a0    c8 60 a9 87 5c 66 aa 22    ..k..6:..`..\f."
  b7 24 1c 27 79 34 c0 22    ce c2 b1 d4 f6 ae ad 93    .$.'y4."........
  03 00 e4 69 3d d2 28 e3    24 55 ed 83 ca f5 2c 76    ...i=.(.$U....,v
  cc 37 0a 2d 84 8c e3 93    35 ec 57 1e f1 72 19 60    .7.-....5.W..r.`
  33 64 28 e1 79 77 bc 83    ff d8 74 b5 cc 2d 46 91    3d(.yw....t..-F.
  70 a8 e3 43 49 26 9d 4e    22 2d db fa 95 d2 c8 93    p..CI&.N"-......
  3e 3a 3d 5c d8 99 55 10    95 40 25 b5 3e 04 1b 5e    >:=\..U..@%.>..^
  e9 61 cc 27 3e e0 81 18    c1 04 2b 3f 8b 9c 47 6b    .a.'>.....+?..Gk
  b4 12 43 2c 8a 53 25 88    d7 37 64 63 47 88 60 a1    ..C,.S%..7dcG.`.
  61 60 09 5b 0b 06 f5 28    a1 31 ab cc af e2 91 10    a`.[...(.1......
  f5 b6 a9 55 a1 04 3c 64    b2 76 ca 84 bc c3 e9 3b    ...U..<d.v.....;
  8d 77 c3 26 f7 f2 c6 4a    09 84 7f 13 9b 5b 93 1a    .w.&...J.....[..
  2d fb a2 1e 7a c6 e7 dc    bc 42 57 ca 80 02 11 33    -...z....BW....3
  ab 1c bc b7 43 17 a5 92    3b 24 66 86 8c 55 dd 39    ....C...;$f..U.9
  43 dc f4 8b 46 92 c2 e9    80 9f b4 51 1d 32 73 9e    C...F......Q.2s.
  0c 70 90 25 c0 7d e8 c9    3a 84 31 84 cc 9c 06 75    .p.%.}..:.1....u
  59 7b c8 a4 6a 31 8c b5    cc b9 0d dd cb 3e e1 a6    Y{..j1.......>..
  92 00 28 3e 18 c9 6b 0c    a8 5d 29 12 60 ec b4 1c    ..(>..k..]).`...
  c2 b2 3f 07 7b 50 11 fc    b4 f2 0c 2b dd 44 4a 0e    ..?.{P.....+.DJ.
  c3 ca 57 57 36 de 1c 79    6d 09 72 24 92 6d c6 00    ..WW6..ym.r$.m..
  a6 af 55 84 07 bc 84 9f    83 bf bb a4 58 e0 e7 1c    ..U.........X...
  c1 79 3b 61 98 2d 3d 47    bb b9 bc a8 93 36 90 ec    .y;a.-=G.....6..
  4b 94 8a 00 5a d8 07 73    2a 03 c8 5b 11 ba b7 f0    K...Z..s*..[....
  b5 26 94 7d d6 f6 2a de    a8 7e f4 ca 9e 33 57 54    .&.}..*..~...3WT
  55 c1 c3 42 b1 2c 61 96    4e 47 30 07 b8 36 01 d3    U..B.,a.NG0..6..
  c1 af 9f 23 15 1c e4 4d    41 39 ae df 0a 5c 05 bb    ...#...MA9...\..
  ab 74 4b 8c a2 9b 2f 19    d1 02 37 3b 74 c8 a4 c5    .tK.../...7;t...
  81 94 bf 68 93 74 55 91    83 7d b4 b3 e7 64 07 e1    ...h.tU..}...d..
  38 86 3f b9 78 74 48 21    e0 37 0b 66 51 e4 1d fe    8.?.xtH!.7.fQ...
  62 01 df 91 8a d9 bf c3    66 a3 e3 a5 b2 9c 1a d8    b.......f.......
  38 19 6c 5c bf be 24 3a    53 28 95 78 8f f6 cb b8    8.l\..$:S(.x....
  80 47 a1 79 ff 4a 0a 15    95 86 c1 1e 0b 6d 6d 56    .G.y.J.......mmV
  2a 26 72 28 7a 3b 8a 26    d9 4f 64 97 76 69 45 1a    *&r(z;.&.Od.viE.
  f2 5e dc 0f 06 b7 7e f5    75 8e 6a 3f bb 89 7f 7d    .^....~.u.j?...}
  44 b1 b3 14 9d 59 d8 c5    c2 93 26 6b 9f 36 29 86    D....Y....&k.6).
  95 b9 ce 8a 93 0b 05 67    c1 14 a2 05 a3 17 44 66    .......g......Df
  be 50 5f b1 13 ca b2 f5    d4 aa 4e ec 33 b7 0a 33    .P_.......N.3..3
  aa 02 b9 38 b4 6e 9d 36    f5 93 c2 dd 0e f3 ef f4    ...8.n.6........
  e7 b8 40 3f c5 d8 fe fb    c1 a0 6c 18 eb d0 7b 7f    ..@?......l...{.
  92 8c e0 54 b6 4f f0 d3    02 f2 bd 6b a0 d1 ed a1    ...T.O.....k....
  e0 5e 23 34 7a 0f 53 17    f3 fb 90 8b 9e 2b 5f aa    .^#4z.S......+_.
  ce 98 d0 fa b8 10 b8 76    4f f0 9a ea 47 85 be 76    .......vO...G..v
  ea 42 09 a3 c5 ed 29 68    2b b5 02 9b 38 8a 69 3a    .B....)h+...8.i:
  b9 9c 81 44 ed d8 3a 7f    6d 94 2c 95 fe d5 e6 67    ...D..:.m.,....g
  8e 9d da bf c3 f8 3d 1c    9e f8 89 f9 dc a3 ae 37    ......=........7
  42 5b e9 4e b7 5d 3d 6e    b5 4d fa fd f9 6c aa a2    B[.N.]=n.M...l..
  8b 1b 22 2f 3c db 49 a5    b2 8a 79 98 7f 54 c4 a1    .."/<.I...y..T..
  62 4e 62 c4 a7 9c fd af    0f c3 b1 c9 2a 31 9e 01    bNb.........*1..
  cc 23 26 5b bb 9c 7b 7f    6b b8 49 36 15 5a 22 32    .#&[..{.k.I6.Z"2
  ac e9 04 24 de 7a 48 c9    33 bc af 8a da f9 b0 29    ...$.zH.3......)
  11 a0 33 31 97 26 b4 fc    cb 0a 7a c8 79 2d 64 9f    ..31.&....z.y-d.
  2f a2 d2 6b d2 1e 42 2e    ef 5e df 80 19 fc 0b 50    /..k..B..^.....P
  36 12 b3 59 c9 87 25 2d    fb 2b be 55 a3 a9 85 80    6..Y..%-.+.U....
  31 fa 80 1b 78 f6 32 b7    4f 10 63 e3 52 6b dd 21    1...x.2.O.c.Rk.!
  28 d2 41 6a 9e 2d 53 23    58 1f fd 3c e1 07 0e 7a    (.Aj.-S#X..<...z
  85 d9 64 5d 73 74 59 5f    89 dd 8d a5 48 26 df a5    ..d]stY_....H&..
  cf 1e 25 ba c7 ba c6 e4    22 be 1b 51 d6 05 7f 48    ..%....."..Q...H
  3e cc 40 e3 de d2 26 25    f2 c3 2b 75 d0 7d cd 60    >.@...&%..+u.}.`
  37 23 4a 06 5c d4 a8 87    07 61 20 06 5f 9c da 15    7#J.\....a ._...
  ee ad 60 b8 b2 91 75 e5    06 e8 88 25 74 11 09 96    ..`...u....%t...
  54 bd 76 23 e9 ba ce 67    78 f3 7a 76 d8 61 c4 ad    T.v#...gx.zv.a..
  fe f9 c0 64 5a e6 05 81    ec 2b be 60 8b b7 11 29    ...dZ....+.`...)
  5e 8a 3e ec b4 30 27 ab    aa f0 7c f6 0f 00 c8 f4    ^.>..0'...|.....
  59 ca fa 30 8d 34 36 6b    3b 93 e6 f1 ff 79 cf 05    Y..0.46k;....y..
  0e ed e2 fe 63 1a eb 7f    7d 3d 43 5b d4 e7 16 71    ....c...}=C[...q
  24 10 10 ec 04 d1 09 c6    9a 93 6f d9 e2 41 a1 93    $.........o..A..
  0c db b5 4a ca 17 8e d3    9b 3a 28 fa c6 97 7d fe    ...J.....:(...}.
  2f ab 7d 4a 24 3a 6c 67    f1 ed ac 7a 6a 31 9f 26    /.}J$:lg...zj1.&
  fa 8e eb 71 8a cc 63 1b    f8 56 f5 ee 7e 4c 7b aa    ...q..c..V..~L{.
  ae fa 48 65 f1 8a 86 05    0d cf 49 43 99 ed fd 97    ..He......IC....
  5b 07 18 27 97 83 c5 df    85 e7 d7 70 d1 76 76 e3    [..'.......p.vv.
  28 60 5e a9 da 88 6f 93    46 1d 3b 33 1b 11 2c 6e    (`^...o.F.;3..,n
  57 49 3e 09 3a fe 18 b2    43 ee 24 aa 27 02 5a 75    WI>.:...C.$.'.Zu
  8f 6c e5 78 78 92 d5 ab    ac 86 83 ec 2b 4b a2 70    .l.xx.......+K.p
  b3 b0 6d e1 db f4 e5 c2    26 fe 78 c0 18 5c 7a 71    ..m.....&.x..\zq
  7c ad 52 20 97 4f 56 67    ae 3c 62 18 bb 1f ef 3c    |.R .OVg.<b....<
  a1 8b db a4 f1 f1 53 b2    7e cc 5a b3 2d 42 11 50    ......S.~.Z.-B.P
  c5 a5 19 63 0f 71 34 2e    bd 5a ee af 8f 7e 60 cc    ...c.q4..Z...~`.
  c3 fa ff 8e 9a 03 11 ba    30 84 ba d3 0e 9a a3 84    ........0.......
  81 2c 33 cb 24 80 b4 ce    b2 b0 4a f3 c9 ac 0f 87    .,3.$.....J.....
  3d 38 3f 22 99 14 85 60    44 6e d7 6d 69 90 b9 5d    =8?"...`Dn.mi..]
  ba f5 96 11 50 02 81 9e    bf ac 99 14 eb 60 12 f7    ....P........`..
  58 93 60 c5 d9 53 bd 46    83 7f 76 96 fc 1d 18 66    X.`..S.F..v....f
  04 a8 e8 4e 2e bd 8f ab    85 e0 b6 b7 58 07 54 51    ...N........X.TQ
  41 a2 6a 61 43 fd 32 83    d9 67 f9 38 f8 ea 7e d4    A.jaC.2..g.8..~.
  a6 63 c5 d7 d1 c0 3a ae    4a b4 d1 be ef f2 0d f7    .c....:.J.......
  92 1c 4b 78 bd 40 55 43    8d fc ac 38 7b 45 fd f0    ..Kx.@UC...8{E..
  64 8c 74 52 86 32 69 ff    29 57 72 90 d4 23 d6 4a    d.tR.2i.)Wr..#.J
  84 50 7a 2c 86 fb a5 02    f7 57 57 99 9d 7b 6e 7b    .Pz,.....WW..{n{
  75 c6 51 ef ce 08 b3 0a    94 43 d0 ba eb f4 5f 30    u.Q......C...._0
  19 b4 19 a7 d1 0b c8 05    78 68 fe d2 5d 10 c5 d8    ........xh..]...
  6b 24 e1 f1 6d 1c d6 43    90 d2 63 12 d4 dc 92 e6    k$..m..C..c.....
  69 7d 14 40 14 b5 9e 16    17 65 3d 84 b3 5d b0 d7    i}.@.....e=..]..
  73 f0 c3 e5 26 66 ba ff    d7 0e bd 5c 81 b9 68 52    s...&f.....\..hR
  b7 3e 35 e8 69 1f 91 6c    92 c6 70 12 b8 d6 80 c2    .>5.i..l..p.....
  17 a0 a1 80 56 b8 e2 15    d2 dc f6 95 bd b6 c5 30    ....V..........0
  6b 9d d3 6a 5d 97 36 13    1d a8 1a 0e 70 e2 3f 75    k..j].6.....p.?u
# //Server confirm (confirm server identity)
T +0.003193 127.0.0.1:43050 -> 127.0.0.1:56968 [AP] #9
  97 52 3e 0d 28 4a 9e 85    d6 c9 9e b2 d4 b9 a0 2c    .R>.(J.........,
  5a af ab 7a 8a 5e 16 be    c1 6f 62 3b ae cc 94 a4    Z..z.^...ob;....
  1e 4d b1 e1 ba 6a 9a 42    23 18 e0 c4 cc ae d8 fb    .M...j.B#.......
  3e 33 42 2a d1 98 55 c2    ea 33 e4 05 68 c4 dc 6d    >3B*..U..3..h..m
  af dd cf 8c 23 1a fb 4a    7c d1 00 e5 9a f3 90 f4    ....#..J|.......
  4b 36 28 d2 c5 d4 bb cb    72 dc 7d 65 e8 20 94 05    K6(.....r.}e. ..
  bc 95 ad ec 7f 3d fc 87    8d 4e 13 8b 6f 52 d9 9d    .....=...N..oR..
  dd 7d 56 56 56 18 13 3c    4f 17 86 41 ce 67 4c ab    .}VVV..<O..A.gL.
  87 ca dd ff 53 ff 61 42    a4 79 a8 cf 00 7a 0a 2d    ....S.aB.y...z.-
  6d 49 5f 8a bb b1 f1 69    c4 ff 11 67 8e f8 ab 6c    mI_....i...g...l
  46 0d 84 e4 b2 da 9d a0    ff f5 ed 10 2b 48 2f 7f    F...........+H/.
  1d 0b 55 64 3f 70 90 94    fe b1 d8 bf e3 6e dc 22    ..Ud?p.......n."
  b7 fd c0 03 b9 30 bb 14    00 e1 46 1a da ed bf 20    .....0....F.... 
  4c 2c 34 a4 64 d6 c5 6f    d7 94 92 e3 b6 97 c3 f9    L,4.d..o........
  27 2d b6 91 ac 5e 29 e1    f8 f6 1e c4 4e 13 d6 48    '-...^).....N..H
  cd 6d 12 75 ca 39 a0 bc    67 7b d9 e7 5e 12 62 14    .m.u.9..g{..^.b.
  6a 5b 7c f3 be 73 35 f7    cf d0 52 7e 36 5e 64 11    j[|..s5...R~6^d.
  80 62 82 67 c8 f7 6e c9    6b ce 7a 34 ea ef 25 de    .b.g..n.k.z4..%.
  ee 61 af 6c ac b9 e4 fc    f2 6a a3 6a c7 76 bc c6    .a.l.....j.j.v..
  54 f4 75 4f 9a 2b 15 8b    01 d6 65 16 c5 b7 6f 4c    T.uO.+....e...oL
  9d c2 ca 21 b0 23 8f 3e    14 cf 56 bc 5a 88 ab d2    ...!.#.>..V.Z...
  98 85 c6 24 fc 17 7e 3d    98 2c 78 d7 14 23 dc 37    ...$..~=.,x..#.7
  62 d3 00 37 44 35 72 d8    3b 36 05 a7 5c 05 17 d8    b..7D5r.;6..\...
  c0 c4 a3 98 25 0e d1 62    37 c5 03 a5 02 a5 f8 b6    ....%..b7.......
  5f 73 76 fb ea 71 ba 39    79 65 24 39 2c 80 5f 02    _sv..q.9ye$9,._.
  54 72 4f 21 d1 10 7a 7e    f9 c2 9f e2 3e ad f9 3f    TrO!..z~....>..?
  02 55 e9 dd eb d9 30 c0    66 f2 53 79 aa 0f e0 cc    .U....0.f.Sy....
  3b d9 6d c7 43 ea 50 11    f4 b8 81 76 ad b4 7a b0    ;.m.C.P....v..z.
  92 3a 91 cd d6 fa 18 e8    2d b9 b5 da 4b a3 0f b1    .:......-...K...
  9f 3a 88 a6 be 5f c5 c5    f6 72 15 87 52 df f3 83    .:..._...r..R...
  be b9 2f d0 e5 e9 96 14    35 8d 60 13 f5 a7 e5 48    ../.....5.`....H
  f3 31 2b c4 02 91 e1 a6    52 7f 6f 6d 0e f1 ab fa    .1+.....R.om....
  b7 d5 74 36 56 fe 1f 91    0d 79 f3 75 03 79 e3 b7    ..t6V....y.u.y..
  61 4a 31 2d 44 15 27 88    bd e1 1a a1 3e 77 7c c8    aJ1-D.'.....>w|.
  41 73 10 8a a4 ed 73 a2    1f 90 13 33 0b ca c9 3b    As....s....3...;
  98 45 2c e1 29 10 0b f0    e1 c5 a7 49 a3 1d 01 e3    .E,.)......I....
  2a fc 6c b4 e1 3e ea c5    b7 43 81 29 2d 8d 84 aa    *.l..>...C.)-...
  49 c1 95 f2 a8 ef 39 69    f0 66 31 cb 18 7a 66 da    I.....9i.f1..zf.
  20 3f ec 8d 80 ed fa 39    74 89 10 16 9b da a6 0b     ?.....9t.......
  21 54 dd 90 b0 09 67 f2    3a 0d 81 8d 84 0e cb c3    !T....g.:.......
  d5 b5 85 ca cc 4c e8 81    25 b6 a0 a7 d3 83 5b b3    .....L..%.....[.
  20 60 d7 9a e2 9c f5 06    bc 3d e7 16 68 45 aa 91     `.......=..hE..
  32 45 91 d2 1a 4d 31 ed    c9 27 87 ef 31 e1 f6 24    2E...M1..'..1..$
  a8 52 9f 69 36 3b 99 ad    21 3b b8 7c 09 06 04 54    .R.i6;..!;.|...T
  7a 2b 3e 0b bd 8f 95 3e    5c fe 89 62 14 88 81 67    z+>....>\..b...g
  1a 6c 6c 99 7c 66 ed 3d    b4 ac 10 70 60 95 83 07    .ll.|f.=...p`...
  f7 60 33 f1 66 0d ab 3e    b9 88 f1 1b 78 63 c5 1f    .`3.f..>....xc..
  04 a9 9d 71 eb 0c a3 a3    92 0b 94 18 da be b0 ed    ...q............
  10 0d f0 09 d5 40 2c 2f    f6 34 ec 75 e2 f9 6e ec    .....@,/.4.u..n.
  b3 3e ab 63 80 c4 f7 72    17 b7 48 31 49 72 35 0c    .>.c...r..H1Ir5.
  ae 00 8e 04 af 4c 9f 46    c0 cf 3d 6a e9 a0 cf 45    .....L.F..=j...E
  9c 73 7e e4 29 68 dc 1a    4e 6c 47 0a 0a 1b 47 98    .s~.)h..NlG...G.
  6d 80 a3 de cf 42 43 57    b4 98 10 49 24 b8 37 63    m....BCW...I$.7c
  12 1a 6d 21 04 1a 8a 5e    c6 e4 d9 49 e3 b5 32 3f    ..m!...^...I..2?
  9a 2f 95 d7 a6 3d 57 1a    02 60 dc c4 ce a6 1e b2    ./...=W..`......
  c6 ac d4 97 d0 2f 24 93    4b ed 6d 6d eb dd 73 25    ...../$.K.mm..s%
  27 1e 51 81 54 60 29 8b    9e 09 bb 2d 03 84 ad 29    '.Q.T`)....-...)
  b8 82 f1 d8 86 87 39 f4    5d f7 d2 53 44 d2 c9 3a    ......9.]..SD..:
  9f a9 d8 d6 90 8f cd 5a    3a 7c ef 01 87 cf 83 51    .......Z:|.....Q
  24 02 57 38 36 02 8c 1d    8e 8e e5 fd c2 36 80 eb    $.W86........6..
  cd 7d 7e 80 9c 09 18 d3    d2 a4 dd 42 82 56 a3 0f    .}~........B.V..
  dc ba 23 d5 3a 88 9b 08    89 4c 6e d0 5d d2 84 ac    ..#.:....Ln.]...
  f2 fb 3b a1 e7 fe 7e f0    7d 3e 6b 9e f6 dd 1f 5c    ..;...~.}>k....\
  44 c1 3c 4f 1d e5 24 58    40 4b 8f 07 f1 f7 51 3a    D.<O..$X@K....Q:
  00 00 0f 35 ed 9b 2e 02    51 db 1a 78 ff fe 4d 8f    ...5....Q..x..M.
  6f a6 83 37 0e 54 40 57    68 52 05 08 8c c2 11 fe    o..7.T@WhR......
  c3 62 5f cb 70 5b e6 95    e2 f5 1f 66 e8 a3 ac 71    .b_.p[.....f...q
  ce a9 22 7c 2f fc fe 03    f7 9b b5 6e 0a b1 a7 e9    .."|/......n....
  62 4d 37 a8 60 05 4d 48    d7 44 0f 1b 32 e2 31 33    bM7.`.MH.D..2.13
  56 29 e3 11 01 af b4 85    bb 76 3a 75 96 de 30 11    V).......v:u..0.
  d5 d0 ce 0c 05 b0 25 09    5c 10 73 31 41 a1 43 05    ......%.\.s1A.C.
  fe aa 2e 0d aa 2f 24 d3    b2 42 e3 5c aa b7 64 5e    ...../$..B.\..d^
  11 ad 2e 90 6b 8c bf 56    63 22 87 10 03 de ae af    ....k..Vc"......
  fe b7 be fe de b5 00 8b    f4 d3 9c d3 f6 5c a0 3d    .............\.=
  19 19 21 ea a7 30 a8 84    95 65 c6 58 d5 94 b8 83    ..!..0...e.X....
  c8 fa 19 4c 91 e4 4a 6d    0b 15 4d c8 51 b3 62 06    ...L..Jm..M.Q.b.
  91 fc f8 80 d7 6f c5 74    73 2b f9 f4 0f bb 7a 2e    .....o.ts+....z.
  7c 28 ec be af 86 59 ed    7c 71 2c 22 44 ce 98 74    |(....Y.|q,"D..t
  38 42 0c c1 02 3d 64 60    fc c6 7b 14 85 51 5b 4b    8B...=d`..{..Q[K
  e9 70 55 80 a0 d9 f6 e2    5d 18 d1 bf 25 12 82 d4    .pU.....]...%...
  26 7f d8 ae a0 d6 49 0e    05 64 f9 63 2a d2 0e fc    &.....I..d.c*...
  6f f4 da c3 a1 fd 00 5c    ed 4d 15 02 f3 d3 e4 b3    o......\.M......
  15 ce 2c ae c1 8b 9e 60    20 d0 0a 8c 45 ab 8c fc    ..,....` ...E...
  06 ad 9a 9f 82 48 3c 9e    a7 33 c2 48 a7 a6 c6 e9    .....H<..3.H....
  a2 40 17 35 21 71 42 93    dd 74 d9 d1 18 86 78 dd    .@.5!qB..t....x.
  bf 01 8f e5 7f 84 ee 7a    55 33 c6 1d 07 48 78 05    .......zU3...Hx.
  5f 12 01 91 8c 4f fa ba    41 ff e3 7d 6c ca 7d a6    _....O..A..}l.}.
  eb 5f 81 6e 20 1f 83 38    c2 66 b1 59 58 e2 a3 75    ._.n ..8.f.YX..u
  b5 13 fb 3a 1e a3 28 f6    38 b2 7f 87 8a 4c ed 21    ...:..(.8....L.!
  5a d5 4c c2 17 96 73 cf    3f 94 d0 9c 76 3f 6f 15    Z.L...s.?...v?o.
  1f 4d 40 c0 38 2e 04 7a    29 36 07 dc 2c 6c 0d 7c    .M@.8..z)6..,l.|
  34 05 87 f0 23 a8 8b 9b    60 23 fd cd 28 be 35 8c    4...#...`#..(.5.
  e5 96 2b 06 08 3a 6c c0    70 66 c2 61 69 ec 14 ea    ..+..:l.pf.ai...
  c8 fb 80 25 a7 c7 2e e3    59 f2 99 a0 56 48 9a ea    ...%....Y...VH..
  28 30 8c a2 84 d7 f5 0b    59 d8 d5 d4 78 33 db 2a    (0......Y...x3.*
  ed c4 07 c4 29 d8 b1 7e    6f 3a 7f c1 83 24 4f 41    ....)..~o:...$OA
  3a 62 e1 f6 89 44 9c df    5e ec af 40 2b 6b 32 ff    :b...D..^..@+k2.
  b2 ab 26 df ce 81 ff af    68 d6 2f fd 83 b7 22 70    ..&.....h./..."p
  b2 68 06 12 18 40 ed 3f    16 08 9c ca 30 5a 01 69    .h...@.?....0Z.i
  88 11 b8 3d 8e 90 d5 70    b4 c4 02 31 55 08 66 f7    ...=...p...1U.f.
  d1 88 62 ba cc b8 b4 61    c0 4b 99 9e d4 63 a2 a9    ..b....a.K...c..
  7c b2 55 39 c6 a6 8a 36    0c f9 bd ff 09 ed ee ff    |.U9...6........
  01 c4 8b 4d 96 15 c1 ac    8e 34 f1 f2 17 c0 24 ee    ...M.....4....$.
  17 53 55 cb d5 bf c9 87    5f fd 26 1c 1b 78 d0 ee    .SU....._.&..x..
  1e a8 58 e1 7d 1a 9f 44    a1 6d 54 ea 7a c4 9b 1d    ..X.}..D.mT.z...
  b0 9b c6 da 64 cb 33 fb    b3 d6 ae fa 3c 35 26 92    ....d.3.....<5&.
  07 2e 51 fd 17 2e 88 ec    9f 18 fc 38 07 db 43 7f    ..Q........8..C.
  d9 7b fe 12 16 93 32 69    69 d7 c8 8b 1d 4d 83 25    .{....2ii....M.%
  2e ff 62 73 59 55 e1 30    4b 15 a9 59 9b 0a 0e 9c    ..bsYU.0K..Y....
  3d 39 8b bc 30 2f 12 ea    72 0e 66 6c e9 d9 63 e3    =9..0/..r.fl..c.
  6a 37 6b 65 20 ba 25 48    84 ed 28 dd aa b4 26 11    j7ke .%H..(...&.
  67 83 62 4c d8 cf c6 68    f2 a5 a3 78 5d 5f 3f 1e    g.bL...h...x]_?.
  ba 3f 2d 4a fd f7 36 f0    19 e6 d5 91 b2 f0 b8 62    .?-J..6........b
  f6 c2 49 23 de 9e be 18    1a e9 27 c1 a7 71 a2 50    ..I#......'..q.P
  d5 26 cf b6 9e 37 8f 31    99 97 f7 8d 9f a1 fe 76    .&...7.1.......v
  65 5b 36 17 4d b7 b6 7d    e0 fe fc 9b 8b ae 73 41    e[6.M..}......sA
  03 5b 6c 8a bb bd 63 ae    78 1a 55 51 19 d0 93 e4    .[l...c.x.UQ....
  04 bb 20 47 10 a6 9b f7    0f 63 a4 d1 94 64 e5 e0    .. G.....c...d..
  94 df cd a1 6f e5 24 b7    cd 84 4d fe 31 ab 88 83    ....o.$...M.1...
  d7 f3 71 8e 4e 83 73 44    24 45 7a 18 1d d7 a8 05    ..q.N.sD$Ez.....
  69 94 e9 6d 2e b1 e7 f5    b5 6b 3d 06 08 aa 23 ad    i..m.....k=...#.
  bd 12 34 84 9d 2d e8 25    f7 49 46 25 c5 27 3f 59    ..4..-.%.IF%.'?Y
  36 b2 c2 1b 35 0f d2 af    8f f9 3c a0 16 73 b4 11    6...5.....<..s..
  ec e5 4a 56 4d 3d b2 f2    0e 4b 8f 7d 97 a8 1d ed    ..JVM=...K.}....
  6e 88 5d 96 ba cf 18 74    4c ae b5 00 94 7a 37 48    n.]....tL....z7H
  29 04 75 0a 4a c7 09 3e    75 2a 9f 17 66 b8 d3 5d    ).u.J..>u*..f..]
  08 38 ea 8f c9 1c b1 ed    4e b9 b8 8b c4 57 09 0f    .8......N....W..
  f4 a7 c8 e3 c2 59 d5 2e    41 71 9e 9f b2 fa 08 3a    .....Y..Aq.....:
  ae cb 21 cd db 22 f9 1d    ad c2 69 52 2a 96 15 48    ..!.."....iR*..H
  18 7a df 8e 6b 4b 52 35    d9 e3 57 1f 29 29 b0 96    .z..kKR5..W.))..
  0f 66 7c a8 13 25 87 7d    cd 74 f8 c2 ed 26 ee 6c    .f|..%.}.t...&.l
  11 4c fa 49 e1 f3 af 74    f9 9d 94 3a 80 19 2e 34    .L.I...t...:...4
  69 04 14 c7 20 c3 7a 1a    d8 67 ad 74 2d 9f 5b 7a    i... .z..g.t-.[z
  9b 61 f0 ed 33 b0 06 f2    b8 7d e7 60 05 20 00 5f    .a..3....}.`. ._
  37 15 da 5d b8 bd b8 63    77 f3 57 9e 09 a0 ca 1c    7..]...cw.W.....
  67 26 b9 a4 9a 69 f4 5a    c1 ef d8 79 f3 9b 9e 74    g&...i.Z...y...t
# //Encrypted message
T +0.000205 127.0.0.1:43050 -> 127.0.0.1:56968 [AP] #10
  7c 48 d5 69 81 aa 8a fb    35 a1 47 2c 0c ce b9 c7    |H.i....5.G,....
  3c 55 f3 a3 fa 06 4f 57    33 a5 b0 51 0e f7 f9 dd    <U....OW3..Q....
  8f 1e 2e dc bf 2a ca 
```
</details>
