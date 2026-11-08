!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [udp_mapping](/configuration/shared/udp-nat/#udp_mapping)  
    :material-plus: [udp_filtering](/configuration/shared/udp-nat/#udp_filtering)  
    :material-plus: [udp_nat_max](/configuration/shared/udp-nat/#udp_nat_max)

!!! question "Since sing-box 1.11.0"

### Structure

```json
{
  "type": "wireguard",
  "tag": "wg-ep",
  
  "system": false,
  "name": "",
  "mtu": 1408,
  "address": [],
  "private_key": "",
  "listen_port": 10000,
  "peers": [
    {
      "address": "127.0.0.1",
      "port": 10001,
      "public_key": "",
      "pre_shared_key": "",
      "allowed_ips": [],
      "persistent_keepalive_interval": 0,
      "reserved": [0, 0, 0]
    }
  ],

  // AmneziaWG Fields

  "jc": 0,
  "jmin": 0,
  "jmax": 0,
  "s1": 0,
  "s2": 0,
  "s3": 0,
  "s4": 0,
  "h1": 0,
  "h2": 0,
  "h3": 0,
  "h4": 0,
  "i1": "",
  "i2": "",
  "i3": "",
  "i4": "",
  "i5": "",
  "header_protection_key": "",
  "content_padding_addition": "",
  "rekey_after_time": "",
  "rekey_timeout": "",
  "reject_after_time": "",
  "keepalive_timeout": "",
  "max_handshake_attempts": "",
  "random_trailers": false,
  "disable_cookies": false,

  ... // UDP NAT Fields

  "workers": 0,
 
  ... // Dial Fields
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### system

Use system interface.

Requires privilege and cannot conflict with exists system interfaces.

#### name

Custom interface name for system interface.

#### mtu

WireGuard MTU.

`1408` will be used by default, or `1280` when `s4` is set (see [AmneziaWG MTU](#amneziawg-mtu)).

#### address

==Required==

List of IP (v4 or v6) address prefixes to be assigned to the interface.

#### private_key

==Required==

WireGuard requires base64-encoded public and private keys. These can be generated using the wg(8) utility:

```shell
wg genkey
echo "private key" || wg pubkey
```

or `sing-box generate wg-keypair`.

#### peers

==Required==

List of WireGuard peers.

#### peers.address

WireGuard peer address.

#### peers.port

WireGuard peer port.

#### peers.public_key

==Required==

WireGuard peer public key.

#### peers.pre_shared_key

WireGuard peer pre-shared key.

#### peers.allowed_ips

==Required==

WireGuard allowed IPs.

#### peers.persistent_keepalive_interval

WireGuard persistent keepalive interval, in seconds.

Disabled by default.

#### peers.reserved

WireGuard reserved field bytes.

#### workers

WireGuard worker count.

CPU count is used by default.

### AmneziaWG Fields

AmneziaWG obfuscation parameters, at the endpoint level as in an AmneziaWG (`awg-quick`) configuration file.
With none of them set, the endpoint is plain WireGuard.

Fields marked ==Server== must equal the server's values, or no handshake or no data gets through.
The others only change how this client behaves and can differ from the server.

A range value is a number, or a string `"N"` or `"N-M"` with `N <= M`, both unsigned 32-bit integers.
`0` and `""` mean unset.
For a range, a new value is picked from it at every use.

#### AmneziaWG MTU

`s4` bytes are prepended to every transport packet. When `mtu` is not set and `s4` is set, `1280` is used instead of `1408`.
When `mtu` is set and exceeds `1492 - 28 - 32 - s4` (a 1492-byte path minus the IP/UDP and WireGuard headers), a warning is logged.

#### jc

Number of junk packets sent before every handshake initiation.

`0` (no junk packets) by default.

#### jmin

Minimum size of a junk packet, in bytes.

#### jmax

Maximum size of a junk packet, in bytes.

Must not be less than `jmin`.

#### s1

==Server==

Padding before a handshake initiation, in bytes, 0 to 65535.

#### s2

==Server==

Padding before a handshake response, in bytes, 0 to 65535.

#### s3

==Server==

Padding before a cookie reply, in bytes, 0 to 65535.

#### s4

==Server==

Padding before every transport packet, in bytes, 0 to 65535.

#### h1

==Server==

Magic header of handshake initiation messages, a range.

Unset headers keep the WireGuard message types `1` to `4`.
The four headers must not overlap.

#### h2

==Server==

Magic header of handshake response messages, a range.

#### h3

==Server==

Magic header of cookie reply messages, a range.

#### h4

==Server==

Magic header of transport messages, a range.

#### i1

Decoy packet sent before the junk packets and the handshake initiation, written in the AmneziaWG
packet language (`<b 0x...>`, `<c>`, `<t>`, `<r N>`, `<rc N>`, `<rd N>`).

The value is case-sensitive and passed to the device as is: it is checked when the endpoint starts, not by `sing-box check`.

#### i2

Second decoy packet, see `i1`.

#### i3

Third decoy packet, see `i1`.

#### i4

Fourth decoy packet, see `i1`.

#### i5

Fifth decoy packet, see `i1`.

#### header_protection_key

==Server==

Base64-encoded 32-byte key that encrypts the header of every packet (AmneziaWG 3).
It must not be all zeros, and each of `s1` to `s4` must be at least `12`, since the padding carries the cipher nonce.

#### content_padding_addition

Range of extra padding bytes inside the encrypted payload of every transport packet.

#### rekey_after_time

Range overriding the WireGuard rekey-after time, in seconds (`120`).

#### rekey_timeout

Range overriding the WireGuard rekey timeout, in seconds (`5`).

#### reject_after_time

Range overriding the WireGuard reject-after time, in seconds (`180`).

#### keepalive_timeout

Range overriding the WireGuard keepalive timeout, in seconds (`10`).

#### max_handshake_attempts

Range overriding the WireGuard maximum number of handshake attempts (`18`).

#### random_trailers

Append a random-length random tail to handshake messages and inside transport packets.

#### disable_cookies

Never send or require cookie replies.

### UDP NAT Fields

See [UDP NAT Fields](/configuration/shared/udp-nat/) for details.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
