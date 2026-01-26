# ![the kurrat logo](logo.png)

A single hop VPN by abusing The Tor Network.

> [!WARNING]  
> This program makes a concious choice to ignore the security that Tor provides. Any and all
> traffic sent can and will be tracked to your IP by an exit node. Proceed with caution.

## How it works

A normal Tor connection looks like this:
```
you (client) -> guard -> relay -> exit
```
This seems rather inefficient if you just want a VPN, why not simple just go directly to the exit?
```
you (client) -> exit
```

Unfortunately most Tor nodes block this behavior.
```c
// connection_edge.c
int connection_exit_begin_conn(const relay_msg_t *msg, circuit_t *circ) {
    // snip!
    if ((client_chan ||
        (!connection_or_digest_is_known_relay(or_circ->p_chan->identity_digest) 
        && should_refuse_unknown_exits(options)))) {
        /* Don't let clients use us as a single-hop proxy. It attracts
        * attackers and users who'd be better off with, well, single-hop
        * proxies. */
    // snip!
}
```

So we can pretend to be a relay and connect to the exit node anyways.
```
you (relay) -> exit
```

## Taking a Tor Node's relay keys

If you run a Tor relay node it's as simple as copying a folder.
[From the Tor docs:](https://community.torproject.org/relay/setup/post-install/)
```
Default locations of the keys folder:

Debian/Ubuntu: /var/lib/tor/keys
FreeBSD: /var/db/tor/keys
OpenBSD: /var/tor/keys
Fedora: /var/lib/tor/keys
```

If you do not curently run a Tor relay node you have two options:
1. Ask a relay owner for their keys
2. [Start running a relay node](https://community.torproject.org/relay/setup/guard/)

## Install

Grab the latest kurrat-musl build from [the releases tab](https://github.com/FoxMoss/kurrat/releases).
Mark as an executable, and run from your CLI.

Not on any package managers at the current moment.

If you so choose you can compile from source.

## Usage

Starting a connection is simple:
```
kurrat keys/
```
(`keys/` is just the folder we got in the previous section.)

There is a builtin help menu as well.
```
$ kurrat --help
kurrat [OPTIONS] key_folder


POSITIONALS:
  key_folder TEXT REQUIRED    The path of your key folder 

OPTIONS:
  -h,     --help              Print this help message and exit 
  -v,     --version           Display program version information and exit 

SOCKS5 OPTIONS:
  -p,     --port UINT         The port the SOCKS5 sever will start on 

EXIT SELECTION:
  -m,     --maxminddb TEXT    The path to a GeoLite2-City maxminddb file 
  -c,     --country TEXT Needs: --maxminddb 
                              The country the tor exit node will be located in 
          --exit_addr TEXT Needs: --exit_port --exit_identity_b64 --exit_ntor_b64 
                              Optional predefined exit node 
          --exit_port TEXT Needs: --exit_addr 
                              Optional predefined exit node port 
          --exit_identity_b64 TEXT Needs: --exit_addr 
                              Optional predefined exit node identity_b64 
          --exit_ntor_b64 TEXT Needs: --exit_addr 
                              Optional predefined exit node ntor key encoded in base64 
```

## Building from source

Prequisites:
- cmake
- make 
- a c compiler
- a c++ compiler (with support for c++20 or above)
- git

```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```
