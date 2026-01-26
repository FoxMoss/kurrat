# Reimplementing Tor to use it as a single-hop proxy.

Tor is mostly used by feds, drug buyers/sellers, and journalists. I am none of these things. I am a
highschooler who needs a fast VPN and doesn't want to fork over money to a provider. I need this for
accessing my independently hosted email sever at school, using a search engine that doesn't just put
my query directly into an LLM, and doom scrolling HN. All together pretty mundane stuff. I really
don't need the anonymity that Tor provides, I just need a fast connection.

So I started off with a query: can I connect directly to an exit node via tor?

I think this Stack Exchange post sums it up quite succinctly:

> No, you cannot use Tor as a single-hop proxy.
> 
> It was intentionally disabled in [#1751 - Project: Make it harder to use exits as one-hop proxies
> ](https://trac.torproject.org/projects/tor/ticket/1751).
>
> In terms of security, you'd lose all anonymity.
>
> -- *[cacahuatl on The Tor Stack Exchange](https://tor.stackexchange.com/a/15109)*

Whenever told something simply isn't possible, I take it as a challenge. We're not bumping up against 
unchangeable laws of physics, we're handling malleable connections which basically already do what we
want.

If we can do:
```
you (client) -> guard -> relay -> exit
```

We should just be able to do this:
```
you (client) -> exit
```

After posting this musing online a friend pointed out that if I had actually read what the Stack
Exchange post I would know that this wouldn't work. Tor blocks any client connecting to an exit node
directly, they posted this line of code from the Tor source:
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

Hm, a setback but lets keep digging.

So it checks the connection's identity digest to make sure it's a known relay before letting it
begin a connection. Lets see what the function `connection_or_digest_is_known_relay` actually does.

```c
/** Return 1 if identity digest <b>id_digest</b> is known to be a
 * currently or recently running relay. Otherwise return 0. */
int
connection_or_digest_is_known_relay(const char *id_digest)
{
  if (router_get_consensus_status_by_id(id_digest))
    return 1; /* It's in the consensus: "yes" */
  if (router_get_by_id_digest(id_digest))
    return 1; /* Not in the consensus, but we have a descriptor for
               * it. Probably it was in a recent consensus. "Yes". */
  return 0;
}
```

Okay! So what's stopping me from just starting a relay node and pretending like I'm forwarding a
middle node when I'm really just sending my own data. 

Looking again at the docs, makes me suspect they there is really no IP checking. So as long as I have
they keys I should be able to act as a relay.

> Since relays have a ramp-up time it makes sense to back up the identity key to be able to restore 
> your relay's reputation after a disk failure - otherwise you would have to go through the ramp-up 
> phase again.
>
> -- *The Tor Project [link](https://community.torproject.org/relay/setup/post-install/)*

Then there should be nothing stopping me if we do this:
```
you (relay) -> exit
```

Now fully nerd sniped I began my hand reimplementation of Tor. 

## The Implementation

I considered basing it off of an existing implementation, but I decided against it for a couple
reasons. Both C Tor and [Arti](https://arti.torproject.org/) are massive codebases. Arti is supposed
to be much cleaner then C Tor but I work the fastest in C++, and I'll be able to debug faster if I
have a good internal model on how the entire code works instead of trying to scavenge through
someone else's codebase. The same friend who pointed out discrepancies in the first idea, had
previous vibe coded a Tor snowflake implementation but the agent failed to handle the cryptography
properly, so I knew having a good mental model here would pay dividends later on.

I'm not completely set on my decision, but at the end of this journey we do have an independent CLI app that
works quite well. More info to plan off for next time I guess.

I also wanted it to be fully statically compiled. Dealing with 20 different package mangers on Linux
is rather cumbersome. So I automatically fetch dependencies if a static build is needed build them
ourselves. Once we have static libraries we can put everything into a single executable when
compiling with musl. 

To make this work I either handle dependencies my self with custom CMake build scripts, or use their
CMake scripts via [CMake
FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html).But generally here the
less libraries we use the better as it cuts down build time.

To initiate a connection with an exit node you have a couple of handshakes to do.

1. TLS

Quite simple, as much as I love hand rolling things we'll be using conventional cryptography
libraries if we want this running faster then Tor. I picked mbedtls, I really like the library after
my experience working with it for undoing Godot encryption, and we'll keep everything portable it's
e*mbed*ed by design. 

A TCP stream is opened 

```c++
    if (no_retry_mbedtls_net_connect(&tcp_net, exit_node_address.c_str(),
                                     exit_port.c_str(),
                                     MBEDTLS_NET_PROTO_TCP) != 0) {
        // connection failed, handle appropriately
    }

```

`no_retry_mbedtls_net_connect` is just a quick fork of the mbedtls net functionality to add a
timeout on connection. This is useful for handling a case when the exit node is blocked by a
firewall, the connection will just stall out.

Then it's as easy as plugging in the SSL connection to the TCP connection
```c++
    mbedtls_ssl_set_bio(&ssl, &tcp_net, mbedtls_net_send, mbedtls_net_recv,
                        NULL);

    if (mbedtls_ssl_handshake(&ssl) != 0) {
        // handle failure
    }
```

2. Versions Exchange

Self explanatory, just tell the server what versions you support.

3. Certs

A Tor relay's keys folder looks like this:

```
-rw------- 1  64 Dec  8 22:23 ed25519_master_id_public_key
-rw------- 1  96 Dec  8 22:23 ed25519_master_id_secret_key
-rw------- 1 172 Dec  8 22:23 ed25519_signing_cert
-rw------- 1  96 Dec  8 22:23 ed25519_signing_secret_key
-rw------- 1 888 Dec  8 22:23 secret_id_key
-rw------- 1 888 Dec  8 22:23 secret_onion_key
-rw------- 1  96 Dec  8 22:23 secret_onion_key_ntor
```

Tor has two key exchange systems, Ed25519 which is the newer system and RSA which despite being
deprecated everything still seems to require. Why was RSA deprecated? I have no idea and couldn't
scrounge up much information.

These are both public key signature systems, where there's a private key and a public key. The
public key can be used to verify a message came from a specific private key. So as long as you get
the public key from a verified stream, you can verify an new message you see as authored by a
specific node.

The only major issue is if a sender is replaying a message it got from the author, a receiver will
have no way to tell if it's a replayed message or if it's a completely new message fabricated for
this connection.

Tor combats this in two punches. The first punch is the certs, Tor will never sign arbitrary
messages with its important keys. The "important keys" being the long term identity key and the
middling term signing key. The only key that will ever sign arbitrary data is the link key, which
will be disposed after the connection is destroyed and never used again. Once a link key is verified
we can get the next part of our handshake.

4. Verification Challenge

This is the second punch, to prevent replays we need to actually verify that the link key was made
for this connection. This is done by sending an authenticate packet, which uses the link key to sign
various information about the connection to prove that yes, indeed this is the connection the link
key was made for.

Then and only then can we verify ourselves as the owners of a specific identity.

5. Key Exchange

So we're done? God I wish.

Now we need an encryption key which we'll use to send our traffic data to the exit with. This is
totally useless when we skip other nodes but if we were to send data across a guard and a middle
node we'd prefer them to not read the data. So each jump of the network has it's own key, that
incrementally encrypts or decrypts a message. This is where *Onion* Routing gets it's name. Each
new layer of the onion is another layer of security, slowly being peeled off.

We'll gloss over the full details here but essentially each node sends the other a public key,
storing it's own corresponding private key. The with the other's sides public key and their own
private key, both sides can generate a shared secret key with an [HMAC
algorithm](https://en.wikipedia.org/wiki/HMAC).

From there we're done and can send encrypted relay packets to and fro.
