# nostrnode-cli

⚠️ This is alpha! Use at your own risk! It is under development but works. Please open issues, submit PR's or reach out.

## What problem does nostrnode solve?
Using multiple Tor endpoints to speak to multiple Bitcoin related services simultaneously via a light client is an incredibly
painful experience, massive latency and unreliability make it unworkable for the most part.

## What does nostrnode do?
Specifically, nostrnode receives encrypted rpc commands intended for Core Lightning, Join Market and Bitcoin Core. 
nostrnode decrypts the command, builds the http request for localhost and forwards it to the correct service (identified 
by port for now). nostrnode takes the response from said service, encrypts it, packages it into a nostr event and sends 
it to the relay which forwards it to the client.

## Why nostrnode?

### Don't trust verify.
nostr uses a bitcoin private/public keypair to sign and verify all messages it sends and receives. Before any url request
touches the internet it is first encapsulated into a nostr event which we signed/verified with our keypair. This is beneficial
because it ensures no middle man has altered your messages. We verify all events locally and ignore them if they are invalid.
We have more layers of security then only relying on ssl (or whatever), you could even use http and your traffic content is still
encrypted.

### easy to use
It is extremely easy to configure and requires no real setup by the client at all other than running the required services
and installing nostrnode. Rpc credentials are produced by nostrnode so that users can add them to their bitcoin.conf, as is the
ssl cert required by Join Market and the master key required by Sparko (Core Lightning). Bitcoin Core and Core Lightning
(thanks to Sparko) support fine-grained permissions.

Users can easily run their own nostr relay to gain even more privacy, speed and reliability. They are very easy to spin up
and use minimal resources.

To connect, light clients need a keypair (which the client creates) and a subscription key to nostrnode (which nostrnode 
creates) to gain access to all services. At present light clients require an array of sensitive, plain text credentials 
to connect which is not only messy from a UX perspective but could also be less secure than handling them in plain text 
via QR. Users must be extremely careful how they store their private key, if the keys are compromised you are screwed! 
Clients should obviously handle the nostr keys themselves, however the encryption key ought to be created out of band.

If a user wants to stop remote access they just quit nostrnode, all services will remain running with rpc only exposed to 
`localhost`. nostrnode is hardcoded to only issue rpc to `localhost`.

### It's fast!
It is much faster then using Tor or some VPNs. That is not to say you shouldn't use nostrnode or a client without a VPN or 
Tor! nostr is not mutually exclusive to Tor or VPNs, you can use all of the above simultaneously on clients and servers.
We can run the nostr socket on Tor and it will still be faster than talking to multiple Tor endpoints via http.

## Why nostr?
I will copy a few tidbits from the nostr repo to explain:
- "The simplest open protocol that is able to create a censorship-resistant global "social" network once and for all."
- "It doesn't rely on any trusted central server, hence it is resilient; it is based on cryptographic keys and signatures, 
   so it is tamper-proof; it does not rely on P2P techniques, therefore it works."

I see nostr as a decentralized network where we can broadcast data to each other in a censorship resistant way. It seems
like the perfect medium for Bitcoin light clients and servers to communicate over. If nostr gains traction (I think it will) 
potentially all Bitcoin related network traffic can be obfuscated in a sea of nostr "social" apps.

## Installation
You need python 3.9.
```bash
git clone nostrnode-cli...
cd nostrnode-cli
pip3 install -r requirements.txt
```

## Usage
```bash
python3 nostrnode.py
```