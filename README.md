FDP — A Next-Generation Protocol & Search System
What is this project?

This project is an experiment in rethinking how data moves and how search works on the internet, or more so our own free decentralized internet in every way.

We are building:

A custom binary network protocol (FDP)
– faster than HTTP
– private by design
– explicit, predictable, and efficient

A distributed, user-oriented search engine
– no tracking
– intent-based queries
– user-controlled ranking

started as an intent to learn systems programming and architecture,

before you go deeper i was thinking of building the protocol in rust and the search engine in go.


Why are we building this?

Because i think modern web systems have problems:

HTTP is verbose and text-heavy
Search engines centralize data and control ranking
Privacy is optional instead of default
Protocols hide too much behind abstractions

my goal is to:

Understand networking from first principles
Design a protocol where every byte has a reason
Learn how real internet protocols are built
Build something extensible
Atleast have myself an internet which is faster and lighter and safer and decentralized and ours.


High-Level Architecture that i have in mind:

Client (CLI/Web)-----> FDP Binary Protocol----->  Core Protocol -----> Search Engine


What is FDP (Flow-Driven Protocol)?

FDP is a binary protocol.
That means:
No strings
No JSON
No headers repeated every request
Just bytes, structure, and rules
Core design rules
Every field has a fixed meaning
Every byte has a purpose
Parsing is deterministic
Invalid packets fail safely and faster

FDP Packet Layout (On-the-Wire)

This is what actually travels over the network:

┌────────────┬────────────────────────────┐
│ Byte 0     │ Version (1 byte)           │
│ Bytes 1-16 │ Session ID (16 bytes)      │
│ Byte 17    │ Intent (1 byte)            │
│ Byte 18    │ Priority (1 byte)          │
│ Byte 19    │ Flags (1 byte)             │
│ Bytes 20-23│ Sequence number (4 bytes)  │
│ Bytes 24-27│ Payload length (4 bytes)   │
│ Bytes 28-35│ Timestamp (8 bytes)        │
│ Bytes 36+  │ Payload (variable)         │
│ Last 32    │ SHA-256 Hash (32 bytes)    │
└────────────┴────────────────────────────┘
this i asked ai to create cause this table looks beautiful this way


Header size: 36 bytes
Hash size: 32 bytes

For comparison: HTTP headers are often 100–500 bytes.

What problems does each field solve?

Version	- Prevents silent protocol breakage
Session ID - Identifies who is talking
Intent - Tells receiver what action to take
Priority	- Scheduling & urgency
Flags	- Compression, encryption, fragmentation
Sequence	- Ordering & duplicate detection
Timestamp	- Delay & replay protection
Hash	- Integrity & tamper detection


Binary Protocol Basic:

The network does not understand structs or strings. 
It only sees bytes like:
01 A3 F9 00 00 00 05 48 65 6C 6C 6F and so and so

So we must convert:

Structured data into raw bytes (serialization) 

and back again raw bytes into structured data (deserialization)


This conversion is the heart of this protocol design.

What is implemented right now?

have been implementing packet structure so currently done with its structure and flags and their methods.
