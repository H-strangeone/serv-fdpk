# FDPK

## What is this project?

This project is an experiment in rethinking how data moves and how search works on the internet or more specifically, building **our own free, decentralized internet** from first principles.

It started as an intent to deeply learn **systems programming and architecture**, and evolved into designing and implementing a real protocol and search system where:

- speed is a design goal
- privacy is the default
- every byte has a reason to exist

The long‑term idea is simple:

> At least have *our own* internet — faster, lighter, safer, decentralized, and ours.


before you go deeper i was thinking of building the protocol in rust and the search engine in go.
---

## What are we building?

###  A custom binary network protocol **(FDP)**

- Faster than HTTP  
- Private by design  
- Explicit, predictable, and efficient  
- Built at the byte level, not text level  

###  A distributed, user‑oriented search engine

- No tracking  
- Intent‑based queries  
- User‑controlled ranking  

###  before you go deeper, just know that i was thinking of building the protocol in rust and the search engine in go, but if you have anything else in mind i am very happy to discuss the benefits of having it and doing it that way.

- **Rust** → protocol, packet format, networking, safety, performance  
- **Go** → search engine, concurrency, indexing, ranking  

---

## Why are we building this?


Because i think modern web systems have problems:

- HTTP is verbose and text‑heavy  
- Search engines centralize data and ranking power  
- Privacy is optional instead of default  
- Protocols hide too much behind abstractions  

### My Goals of this project(obviously later this could be something bigger and better)

- Understand networking from **first principles**
- Design a protocol where **every byte has a reason**
- Learn how real internet protocols are built
- Build something **extensible**
- Atleast have myself an internet which is faster and lighter and safer and decentralized and ours.

---

## High-Level Architecture that i have in mind:


```
Client (CLI/Web)-----> FDP Binary Protocol----->  Core Protocol -----> Search Engine
```

---

## What is FDP (Flow‑Driven Protocol)?

FDP is a **binary protocol**.

That means:

- No strings  
- No JSON  
- No repeated headers  
- Just bytes, structure, and rules  

### Core design rules

- Every field has a fixed meaning  
- Every byte has a purpose  
- Parsing is deterministic  
- Invalid packets fail **safely and fast**  

---

## FDP Packet Layout (On‑the‑Wire)

This is what actually travels over the network:

```
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
```

Header size: **36 bytes**  
Hash size: **32 bytes**  

For comparison: HTTP headers are often **100–500 bytes**.

---

## What problems does each field solve?

| Field        | Purpose |
|-------------|---------|
| Version     | Prevents silent protocol breakage |
| Session ID  | Identifies who is talking |
| Intent      | Tells receiver what action to take |
| Priority    | Scheduling and urgency |
| Flags       | Compression, encryption, fragmentation |
| Sequence    | Ordering and duplicate detection |
| Timestamp   | Delay and replay protection |
| Hash        | Integrity and tamper detection |

---

## Binary Protocol Basics

The network does **not** understand structs or strings.

It only sees raw bytes like:

```
01 A3 F9 00 00 00 05 48 65 6C 6C 6F
```

Because of this, we must convert:

- **Structured data → raw bytes** (serialization)
- **Raw bytes → structured data** (deserialization)

This conversion is the **heart of protocol design**.

---

## What is implemented right now?

Current progress focuses on the **packet layer**:

### What is implemented right now?

have been implementing packet structure so currently done with its structure and flags and their methods.

- Packet structure
- On‑the‑wire layout
- Flags system (bit‑packed control byte)
- Compression and encryption indicators
- Serialization (`to_bytes`)
- Deserialization (`from_bytes`)
- Hash‑based integrity verification

At this stage ensured the **packet format is correct, safe, and fully understood** before moving deeper into networking, sessions, and search logic.
