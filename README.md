# sendspin-sender
This project is fully written by AI.

# This is 100% AI code
I didn't thoroughly check it or even made architectural decisions. My work is this:

> I want to be able to stream low latency audio from my linux pc to my music assistant. Sendspin is the perfect protocol for that, but I couldn't find any sendspin senders that transmit audio from a pc to a sendspin server. Build this exact program in rust and preferrably with an easy integration into pipewire so it later shows as a normal output in the kde audio control center

So this is WTFPL licensed.
## Actual README

Stream your PC's audio to a [Sendspin](https://github.com/Sendspin/spec) server
(e.g. [Music Assistant](https://music-assistant.io/)) using the Sendspin
`source@v1` role.

The sender creates a **virtual PipeWire sink** named *Sendspin*. It shows up in
your desktop's audio control center (KDE, GNOME, …) like any other output
device. Pick it as the output for any application, and that audio is captured
and streamed to the Sendspin server with low latency (10 ms PCM chunks).

```
app ─▶ "Sendspin" virtual sink ─▶ capture ─▶ Sendspin source@v1 (Noise-encrypted) ─▶ server
```

## Features

- Implements the Sendspin `source@v1` role over `ws://`/`wss://`.
- **Noise `KKpsk2`** encrypted transport (`25519_ChaChaPoly_SHA256`), including
  the in-band re-handshake used for pairing.
- **Pairing PSK flow**: no six-digit codes; pair once by pasting a token into
  the server.
- **Client-initiated** connections only: it dials the server (optionally
  discovering it over mDNS) and never advertises itself for server-initiated
  connections.
- Clock synchronization (Kalman-filtered NTP-style offset/drift) so chunk
  timestamps land in the server's clock domain.
- PCM (`s16le`) output at 48 kHz stereo by default, in 10 ms chunks.
- Runs as a **systemd user service**.
- Replaces any lingering sink left by a previous run, so restarts never
  accumulate duplicate output devices.

## Requirements

- Linux with a running PipeWire session (`pipewire` + `wireplumber`).
- Rust toolchain to build (edition 2024; recent stable).

## Build

```sh
cargo build --release
install -Dm755 target/release/sendspin-sender ~/.cargo/bin/sendspin-sender
```

### Prebuilt binaries

CI builds `x86_64` and `aarch64` Linux binaries on every push and attaches
tarballs to tagged releases (`v*`). Each archive contains the stripped binary,
the systemd unit, the example config and this README:

```sh
tar xzf sendspin-sender-vX.Y.Z-x86_64.tar.gz
install -Dm755 sendspin-sender ~/.cargo/bin/sendspin-sender
install -Dm644 sendspin-sender.service ~/.config/systemd/user/sendspin-sender.service
```

The release binary dynamically links only `libpipewire-0.3.so.0` and glibc, so
it runs on any distro with PipeWire installed.

### Build dependencies

`pipewire-sys` generates bindings with `bindgen`, so the build needs the
PipeWire headers and libclang (in addition to `pkg-config` and a C toolchain):

- Debian/Ubuntu: `libpipewire-0.3-dev libspa-0.2-dev libclang-dev pkg-config clang`
- Fedora: `pipewire-devel clang-devel`
- Arch: `pipewire libclang`

PipeWire **≥ 0.3.44** is required (the crate enables the `v0_3_44` feature set).

## Pairing

Pairing uses a **pairing token**. The client prints one; you paste it into your
Sendspin server. The token embeds the client's static public key and its
per-device pairing PSK.

1. Print a token (generates and persists the client identity and pairing PSK on
   first use, under `~/.local/state/sendspin-sender/`):

   ```sh
   sendspin-sender print-token
   ```

2. Paste the `SP:0…` token into your server's pairing UI, selecting this client.
3. In Music Assistant, the client appears in the Sendspin provider's pairing
   dialog. Paste the token there.

Once paired, the server stores a long-term PSK and the client persists a matching
record. Later connections use that record automatically — you never repeat the
token.

To inspect a token without pairing:

```sh
sendspin-sender verify-token 'SP:0…'
```

## Running

```sh
# Dial a specific server
sendspin-sender --server ws://192.168.1.10:8927/sendspin run

# Or discover a server over mDNS (_sendspin-server._tcp)
sendspin-sender run
```

While it runs, the *Sendspin* sink is visible in your audio control center.
Route any application to it and the audio is streamed. Playback starts when the
server sends the source `start` command (e.g. when you start the source in Music
Assistant).

Log verbosity follows `RUST_LOG`:

```sh
RUST_LOG=sendspin_sender=debug sendspin-sender run
```

## Configuration

Configuration is read from `~/.config/sendspin-sender/config.toml` (override with
`--config`). Every key is optional — see
[`config.example.toml`](config.example.toml) for the full annotated set:

```toml
server_url = "ws://192.168.1.10:8927/sendspin"  # empty => mDNS discovery
discover = true
name = "Sendspin Sender"
codec = "pcm"            # "pcm" or "flac"
sample_rate = 48000
channels = 2
bit_depth = 16
chunk_millis = 10
line_sense = false
sink_name = "sendspin-sender.sink"
sink_description = "Sendspin"
```

### State

| Path                                          | Contents                          |
| --------------------------------------------- | --------------------------------- |
| `~/.config/sendspin-sender/config.toml`       | Configuration                     |
| `~/.local/state/sendspin-sender/identity.toml`| Static keypair (keep secret)      |
| `~/.local/state/sendspin-sender/pairings.toml`| Pairing PSK + per-server records  |

## systemd user service

```sh
install -Dm644 dist/sendspin-sender.service ~/.config/systemd/user/sendspin-sender.service
systemctl --user daemon-reload
systemctl --user enable --now sendspin-sender.service
journalctl --user -u sendspin-sender -f
```

Adjust `ExecStart` in the unit if the binary is not at `~/.cargo/bin/sendspin-sender`.

## Latency tuning

End-to-end delay is the sum of four stages. The sender controls only the first two,
which are small; the last two dominate and are tuned on the server and player.

| Stage                        | Typical | Controlled by                          |
| ---------------------------- | ------- | -------------------------------------- |
| Desktop → virtual sink       | ~10 ms  | PipeWire quantum (this sender)         |
| Capture → chunk → network    | ~10 ms  | `chunk_millis` (this sender)           |
| Server → player send-ahead   | 0.5–2 s | Player's `min_buffer_ms`; server policy |
| Player decode + audio output | 30–200 ms | Player (`required_lead_time_ms`, backend) |

### Sender-side

- `chunk_millis` (default 10) sets both the chunk duration and the PipeWire
  scheduling quantum. Lowering it to `5` trims a few ms. It cannot go below the
  protocol's 5 ms minimum.
- The sender asks PipeWire for a `node.latency` equal to one chunk, so the graph
  runs at 10 ms instead of its ~21 ms default. Verify with:
  `pw-cli info sendspin-sender.sink | grep node.latency` → `480/48000`.
- Backlogged audio is dropped past a small bound (~60 ms) so a stall resumes from
  live capture instead of playing stale audio.

These together are usually **under ~30 ms** and are not where a multi-second delay
comes from.

### Server- and player-side (the usual cause)

The server schedules live source audio at least each player's `min_buffer_ms`
ahead of its timestamp, and never less while playing (see the Sendspin
[player role](https://github.com/Sendspin/spec/blob/main/roles/player/v1.md#server-audio-send-constraints)).
A web player that reports a large `min_buffer_ms` therefore adds that much latency.

For the **Music Assistant web player**:

- Its reported `min_buffer_ms` / `required_lead_time_ms` are chosen by the web
  player front-end. If your MA build exposes a "Sendspin"/player latency or
  buffer setting for it, lower it — a LAN can run comfortably at 100–200 ms.
- MA has a per-player **static delay** setting (`sendspin_static_delay`, default
  0). Keep it at `0`; raising it adds delay.
- Live sources (`AUDIO_SOURCE`) stay at the `min_buffer_ms` floor, so that value
  is effectively your end-to-end buffer. Buffered media (normal tracks) are less
  affected because the server can race ahead.
- Routing source audio through MA's ffmpeg/DSP path (resampling, filters) adds a
  little more; a source format matching the player's preferred format avoids some
  resampling. Announce `sample_rate`/`channels` matching what the player wants
  (commonly 48 kHz stereo).

If you can measure the player's reported `min_buffer_ms`, that is very close to
the floor of your achievable delay; the sender cannot go below it.

## Protocol notes

- Handshake: Noise `KKpsk2_25519_ChaChaPoly_SHA256`. The server is the Noise
  initiator; the client is the responder. The PSK is mixed at location 2, after
  message 1, so the client reads `psk_id`/`psk_category` (`lt`/`pr`/`sn`) from
  message 1 before selecting a credential.
- The handshake hash `h` (the prologue for re-handshakes) is only final after
  message 2 is written — the client captures it at that point.
- The client always keeps its pairing PSK among its handshake candidates so the
  server can re-handshake onto it for (re-)pairing.
- An in-band re-handshake swaps session keys without closing the WebSocket; the
  client answers message 2 under the old keys, then both switch. Streams and the
  time filter persist across the swap.
- Source audio chunks are `[12][timestamp: u64 BE][PCM]`, sent as encrypted
  binary messages, timestamped in the server's clock domain.
