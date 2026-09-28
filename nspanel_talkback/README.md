# NSPanel Companion Talkback

Low-latency two-way audio from an NSPanel to a Reolink doorbell.

Speaking to the door through the camera's ONVIF backchannel arrives two to
three seconds late: that path carries a large fixed buffer in the firmware,
and no amount of care on this side removes it. Reolink's own app is under a
second, and the difference is the protocol — their app uses **Baichuan**, on
TCP 9000. So does this.

The add-on takes the 16 kHz mono PCM a panel already sends, encodes it to
ADPCM, and carries it over Baichuan. Nothing resamples; the rate already
matches what the camera asks for.

**Video is not affected.** Whatever serves the panel's video goes on doing so.
Only the microphone's route changes.

## Configuration

| Option | Meaning |
| --- | --- |
| `camera_host` | The doorbell's address |
| `camera_username` | A **limited** camera user — talkback does not need admin |
| `camera_password` | That user's password |
| `camera_port` | Baichuan port, 9000 unless you moved it |
| `camera_channel` | 0 for a standalone doorbell |

Home Assistant pairs with this add-on by itself when both run on the same
host: the pairing code is readable only from localhost, and answering there is
what establishes that the add-on is the local one.

## Checking it works

The panel editor has a **Test at the door** button. By hand:

```sh
curl -X POST -H "Authorization: Bearer <token>" http://<host>:8099/api/test-tone
```

Both play a two-tone at the door with no microphone involved, so silence
points at the protocol path rather than at capture, gain, or a quiet room.

| Endpoint | |
| --- | --- |
| `GET /api/info` | version, whether paired, configured camera |
| `GET /api/ability` | what the camera says it accepts |
| `GET /api/diagnostics` | the last dozen talks, timed |
| `POST /api/test-tone` | a tone at the door |
| `POST /api/talk` | 16 kHz mono PCM, streamed |

`/api/diagnostics` is the one to reach for when talkback is slow. Each record
compares how long a request had been open when speech arrived against how much
audio actually arrived before it: equal means the panel streamed in real time,
less means it stalled, more means it dumped a backlog. `drift_seconds` then
says whether the camera was fed slower than real time once speech started.

## Behaviour worth knowing

**Silence before speech is dropped.** A panel opens its talkback request as
soon as a camera page appears and fills the wait with zero-filled frames.
Forwarding those would fill the camera's playout buffer before the first word,
and since it drains in real time every word would arrive that far behind.

**One talker at a time.** The camera permits one, and answers 422 to the
second. That is correct — two people talking to a door should conflict — so it
is reported rather than retried. The channel is claimed at the first word and
released after a second of silence, so letting go of the button frees it for a
phone, another panel, or HomeKit.

**The connection stays open between talks**, with a keepalive, because
establishing it costs three round trips while claiming the talk channel costs
about 50 ms. An abandoned session frees everything within a second of the
connection dropping.

**The camera fails silently.** Hand it a format it dislikes and it answers
`200 OK`, acknowledges every packet, and plays nothing. `TALKABILITY` is
queried and compared at connection time for that reason — if a firmware update
moves the goalposts, the log says so rather than the doorbell going quiet.

## If the add-on is unavailable

Panels fall back to their previous talkback path — slower, but you can still
answer the door. This add-on is an optimisation, not a dependency.
