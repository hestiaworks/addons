# NSPanel Companion Talkback

Low-latency two-way audio to a Reolink doorbell.

Speaking to the door through the camera's ONVIF backchannel arrives two to
three seconds late, because that path carries a large fixed buffer in the
firmware. Reolink's own app is under a second, and the difference is the
protocol: their app uses Baichuan, on TCP 9000. This add-on does the same.

It takes 16 kHz mono PCM — which is what a panel already sends — encodes it
to ADPCM, and carries it over Baichuan. Nothing resamples.

**Video is not affected.** Scrypted keeps serving the stream, prebuffered, and
keeps HomeKit working. Only the microphone's route changes.

## Configuration

| Option | Meaning |
| --- | --- |
| `camera_host` | The doorbell's address |
| `camera_username` | A **limited** camera user — talk does not need admin |
| `camera_password` | That user's password |
| `camera_port` | Baichuan port, 9000 unless you moved it |
| `camera_channel` | 0 for a standalone doorbell |

## Checking it works

```sh
curl -X POST -H "Authorization: Bearer <token>" http://<host>:8099/api/test-tone
```

Plays a two-tone at the door with no microphone involved, so a silent result
points at the protocol rather than at capture or a quiet room.

`GET /api/ability` reports what the camera says it accepts. Worth a look if
talk goes quiet after a firmware update — the camera answers 200 OK and
acknowledges every packet even when it cannot decode what it is being sent,
so silence is the only symptom it will ever give you.

## Only one talker at a time

The camera permits one, and answers 422 to the second. That is correct — two
people talking to the door at once should conflict — so this reports it
rather than retrying. An abandoned session frees the channel within a second
of the connection dropping, so nothing can wedge it.
