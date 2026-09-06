# Participant consent — lab network capture (M11.1)

This capture records **network traffic on a private lab network created for this project**. It
is not a recording of anyone's normal internet use, and it must not be run on a shared, campus,
employer or home network carrying other people's traffic.

## What is recorded

- Packet headers and payloads on the lab hotspot interface only, for the duration of a session
  (typically 20–30 minutes), written to a `.pcap` file.
- Only devices that the named participants below deliberately connect to the lab hotspot.

## What is done with it

- Feature extraction and model training/evaluation for the SIH26153 project.
- A derived, **labelled** subset may be published with the project so results are reproducible.
  Before any publication: IP addresses are pseudonymised, and the released artefact is reviewed
  for anything personally identifying.

## Rules the operator agrees to

1. **Only attack machines and accounts owned by the team.** No third-party systems, no
   internet-facing targets, no production infrastructure.
2. **Isolated network.** The lab hotspot must not bridge to a network carrying other people's
   traffic.
3. **Dummy credentials only.** The brute-force scenario uses accounts created for the capture;
   no real password is ever typed into a captured session.
4. **No personal browsing during capture.** Benign traffic is generated from a scripted list.
5. Any participant may stop the capture at any time and have that session's file deleted.

## Participants

| Name | Role (operator / benign-traffic device owner) | Date | Signature |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

Capture session ID: ________________  Location: ________________

Operator confirms all five rules above were followed: ________________ (signature)
