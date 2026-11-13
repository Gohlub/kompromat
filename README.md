# Компромат

Kompromat is a minimalist, open-source protocol for capture-the-flag workflows
on your infrastructure. Mechanically, a simple CLI is used to produce a key file. Whoever finds it can prove
they have it and send you a private note, without the API or anyone else knowing how or what.

I am planning a public capture-the-flag game at [kompromat.sh](https://kompromat.sh)
where anyone can hunt for keys and use the protocol to prove a find.

## How it works

The CLI generates a random 32-byte secret on your machine and derives a public
key from it. The **manifest** is the public registration file. It contains
the public key and metadata. The **dossier** is the private channel where people
with copies of the secret key file can exchange encrypted notes.

A finder can use the CLI to create a Schnorr proof and submit it to the API.
Anyone with the public key can verify that the signer held the secret when
they made the proof.

A proof can stand on its own. To include a private reply, the CLI derives a
separate encryption key from the same secret with `HKDF-SHA256`, encrypts the text
with `XChaCha20-Poly1305`, and signs the proof together with the encrypted reply.
Anyone who holds a copy of the key file can read the reply.

## What the API does

The API is a small HTTP service backed by SQLite. The `register` command sends
the manifest to the API. A *finder* sends a signed proof to `POST /proofs`.
The API verifies it against the registered key and stores it for retrieval. The server does this without knowing where you placed the file or what it means to you.

In the dossier, a finder can leave an encrypted note with `report --message`.
Any key holder can reply with `kompromat attach canary.json --message 'Got it'`
or read the conversation with
`kompromat unlock canary.json`. The API stores the notes as ciphertext.

## Create a canary

With Rust installed, run these commands from the repository to install the CLI
and start the local API.

```sh
cargo install --locked --path .
kompromat-api
```

In another terminal, write the secret key to `canary.json`, save the public
manifest as `manifest.json`, and register it.

```sh
kompromat generate --out canary.json > manifest.json
kompromat register manifest.json
```

These commands use `http://127.0.0.1:3000`. For a canary on another machine,
pass the same reachable API URL with `--api` to both `generate` and `register`.

Keep a copy of `canary.json` and place another in a backup. The file carries
its own reporting instructions and API address. Whoever finds it can run
`kompromat report canary.json` to send a proof, or add
`--message 'Found in the backup'` to include a private note.
