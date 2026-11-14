# Kompromat

Kompromat is a minimalist, open-source protocol for capture-the-flag workflows
on your infrastructure. Mechanically, a simple CLI is used to produce a key file.
Whoever finds it can prove they have it and send you a private note.

I am planning a public capture-the-flag game at [kompromat.sh](https://kompromat.sh)
where anyone can hunt for keys and use the protocol to prove a find.

## How it works

The CLI generates a random 32-byte secret on your machine and derives a public
key from it. You plant the file containing the secret and keep a separate defender key.
The **manifest** is the public registration file. It contains both public keys
and any metadata you want to share.

A finder can use the CLI to create a Schnorr proof and submit it to the API.
Anyone with the public key can verify that the signer held the secret when
they made the proof. Reading the flag itself is silent.

Each report opens a **dossier** where you and that finder can exchange encrypted
notes. The CLI saves a dossier key for the finder. Your defender key opens all
the dossiers for this flag. Keep those keys backed up outside the target.
Older shared flags let anyone holding a copy read their shared notes.

## What the API does

The API is a small HTTP service backed by SQLite. The `register` command sends
the manifest to the API and prints the hunt URL, `/dossiers/{flag}`. A finder
sends a signed proof and encrypted note to `POST /report`. The API verifies
the proof and returns the submission with a receipt giving its dossier ID,
order of arrival and time.

The first note is at `/threads/{id}` and replies are at `/threads/{id}/messages`.
The API stores the notes as ciphertext. Anyone with the hunt URL can see the
dossier IDs, when reports arrived, which side sent each note and its size.

## Create a canary

With Rust installed, run these commands from the repository to install the CLI
and start the local API.

```sh
cargo install --locked --path .
kompromat-api
```

In another terminal, use a private directory to write the flag to `canary.json`,
save the public manifest as `manifest.json`, and register it.

```sh
kompromat generate --out canary.json --manifest-out manifest.json
kompromat register manifest.json
```

Keep `defender.json` here and place a copy of `canary.json` in a backup. Share
the hunt URL in your own brief. Whoever finds the file can run
`kompromat report canary.json --hunt "$HUNT_URL" --message 'Found in the backup'`.
For a longer note, use `--message-stdin < writeup.txt`. The flag stays local.

The finder reads replies with `kompromat unlock <dossier-key-file>`. You can
list reports with `kompromat unlock defender.json` and add `--dossier <id>` to read one.
Either of you can reply with `kompromat attach --key <key> --message 'Got it'`.
With the defender key, add `--dossier <id>`. If the receipt gets lost, the finder
can run `report` again with the saved dossier key. If a reply was interrupted,
read the conversation before resending it.

To list a hunt, run `kompromat publish defender.json --title "Export preview" --brief "$BRIEF_URL"`.
It appears at `/` and in the JSON list at `/hunts` until you `withdraw` it.
A brief might say “Use tenant A on the preview through Friday. If its export
includes a record from tenant B, send me the record ID.” The receipt tells
you when the report arrived. Check the record against the export before awarding credit.

These commands use `http://127.0.0.1:3000`. For a remote hunt, put an HTTPS
reverse proxy in front of the local API and pass its public HTTPS URL with
`--api` to both `generate` and `register`.
