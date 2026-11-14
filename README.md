# Kompromat

Kompromat is a capture-the-flag protocol for your infrastructure. A finder
can prove they reached a planted key and send an encrypted write-up.

I am planning a public capture-the-flag game at [kompromat.sh](https://kompromat.sh)
where anyone can hunt for keys and use the protocol to prove a find.

## Private dossiers

DEF generates the flag, registers its manifest, and shares the hunt URL printed
by `register`. Plant only `flag.json`. Keep `defender.json` private.
For a remote registry, pass the same HTTPS `--api` to both commands.

```sh
kompromat generate --out flag.json --defender-out defender.json > manifest.json
kompromat register manifest.json
```

ATK uses the hunt URL from the registry or DEF. The CLI checks the flag and
recipient against that hunt before sending the encrypted write-up.

```sh
kompromat report flag.json --hunt "$HUNT_URL" --message 'I could read another tenant’s export' --dossier-key-out alice.json
kompromat unlock alice.json
```

`POST /report` verifies the flag proof and signed write-up together. On
acceptance ATK receives the dossier ID, order for this flag, and UTC time.
Retry with `kompromat report alice.json` to keep the same ID and order.

```sh
kompromat unlock defender.json
kompromat unlock defender.json --dossier "$ID"
kompromat attach --key defender.json --dossier "$ID" --message 'Which export request?'
kompromat attach --key alice.json --message 'The scheduled export.'
```

ATK and DEF decrypt locally. Use the dossier key created on your machine for
follow-ups. Older finder keys also need `--hunt`. Pass `--after N` to `unlock`
when a page returns `next_after`. DEF judges the report.

## Run locally

With Rust installed, run these commands from the repository to install the CLI
and start the local API.

```sh
cargo install --locked --path .
kompromat-api
```

For a shared dossier, generate a flag without a defender key.

```sh
kompromat generate --out canary.json > manifest.json
kompromat register manifest.json
```

These commands use `http://127.0.0.1:3000`. For a canary on another machine,
pass the same reachable API URL with `--api` to both `generate` and `register`.

Plant a copy of `canary.json`. A finder can submit a bare proof with
`kompromat report canary.json`. For a shared note, pass the registered hunt URL
with `--hunt` and the text with `--message`. Anyone with the flag can read it.
To prepare a shared note offline, use `prove --message` with `--manifest`
pointing to the public manifest obtained from the registry.
