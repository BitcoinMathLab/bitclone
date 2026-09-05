# BitClone Development Reference

## Learning Bitcoin by creating a Bitcoin clone

---

## Development environment

The primary external Bitcoin block source and storage host is currently the downstairs Linux computer running the
Bitcoin Core daemon (accessed with `bitcoin-cli`). Its current LAN address is `192.168.0.108`, but that address may
change; integrations should discover or configure the current address rather than hard-code it.

### Remote Core prerequisite

BitClone development and testing that retrieves real block or transaction data requires an active SSH tunnel from
Lenny to the downstairs Linux computer (`Skyscraper`). Mocked unit tests do not require the tunnel.

From the repository root, run:

```bash
./.venv/bin/python startup.py
```

The startup helper creates or reuses a persistent SSH connection, starts Bitcoin Core on Skyscraper if necessary,
waits for its RPC service, atomically refreshes `~/.bitclone/skyscraper.cookie`, and opens the local RPC tunnel on port
18332. It then starts the sibling backend on `http://127.0.0.1:8000` and frontend on
`http://127.0.0.1:4200`. The application processes run in the background; their PID and log files are stored in
`~/.bitclone`. Services already listening on those ports are left running. The helper may prompt for Greg's SSH
password when no SSH key or existing control connection is available, and does not store that password.

To prepare only Bitcoin Core and the RPC tunnel, retaining the helper's earlier behavior, run:

```bash
./.venv/bin/python startup.py --infrastructure-only
```

The SSH connection and tunnel remain available after the helper exits. Close them at the end of a development session
with:

```bash
ssh -S ~/.bitclone/skyscraper-ssh.sock -O exit greg@Skyscraper
```

If hostname discovery is unavailable, select Skyscraper's current LAN address explicitly:

```bash
./.venv/bin/python startup.py --ssh-host 192.168.0.108
```

The current address may change and is therefore only a fallback, not embedded in the helper. To establish the tunnel
and copy the cookie manually instead, start this command in a dedicated terminal and leave it open:

```bash
ssh -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -L 127.0.0.1:18332:127.0.0.1:8332 \
  greg@192.168.0.108
```

Bitcoin Core RPC authentication currently uses Skyscraper's cookie at `/mnt/bitcoin/Bitcoin/.cookie`. In the manual
workflow, copy it to Lenny as `~/.bitclone/skyscraper.cookie` with mode `600`. The cookie rotates whenever Bitcoin Core
restarts and must then be copied again; `startup.py` handles this refresh on every run.

BitClone's `bitcoin-core-remote` storage mode reads blocks on demand through Bitcoin Core JSON-RPC and does not retain
block bodies locally. Prefer the SSH tunnel to Core's loopback RPC listener instead of exposing port 8332 broadly.
Initialize the remote data directory once:

```bash
python -m src \
  --data-dir ~/.bitclone-remote \
  --block-storage bitcoin-core-remote \
  --core-rpc-url http://127.0.0.1:18332 \
  --core-rpc-cookie ~/.bitclone/skyscraper.cookie \
  init
```

Later commands load those settings from `~/.bitclone-remote/bitclone.toml`, so only the data directory needs to be
selected:

```bash
python -m src --data-dir ~/.bitclone-remote getremotechaininfo
python -m src --data-dir ~/.bitclone-remote status
```

### Local service API

BitClone can expose its read-only v1 operator API on the loopback interface. Supply a bearer token through the
environment so it is not written to `bitclone.toml`:

```bash
export BITCLONE_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m src --data-dir ~/.bitclone serve-api
```

If the environment variable is omitted, BitClone prints a high-entropy token valid only for that server run. For a
remote-backed inspection session that should not start BitClone's public P2P workers, add `--api-only`.

The API defaults to `http://127.0.0.1:8334/api/v1`. Its generated OpenAPI document is available at
`/api/v1/openapi.json`. Health, version, and OpenAPI metadata are public locally; operational resources require:

```bash
curl -H "Authorization: Bearer $BITCLONE_API_TOKEN" \
  http://127.0.0.1:8334/api/v1/node/status
```

Live sync, peer, block, mempool, warning, and lifecycle events are available through SSE:

```bash
curl -N -H "Authorization: Bearer $BITCLONE_API_TOKEN" \
  http://127.0.0.1:8334/api/v1/events
```

Known peer addresses, including disconnected endpoints and their latest connection diagnostics, are available at:

```bash
curl -H "Authorization: Bearer $BITCLONE_API_TOKEN" \
  http://127.0.0.1:8334/api/v1/peers/address-book
```

The same server accepts Bitcoin-compatible JSON-RPC at `/` and `/rpc`. Bearer authentication works for native clients;
Bitcoin tooling can use any non-empty RPC username and the BitClone API token as its HTTP Basic password:

```bash
bitcoin-cli \
  -rpcconnect=127.0.0.1 \
  -rpcport=8334 \
  -rpcuser=bitclone \
  -rpcpassword="$BITCLONE_API_TOKEN" \
  getblockchaininfo
```

Supported compatibility methods are `getblockchaininfo`, `getnetworkinfo`, `getpeerinfo`, `getrawmempool`,
`getrawtransaction`, `decoderawtransaction`, `sendrawtransaction`, and `gettxout`. Wallet and mining RPC methods return
explicitly unavailable errors until their planned sprints.

### Browser operator console

Open `http://127.0.0.1:8334/` in a browser on the machine running BitClone. Enter the same
`BITCLONE_API_TOKEN` used to start the server. The token is retained only in that browser tab's session storage.

The console provides node and synchronization status, explicit local-versus-remote trust labeling, chain details,
peer diagnostics, mempool inspection, block and transaction lookup, live node events, and an allowlisted advanced RPC
console. Mutating RPC methods display a warning and require an additional confirmation.

In `bitcoin-core-remote` storage mode, the mempool view reads Bitcoin Core's live verbose mempool and labels it as a
trusted remote source. Archival and pruned BitClone nodes continue to show their independently maintained local mempool.
Local mempool admission reads directly from the node's active-chain UTXO view and overlays outputs from unconfirmed
parents. Transaction dependencies are bounded by ancestor and descendant count/size policy, unknown-parent transactions
are retained briefly in a bounded orphan pool, and block templates select fee-paying packages in dependency order.
Opt-in BIP125 replacements evict their complete conflict set only when they cover its fees plus incremental relay cost.
Under memory pressure, low-fee descendant packages are evicted and establish a decaying rolling minimum relay fee.
Consensus-invalid, non-standard, orphan, and other policy outcomes remain distinct within mempool admission.

Local chainstate updates commit block-index membership, undo data, and UTXO mutations as one transaction. Block-file
writes are rolled back on commit failure and reconciled on startup. Competing branches are selected by cumulative work,
with bounded orphan-block retention and hard-coded mainnet checkpoints at known historical heights.

The browser runtime has no JavaScript package dependencies. Playwright is used only for development tests:

```bash
npm install
sudo npx playwright install-deps chromium  # Ubuntu/Debian system libraries
npx playwright install chromium
npm run test:browser
```

Binding beyond loopback is rejected unless a TLS certificate, private key, and explicit browser origin are configured.
The API applies exact origin checks, scoped bearer credentials, rate limits, secret redaction, CSRF groundwork, and a
mode-`0600` audit log under the selected network's log directory.

---

## Bitcoin Notes

Types of Bitcoin wallets:

- Full node: A program that validates the entire history of Bitcoin transactions. (A full node uses the most resources
  but offers full autonomy to the user.)
- Lightweight client (AKA: simplified-payment-verification (SPV) client): Connects to a full node for sending and
  receiving Bitcoin transacations, but stores the user wallet locally; partially validates the transactions it receives,
  and independently creates outgoing transactions.
- 3rd-party API client: One that interacts with Bitcoin through a 3rd-party system of APIs rather than by connecting to
  the Bitcoin network directly. The wallet may be stored by the user or 3rd-party servers. The client trusts the remote
  server to provide it with accurate information and protect its privacy.

NB: Bitcoin is a peer-to-peer (P2P) network. Full nodes are called the _peers_ and lightweight wallets (and other
software) are called _clients_.

- The pair of currencies given as (x/y) represent the market exchange rate for those currencies. e.g If (BTC/USD) =
  $62780, this means that 1 BTC can be exchanged for 62780 US dollars.

### Transactions

- Transactions are kept similar to double-entry bookkeeping. Each transaction contains one or more _inputs_ and one or
  more _outputs_. The _inputs_ represent spending funds and the _outputs_ represent receiving funds.
- The inputs and outputs will not necessarily add up to the same amount. The total amount represented by all the inputs
  should exceed the total amount assigned in the outputs. The difference between inputs and outputs represents the
  transaction fee, collected by the miner.
- The transaction also contains proof of ownership in the form of a digital signature (created using elliptic curves).
- The input in a transaction refers to an output of a previous transaction. It continues in this pattern until it
  reaches the original mining transaction which created the coins.
- In addition to one or more outputs that pay the receiver of bitcoins, many transactions will also include an output
  that pays the spender of the bitcoins, called a _change_ output. This is similar to the idea of paying $1 USD for
  something and getting $0.50 change. The input amount will likely not equal the amount to be paid to the recipient,
  hence the necessity of change output.
- However not every transaction has a change output. Such transactions are called _changeless_ transactions, and they
  can only have a single output.
- Different wallets use different strategies when choosing which inputs to use in a payment, called _coin selection_.

#### Types of transactions

- Simple payment (one input, two outputs - recipient and change)
- Aggregating transaction (collecting many small inputs to aggregate together to one output)
- Distributing transaction (AKA: payment batching) (one input to many outputs)

The wallet application contains all the logic necessary for creating a transaction. The user need only supply the
recipient address, amount and transaction fee. The wallet can create and sign this transaction without being connected
to the Bitcoin network. (However, to send the transaction the wallet will have to connect to the network.)

### UTXOs

A Bitcoin wallet that runs on a full node contains a copy of every confirmed transactions unspent outputs (that is,
outputs not yet referenced by an input of a later transaction). These are called _unspent transaction outputs (UTXOs)_.
Hence, a wallet that displays a users Bitcoin balance is in fact reporting the total amount assigned to all UTXOs with
the user's address.

### Propagation

Once the transaction is created, it needs to be propagated to the Bitcoin network. As every transaction contains all
necessary information to be processed, it does not matter how the user connects to the network. Once connected to the
Bitcoin network, the user (or an application) must send the transaction to a full node. Once received, a node will
validate the transaction and forward it to all other peers its connected to if the transaction is accepted. This method
of forwarding to all other connected peers is called _gossiping_. Thus the transaction will get propagated to a large
number of nodes in only a few seconds.

## Mining

Suppose a user has sent a transaction to the network and it is received by a node. The transaction does not become
accepted (part of the _blockchain_) until it is included in a _block_ through a process called _mining_. (Mining will be
explained in more depth later).

As a brief explanation, to mine a block means to calculate an appropriate value to include in the blocks header. This
calculation takes a lot of resources and is difficult to find. However verifying the solution takes a trivial amount of
computing. This solution type (hard to find, easy to validate) provides one of the benefits of Bitcoin.

Mining serves two purposes:

- Miners can only receive honest income from creating blocks that follow all of Bitcoin's _consensus rules_. Thus miners
  are incentivized to only include valid transactions in their blocks.
- Mining (currently) creates new Bitcoins in each block. The amount of Bitcoin created per block is limited (called the
  _mining reward_) and will vary over time. In fact, the mining reward will grow smaller over time according to a fixed
  schedule

A successful miner will collect the reward (in the form of new Bitcoins plus the transaction fees). However, the reward
will only be collected if the miner has only included valid transactions, with Bitcoin's _consensus_ rules determining
which transactions are valid. This provides security for Bitcoin without the need for a central authority.

Mining is designed to be a decentralized lottery. Each miner can create their own lottery ticket by creating a
_candidate block_ that includes the new transactions they want to include, plus some additional data fields. The
candidate block will then have its data _hashed_, and if the data meets the minimum requirements, the block is accepted.

### Hash function

A hash function is a type of mathematical function which, given the same input, will produce the same output each time.
But it is designed so that the output value is impossible to predict given the input value. In fact, given two input
values that are nearly identical, their hash values will be radically different.

Ex:

Suppose we have two strings: "bat" and "cat". Using the SHA-256 algorithm (a hashing function), we see the hash value
of 'bat' is

```
2b1af0fe3b9b32d6a425f0d4f9b06eade50cff70aaa41824da025576d00bbf47
```

but the hash value of 'cat' is

```
175cc6f362b2f75acd08a373e000144fdb8d14a833d4b70fd743f16a7039103f
```

In this fashion, a hash value provides security as we cannot know ahead of time what the output of a hash function is
going to be. We emphasize that hash functions can take any value as input, but behind the scenes this input will get
translated into a numerical value. We see above that the output of a hash function is just an integer, given in
hexadecimal form.

### Proof of work

In order to mine a block, the hash value of a certain data field on the block must be less than a certain value, called
the _difficulty_ of the block. If a miner calculates the hash value of this data field and finds that its greater than
the difficulty, the miner will increase the value of a particular data field called the _nonce_, and retry the hash
function. In this fashion, the miner can continually try to find a new candidate hash value by increasing the nonce. The
speed at which a miner is able to calculate new hash values is called the miners _hash rate_.

Once an appropriate hash value has been found, the block is propagated across the network and other users can verify the
validity of the block by quickly performing the same hash function on the candidate. This makes the work necessary to
mine a valid block significant, but the verification of this block is trivial. The simple verification process is able
to probabalistically prove that work was done, so the data necessary to generate that proof (e.g., a valid block) is
called _proof of work (POW)_.

---

- UTXO
- Transaction
- Block
- Database
- Blockchain
- Mining
- Wallet
- Node
- API
- GUI
