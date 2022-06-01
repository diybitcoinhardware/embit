# Transactions

This module defines raw Bitcoin transactions as they appear on Bitcoin Blockchain. For the majority of wallet-specific operations it's much more convenient to use [`PSBT`](./psbt.md) that include extra metadata required for signing and parsing.

The module also includes [`SIGHASH`](#SIGHASH) constants that define what parts of the transaction are covered by the signature when calculating hash for signing.

Defined classes: [`Transaction`](#Transaction), [`TransactionInput`](#TransactionInput), [`TransactionOutput`](#TransactionOutput).

All `Transaction*` classes use hex encoding as string representation. They can also be parsed from byte array or byte stream. Read the [basics](README.md#basics) to learn how it works.

**Examples:**

Parsing transaction and printing destination addresses:

```py
from embit.transaction import Transaction
from embit.networks import NETWORKS

# using regtest for address display
net = NETWORKS["regtest"]

hextx = "02000000000101a71718b08f7b9a24f6a6251fb0e0aae35376ec0df2a1e2894955f174ac5137820000000000feffffff0271dce316010000001600145af0d1c7f2134d6ffe5fc3079700091e91ee27c440420f00000000001600148464ca4202f52e0d1411dcbf12e97e1709c6379c0247304402207d715b12cd8a92fc25eb06ba5df5cb1345179bddfb31106525186599871f485e022032a523c336ae120d196945855d6ed1de1c8e09d35fc9e0d93e3893fd0493c7d70121024fd5073ee4a67a03878592b339bd01c47f86aa6b4460f28de623d4992339b71200000000"

# parsing from hex string:
tx = Transaction.from_string(hextx)
# or using parse method on bytes:
raw = bytes.fromhex(hextx)
tx = Transaction.parse(raw)

if tx.is_segwit:
    print("Segwit transaction")
else:
    print("Legacy transaction")
print("txid: %s" % tx.txid().hex())

print("%d inputs" % len(tx.vin))
print("%d outputs" % len(tx.vout))
for out in tx.vout:
    print("%d sats to %s" % (out.value, out.script_pubkey.address(net)))
# >> 4678999153 sats to bcrt1qttcdr3ljzdxklljlcvrewqqfr6g7uf7y53mqvf
# >> 1000000 sats to bcrt1qs3jv5ssz75hq69q3mjl396t7zuyuvduu4vl66p
```

Manually creating a transaction

```py
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.script import p2wpkh, p2sh, Script
from embit.ec import PrivateKey

pk = PrivateKey.from_wif("L4WK9uFXiVRUopgcs41DmThuJdrmnNPX43E9TNhyjsb6Vh2eJcuB")

# inputs
vin = [
    TransactionInput(
        txid=bytes.fromhex("823751ac74f1554989e2a1f20dec7653e3aae0b01f25a6f6249a7b8fb01817a7"),
        vout=0,
    )
]
# outputs
vout = [
    # output to nested segwit
    TransactionOutput(1000_000, p2sh(p2wpkh(pk))),
    # output from address
    TransactionOutput(123_456, Script.from_address("bcrt1qttcdr3ljzdxklljlcvrewqqfr6g7uf7y53mqvf"))
]
tx = Transaction(vin=vin, vout=vout)

print(tx) # will print hex unsigned transaction we just constructed
```

For signing examples check [Transaction Methods](#Methods).

# `SIGHASH`

`SIGHASH` is a collection of constants used for signing. Depending on the sighash different parts of the transactions are covered by the signature. The default sighash used in the majority of transactions is `SIGHASH.ALL` that covers all inputs and outputs of the transactions.

Available sighashes:

- `SIGHASH.DEFAULT = 0x00` - a sighash for taproot signatures that covers everything in the transaction and should be omitted during signature serialization. Use it ONLY when creating Schnorr signatures.
- `SIGHASH.ALL = 0x01` - a default sighash for all types of transactions, covers everything in the transaction.
- `SIGHASH.NONE = 0x02` - very dangerous sighash type, only covers inputs, so outputs of the transaction can be replaced with any other outputs without invalidating the signature. If all inputs use this sighash the miners can steal all the funds by replacing your outputs with miner's outputs.
- `SIGHASH.SINGLE = 0x03` - this sighash covers all inputs and only one output that is at the same position as the input. So if input #1 uses this sighash it only requires that output #1 doesn't change, all other outputs can be replaced.
- `SIGHASH.ANYONECANPAY = 0x80` - a flag that can be combined with other sighash types and allows adding other inputs to the transaction. For example you can combine `SIGHASH.SINGLE | SIGHASH.ANYONECANPAY` to create a signature that will allow adding other inputs and changing other outputs and only requires that your input and corresponding output remain the same.

# `Transaction`

## Constructor

You can create a transaction manually, all arguments are optional, but with empty `vin` and `vout` raw transaction doesn't make sense. You can mutate `tx.vin` and `tx.vout` after creation though.

```py
Transaction(version=2, vin=[], vout=[], locktime=0)
```

**Arguments:**

- `version = 2` - transaction version. Version 2 adds support for relative timelocks as defined in [BIP-68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)
- `vin` - transaction inputs, list of `TransactionInput` class instances.
- `vout` - transaction outputs, list of `TransactionOutput` class instances.
- `locktime = 0` - minimal block height when transaction can be mined, a good practice to set it to the current block height.

## Serialization

Parsing:

- `Transaction.parse(bytes)` - parses transaction from byte array, returns an instance of the `Transaction`
- `Transaction.read_from(stream)` - parses transaction from byte stream like file or `BytesIO` object, returns an instance of the `Transaction`
- `Transaction.read_vout(stream, idx)` - a memory-efficient parsing of the transaction if you only need a particular `TransactionOutput`. `idx` is the index of the output you are interested in. Returns a tuple: instance of `TransactionOutput` that was found in the transaction at index `idx`, tx hash without witness (`32` bytes, reverse of the txid).

## Attributes

You can change them at any time.

!> Note that signatures commit to version and locktime, so changing version number or locktime in a signed transaction will make the transaction invalid.

- `version` - transaction version
- `vin` - list of inputs
- `vout` - list of outputs
- `locktime` - minimal block height when transaction can be mined

## Properties

These properties only implement getter, so you can't change them.

- `is_segwit` - returns `True` if any input of the transaction contains non-empty witness. Note that unsigned segwit transaction will return `False` until you fill in witness data.

## Methods

- `txid()` - returns txid of the transaction (`32` bytes), reversed of the `tx.hash()`
- `hash()` - returns a hash of the transaction without witness using double-sha256
- [`sighash_legacy(input_index, script_pubkey, sighash=SIGHASH.ALL)`](#sighash_legacy) - returns a `32` byte hash to sign for legacy input
- [`sighash_segwit(input_index, script_pubkey, value, sighash=SIGHASH.ALL)`](#sighash_segwit) - returns a `32` byte hash to sign for segwit input
- [`sighash_taproot(input_index, script_pubkeys, values, sighash=SIGHASH.DEFAULT)`](#sighash_taproot) - returns a `32` byte hash to sign for taproot input
- `clear_cache()` - removes segwit signing cache

### `sighash_legacy()`

Legacy sighash only needs information about the scriptpubkey of the output it is spending.

**Arguments**

- `input_index: int` - index of the input that you want to sign
- `script_pubkey: script.Script` - script pubkey of the output this input is spending
- `sighash = SIGHASH.ALL` - what sighash to use, for more info see [`SIGHASH`](#SIGHASH) section

**Returns**

a `32` byte hash to sign

**Example**

This example assumes a single-address legacy wallet with p2pkh script type.

```python
from embit.transaction import Transaction, SIGHASH
from embit.ec import PrivateKey
from embit.script import p2pkh, Script

# private key that we will use to sign input
pk = ec.PrivateKey.from_string("L4WK9uFXiVRUopgcs41DmThuJdrmnNPX43E9TNhyjsb6Vh2eJcuB")

# read legacy transaction we want to sign from a file
with open("legacy.tx", "rb") as f
    tx = Transaction.read_from(f)

# calculate hashes for all inputs, sign them with our private key and put to scriptsig
# a valid scriptsig should contain a signature with sighash byte and a pubkey
for i, inp in enumerate(tx.vin):
    # get hash to sign using p2pkh script type
    msg = tx.sighash_legacy(i, p2pkh(pk))
    sig = pk.sign(msg)
    # create a valid legacy scriptsig
    sc = Script()
    # append signature sighash
    sc.push(sig.serialize() + bytes([SIGHASH.ALL]))
    sc.push(pk.sec())
    # set scriptsig
    inp.script_sig = sc

# write signed transaction to file
with open("legacy_signed.tx", "wb") as f:
    tx.write_to(f)
```

### `sighash_segwit()`

Segwit sighash needs information about the scriptpubkey and the amount of the output it is spending.

**Arguments**

- `input_index: int` - index of the input that you want to sign
- `script_pubkey: script.Script` - script pubkey of the output this input is spending
- `value: int` - value of the output this input is spending in satoshi
- `sighash = SIGHASH.ALL` - what sighash to use, for more info see [`SIGHASH`](#SIGHASH) section

**Returns**

a `32` byte hash to sign

**Example**

This example assumes a single-address native segwit wallet with p2wpkh script type.

Also assuming that the transaction has one input that is spending `1000000` sats.

!> Note that even though we are signing `p2wpkh` input we still use `p2pkh` script type!

```python
from embit.transaction import Transaction, SIGHASH
from embit.ec import PrivateKey
from embit.script import p2pkh, Witness

# private key that we will use to sign input
pk = ec.PrivateKey.from_string("L4WK9uFXiVRUopgcs41DmThuJdrmnNPX43E9TNhyjsb6Vh2eJcuB")

# read legacy transaction we want to sign from a file
with open("segwit.tx", "rb") as f
    tx = Transaction.read_from(f)

# get hash to sign using p2pkh script type
# p2wpkh is a special case and it uses p2pkh in the sighash!
msg = tx.sighash_segwit(0, p2pkh(pk), 1000_000)
sig = pk.sign(msg)

# create a witness with two items - signature with sighash flag, and pubkey
w = Witness([
    sig.serialize() + bytes([SIGHASH.ALL]),
    pk.sec(),
])
# set witness
tx.vin[0].witness = sc

# if you are using nested segwit you also need to set scriptsig to your witness script:
# tx.vin[0].script_sig = p2wpkh(pk)

# write signed transaction to file
with open("segwit_signed.tx", "wb") as f:
    tx.write_to(f)
```

### `sighash_taproot()`

Taproot sighash needs information about ALL scriptpubkeys and amounts of the outputs this transaction is spending.

**Arguments**

- `input_index: int` - index of the input that you want to sign
- `script_pubkeys: list(script.Script)` - list of all script pubkeys of the outputs this transaction is spending
- `values: list(int)` - list of all values of the outputs this transaction is spending in satoshi
- `sighash = SIGHASH.DEFAULT` - what sighash to use, for more info see [`SIGHASH`](#SIGHASH) section

**Returns**

a `32` byte hash to sign using `schnorr_sign` function.

**Example**

This example assumes a single-address taproot wallet with key-only p2tr script type.

Also assuming that the transaction has one input that is spending `1000000` sats.

```python
from embit.transaction import Transaction, SIGHASH
from embit.ec import PrivateKey
from embit.script import p2tr, Witness

# private key that we will use to sign input
pk = ec.PrivateKey.from_string("L4WK9uFXiVRUopgcs41DmThuJdrmnNPX43E9TNhyjsb6Vh2eJcuB")
# tweaked taproot key with empty tapscript
tweaked = pk.taproot_tweak()

# read legacy transaction we want to sign from a file
with open("taproot.tx", "rb") as f
    tx = Transaction.read_from(f)

msg = tx.sighash_taproot(0, [p2tr(pk)], [1000_000])
# use tweaked private key to sign the message
sig = tweaked.schnorr_sign(msg)

# create a witness the signature
# we don't need to add sighash because we use SIGHASH.DEFAULT
# and we don't need pubkey because p2tr already has taproot
w = Witness([
    sig.serialize()
])
# set witness
tx.vin[0].witness = sc

# write signed transaction to file
with open("taproot_signed.tx", "wb") as f:
    tx.write_to(f)
```

# `TransactionInput`

## Constructor

```py
TransactionInput(txid, vout, script_sig=None, sequence=0xFFFFFFFF, witness=None)
```

**Arguments:**

- `txid: bytes` - `32` bytes, txid of the transaction this input is spending.
- `vout: int` - index of the output this input is spending.
- `script_sig: script.Script` - input script sig, if `None` (default) - it will create an empty script sig.
- `sequence = 0xFFFFFFFF` - sequence number. For Replace-by-fee set it to lower value for example `0xfffffffd`. Also used by timelocked transaction, see [BIP-68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki).
- `witness: script.Witness` - input witness, if `None` (default) - set to empty witness.

Serialization and parsing is done as usual - `from_string(hex)`, `to_string()`, `parse(bytes)`, `serialize()`, `read_from(stream)`, `write_to(stream)`.

## Attributes

You can change them at any time.

- `txid: bytes` - `32` bytes, txid of the transaction this input is spending.
- `vout: int` - index of the output this input is spending.
- `script_sig: script.Script` - input script sig, if `None` (default) - it will create an empty script sig.
- `sequence: int` - sequence number. Used for Replace-by-fee signalling and in timelocked transaction, see [BIP-68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki).
- `witness: script.Witness` - input witness. Legacy and unsigned inputs have empty witness.

## Properties

These properties only implement getter, so you can't change them.

- `is_segwit` - returns `True` if the input has non-empty witness. Note that unsigned segwit transaction input will return `False` until you fill in witness data.


# `TransactionOutput`

## Constructor

```py
TransactionOutput(value, script_pubkey)
```

**Arguments:**

- `value: int` - value of the output in satoshi
- `script_pubkey: script.Script` - output script defining spending conditions.

Serialization and parsing is done as usual - `from_string(hex)`, `to_string()`, `parse(bytes)`, `serialize()`, `read_from(stream)`, `write_to(stream)`.

## Attributes

You can change them at any time.

- `value: int` - value of the output in satoshi
- `script_pubkey: script.Script` - output script defining spending conditions.
