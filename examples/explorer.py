"""
This example shows how to fetch utxos from mempool.space
and build PSBT transaction for signing.
Requires `requests` module (`pip3 install requests`)
"""
import requests
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.ec import PublicKey
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit import script, bip32, finalizer

# link to the explorer API (esplora or mempool.space)
# API = "https://mempool.space/testnet/api"
API = "https://blockstream.info/testnet/api"
# we will generate testnet addresses
network = NETWORKS['test']

# after GAP_LIMIT addresses without any transactions
# we will stop querying
GAP_LIMIT = 20

# You can either provide a combined descriptor with {0,1} branches,
# or iterate over descriptors (recv and change descriptors)
# Seed: session spawn august alpha trap spider thing swim finish motor neutral across
# Here we use combined descriptor (Bitcoin Core doesn't support that though)
# Here we use vpub, but it's the same as this tpub: tpubDC93uE1NfJMF37r4EL87CHBUEtScESkBNo6Ym3DYCqKdmdtsL8ZqK39aHfaESmSn9ZohH1vzQjDchsuAXRDGXuowXZSXj3fY7PJ9yBAhWst
# native segwit
desc = Descriptor.from_string("wpkh([911cf0a8/84h/1h/0h]vpub5Y6tmeqrefJq4jGy7RZmaBf6Zq44MpG7zwToqhNd6uoyv9bhkbPcvUAU1DaGvTBhYP3BAVDzxJgUF8BRhAY13zzSjHJNshNKyyaTS4F5hnr/<0;1>/*)")
# desc = Descriptor.from_string("sh(wpkh([911cf0a8/49h/1h/0h]upub5EQTr2VnHFmuJc3btwZcETwhDCzvXF8hqK2AS57ZN5fzxa6LGMtoAKuyc12F7rBpKUyocqfc8kCTzHdTmJh1i6672pu3JzobNHu39oW9Btd/<0;1>/*))")
# desc = Descriptor.from_string("pkh([911cf0a8/44h/1h/0h]tpubDD958ijpckkrCrWzY4jTwuCafkK1gijyJVbc96EViYN29Ac7K9eUyzSTrwQuoGUvwpzQMHh2fT8JGtnYHjTFWRXJAEs48s1nZSpG92hC1yb/<0;1>/*)")

# where to send
DESTINATION = "2N6AUY73q79SPzGvgPhR9biETV7DZffTQz9"
# amount to send in sat
AMOUNT = 10_000
# if change is less than DUST_LIMIT we don't create UTXO for it
DUST_LIMIT = 100


# to speed up connection to the API
s = requests.session()

# last known block height, can be used as locktime in the transaction
block = int(s.get(f"{API}/blocks/tip/height").text)

# all utxos will be stored here
# note: makes sense to cache it for this wallet and request only new ones
utxos = []

for branch in [0]: # range(len(desc.num_branches)):
    # change address is first unused address from last branch
    # that is not followed by a used address
    change_output = None

    # checking receiving addresses
    unused_counter = 0
    i = 0 # index of the address we are checking

    while unused_counter < GAP_LIMIT:
        # descriptor for address i
        d = desc.derive(i, branch_index=branch)
        addr = d.address(network)
        # sometimes request to API can fail, makes sense to add retry counter or something
        res = s.get(f"{API}/address/{addr}").json()
        # check if there are any transactions here
        used = (res.get("chain_stats",{}).get("funded_txo_count", 0) + 
                res.get("mempool_stats",{}).get("funded_txo_count", 0)) > 0
        # no incoming txs on this address - empty
        if not used:
            if change_output is None:
                # store current unused address (descriptor) as change_output
                change_output = d
            print(addr,"unused")
            unused_counter += 1
            i += 1
            continue

        # if used - change address should be after this one
        change_output = None

        # if used - check the balance:
        balance = (res.get("chain_stats",{}).get("funded_txo_sum", 0) +
                   res.get("mempool_stats",{}).get("funded_txo_sum", 0) -
                   res.get("chain_stats",{}).get("spent_txo_sum", 0) -
                   res.get("mempool_stats",{}).get("spent_txo_sum", 0))
        # positive balance - we have utxos there
        if balance > 0:
            print(addr, "utxos!", balance)
            utxoarr = s.get(f"{API}/address/{addr}/utxo").json()

            # derivation information for utxos
            bip32_derivations = {}
            for k in d.keys:
                bip32_derivations[PublicKey.parse(k.sec())] = DerivationPath(k.origin.fingerprint, k.origin.derivation)

            # for multisig this is important,
            # for native segwit single sig it's None
            ws = d.witness_script()
            rs = d.redeem_script()
            script_pubkey = d.script_pubkey()

            utxos += [{
                "txid": utxo["txid"],
                "vout": utxo["vout"],
                "value": utxo["value"],
                "witness_script": ws,
                "redeem_script": rs,
                "bip32_derivations": bip32_derivations,
                "witness_utxo": TransactionOutput(utxo["value"], script_pubkey) if d.is_segwit else None,
            } for utxo in utxoarr]
        else:
            print(addr, "empty")
        i += 1

# get the fee rate, we target for inclusion in 6 blocks:
fee_rate = s.get(f"{API}/fee-estimates").json()["6"]
print("Fee rate", fee_rate)

# estimate the transaction size - we'll have 2 outputs and some unknown yet number of inputs.
# so we need to calculate the size of the transaction without any inputs and weight per input.
# version, locktime, num_inp, num_out
no_input_size = (4+4+2)
# marker + segwit flag
if desc.is_segwit:
    no_input_size += 2

# adding outputs
no_input_size += (len(change_output.script_pubkey().serialize()) + 8)
no_input_size += (len(script.address_to_scriptpubkey(DESTINATION).serialize()) + 8)

per_input_size = (32 + 4 + 4) # txid + vout + sequence

# we can re-use change_output descriptor for weight calculations
# as all our inputs have the same script structure

# check if we have redeem script and add it to the size
if change_output.redeem_script():
    per_input_size += len(change_output.redeem_script().serialize())
else:
    per_input_size += 1 # empty redeem script still takes 1 byte

if change_output.is_pkh:
    # script_sig length for single sig
    sigs_size = 34 + 74 # pubkey + signature
elif change_output.is_basic_multisig:
    # script_sig length for multisig
    sigs_size = 34 * len(desc.keys) # pubkeys
    sigs_size += 74 * change_output.miniscript.args[0] # threshold
    sigs_size += len((change_output.witness_script() or change_output.redeem_script()).serialize()) # script

if desc.is_segwit:
    per_input_size += sigs_size/4 # witness is 4x cheaper
else:
    per_input_size += sigs_size

# Now when we have all utxos and size estimates
# we can construct a transaction

# Very stupid coin selection:
# we just go through utxos and add them until we have enough for destination + fee

spending_amount = 0
fee = fee_rate*no_input_size
inputs = []

for utxo in utxos:
    # get full prev tx if we are using legacy (or Trezor)
    if not d.is_segwit:
        utxo["non_witness_utxo"]= Transaction.from_string(s.get(f"{API}/tx/{utxo['txid']}/hex").text)
    inputs.append(utxo)
    spending_amount += utxo["value"]
    fee += per_input_size*fee_rate
    if spending_amount >= AMOUNT + fee:
        break

if spending_amount < AMOUNT + fee:
    raise RuntimeError("Not enough funds")
# round fee to satoshis
fee = int(fee)+1

vin = [TransactionInput(bytes.fromhex(inp["txid"]), inp["vout"]) for inp in inputs]
vout = [
    TransactionOutput(AMOUNT, script.address_to_scriptpubkey(DESTINATION))
]
# add change output
if spending_amount-fee-AMOUNT > DUST_LIMIT:
    vout.append(
        TransactionOutput(spending_amount-fee-AMOUNT, change_output.script_pubkey()),
    )

tx = Transaction(vin=vin, vout=vout)
# now create PSBT from this transaction
psbt = PSBT(tx)
# fill missing information for all inputs and change output
for i, inp in enumerate(inputs):
    psbt.inputs[i].bip32_derivations = inp["bip32_derivations"]
    psbt.inputs[i].witness_script = inp["witness_script"]
    psbt.inputs[i].redeem_script = inp["redeem_script"]
    psbt.inputs[i].witness_utxo = inp.get("witness_utxo", None)
    psbt.inputs[i].non_witness_utxo = inp.get("non_witness_utxo", None)

if len(psbt.outputs) > 1:
    # derivation information for utxos
    bip32_derivations = {}
    for k in change_output.keys:
        bip32_derivations[PublicKey.parse(k.sec())] = DerivationPath(k.origin.fingerprint, k.origin.derivation)

    psbt.outputs[1].witness_script = change_output.witness_script()
    psbt.outputs[1].redeem_script = change_output.redeem_script()
    psbt.outputs[1].bip32_derivations = bip32_derivations

# sort inputs lexagraphically
sorted_inputs = sorted(zip(psbt.tx.vin, psbt.inputs), key=lambda z: z[0].txid)
psbt.tx.vin = [z[0] for z in sorted_inputs]
psbt.inputs = [z[1] for z in sorted_inputs]

# sort outputs lexagraphically
sorted_outputs = sorted(zip(psbt.tx.vout, psbt.outputs), key=lambda z: z[0].script_pubkey.data)
psbt.tx.vout = [z[0] for z in sorted_outputs]
psbt.outputs = [z[1] for z in sorted_outputs]

# check if it's multisig and if so - fill xpubs field
if len(desc.keys) > 1:
    for k in desc.keys:
        psbt.xpubs[k.key] = DerivationPath(k.origin.fingerprint, k.origin.derivation)

# psbt is ready for signing:
print(psbt.to_string())

# sign the transaction with your root key (or pass it to the hardware wallet)
# Seed: session spawn august alpha trap spider thing swim finish motor neutral across
root = bip32.HDKey.from_string("tprv8ZgxMBicQKsPeV6hdhzTDoALgUoNsNPqYq4aJPrazkDxmGWV2TGAVtKg7U9CKeKztcAzJv91k1vGB9VecKkPQ5osnViqjvtUm9nCuJfqimg")
psbt.sign_with(root)

print(psbt)
# finalize the transaction
signedtx = finalizer.finalize_psbt(psbt)
if not signedtx:
    raise RuntimeError("Failed to finalize transaction")

print("Signed transaction:")
print(signedtx.to_string())

# Uncomment to broadcast the transaction:
# res = s.post(f"{API}/tx", data=signedtx.serialize().hex())
# print(res.text)
