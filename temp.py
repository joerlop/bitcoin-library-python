from helper import little_endian_to_int, hash256, decode_base58
from ecc import PrivateKey
from tx import Tx, TxIn, TxOut
from script import p2pkh_script

list_a = [1, 2, 3]
b = list_a
b.append(4)
print(list_a)


# How to generate an address:
passphrase = b'whatever'
secret = little_endian_to_int(hash256(passphrase))
pk = PrivateKey(secret)
print(pk.point.address(testnet=True))

"""
How to create a transaction:

output_address_1 = 'mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt'
output_address_2 = 'mqdZtV16UixrjvkW5eQfpMiyspZYEoJSxV'
# this tx will have only one input.
prev_tx = bytes.fromhex('2307609ae4a3071a29c3ed5a5dc3646b8373a19d45e06653e7841d0b703aef63')
# initially we don't know the scriptsig, so it's left blank.
tx_in = TxIn(prev_tx, 0)
# for the outputs, we need to generate the script_pubkeys for each one.
# we start by decoding the address.
decoded_address_1 = decode_base58(output_address_1)
script_pubkey_1 = p2pkh_script(decoded_address_1)
# we do the same for the second output.
decoded_address_2 = decode_base58(output_address_2)
script_pubkey_2 = p2pkh_script(decoded_address_2)
# we specify the amounts for each output.
amount_1 = int(0.00005 * 100000000)
amount_2 = int(0.00003 * 100000000)
# we create the outputs.
tx_out_1 = TxOut(amount_1, script_pubkey_1)
tx_out_2 = TxOut(amount_2, script_pubkey_2)
# we create the outputs array
tx_outputs = [tx_out_1, tx_out_2]
# we create the transaction - remember that the scriptsig is still empty.
tx = Tx(1, [tx_in], tx_outputs, 0, True)
# now we create the scriptsig for the input we have.
passphrase = b'whatever'
secret = little_endian_to_int(hash256(passphrase))
pk = PrivateKey(secret)
print(tx.sign_input(0, pk))
# finally we print the serialization of the tx.
print(tx.serialize().hex())
"""

output_address = 'mqdZtV16UixrjvkW5eQfpMiyspZYEoJSxV'
amount = int(0.019 * 100000000)
# Build the tx_inputs array
prev_tx_1 = bytes.fromhex('404d102136c025954e111c5c80c6bcd47880c1f14e9a83621398f9efd492221f')
prev_tx_2 = bytes.fromhex('57be406ddb6e61d1e3dc4177c0c75d844fb6f9c32aea4b49a99ebe2969f7bea7')
prev_index_1 = 1
prev_index_2 = 0
tx_in_1 = TxIn(prev_tx_1, prev_index_1)
tx_in_2 = TxIn(prev_tx_2, prev_index_2)
tx_inputs = [tx_in_1, tx_in_2]
# Build the tx_outputs array
decoded_address = decode_base58(output_address)
script_pubkey = p2pkh_script(decoded_address)
tx_out = TxOut(amount, script_pubkey)
tx_outputs = [tx_out]
# Create the tx.
transaction = Tx(1, tx_inputs, tx_outputs, 0, True)
passphrase = b'jonathanerlichloquesea123geryjj.erlich155@gmail.com'
secret = little_endian_to_int(hash256(passphrase))
pk = PrivateKey(secret)
print(transaction.sign_input(0, pk))
print(transaction.sign_input(1, pk))
print(transaction.serialize().hex())