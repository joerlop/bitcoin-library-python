from helper import little_endian_to_int, hash256, decode_base58
from ecc import PrivateKey
from tx import Tx, TxIn, TxOut
from script import p2pkh_script, Script
from io import BytesIO
from network import SimpleNode, GetHeadersMessage, HeadersMessage, FILTERED_BLOCK_DATA_TYPE, GetDataMessage, TX_DATA_TYPE, BLOCK_DATA_TYPE, BlockMessage
from block import Block, GENESIS_BLOCK, LOWEST_BITS
from helper import calculate_new_bits, decode_base58
from bloomfilter import BloomFilter
from merkleblock import MerkleBlock
import time

"""
How to generate an address:
"""
# passphrase = b'whatever'
# secret = little_endian_to_int(hash256(passphrase))
# pk = PrivateKey(secret)
# print(pk.point.address(testnet=True))

"""
How to create a transaction with 1 input:
"""
# output_address_1 = 'mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt'
# output_address_2 = 'mqdZtV16UixrjvkW5eQfpMiyspZYEoJSxV'
# # this tx will have only one input.
# prev_tx = bytes.fromhex('2307609ae4a3071a29c3ed5a5dc3646b8373a19d45e06653e7841d0b703aef63')
# # initially we don't know the scriptsig, so it's left blank.
# tx_in = TxIn(prev_tx, 0)
# # for the outputs, we need to generate the script_pubkeys for each one.
# # we start by decoding the address.
# decoded_address_1 = decode_base58(output_address_1)
# script_pubkey_1 = p2pkh_script(decoded_address_1)
# # we do the same for the second output.
# decoded_address_2 = decode_base58(output_address_2)
# script_pubkey_2 = p2pkh_script(decoded_address_2)
# # we specify the amounts for each output.
# amount_1 = int(0.00005 * 100000000)
# amount_2 = int(0.00003 * 100000000)
# # we create the outputs.
# tx_out_1 = TxOut(amount_1, script_pubkey_1)
# tx_out_2 = TxOut(amount_2, script_pubkey_2)
# # we create the outputs array
# tx_outputs = [tx_out_1, tx_out_2]
# # we create the transaction - remember that the scriptsig is still empty.
# tx = Tx(1, [tx_in], tx_outputs, 0, True)
# # now we create the scriptsig for the input we have.
# passphrase = b'whatever'
# secret = little_endian_to_int(hash256(passphrase))
# pk = PrivateKey(secret)
# print(tx.sign_input(0, pk))
# # finally we print the serialization of the tx.
# print(tx.serialize().hex())


"""
Creating a tx with multiple inputs.
"""
# output_address = 'mqdZtV16UixrjvkW5eQfpMiyspZYEoJSxV'
# amount = int(0.019 * 100000000)
# # Build the tx_inputs array
# prev_tx_1 = bytes.fromhex('404d102136c025954e111c5c80c6bcd47880c1f14e9a83621398f9efd492221f')
# prev_tx_2 = bytes.fromhex('57be406ddb6e61d1e3dc4177c0c75d844fb6f9c32aea4b49a99ebe2969f7bea7')
# prev_index_1 = 1
# prev_index_2 = 0
# tx_in_1 = TxIn(prev_tx_1, prev_index_1)
# tx_in_2 = TxIn(prev_tx_2, prev_index_2)
# tx_inputs = [tx_in_1, tx_in_2]
# # Build the tx_outputs array
# decoded_address = decode_base58(output_address)
# script_pubkey = p2pkh_script(decoded_address)
# tx_out = TxOut(amount, script_pubkey)
# tx_outputs = [tx_out]
# # Create the tx.
# transaction = Tx(1, tx_inputs, tx_outputs, 0, True)
# passphrase = b'whatever'
# secret = little_endian_to_int(hash256(passphrase))
# pk = PrivateKey(secret)
# print(transaction.sign_input(0, pk))
# print(transaction.sign_input(1, pk))
# print(transaction.serialize().hex())

"""
How to connect to a node and ask for some headers.
"""
# # We are going to ask for the headers starting from genesis block.
# previous = Block.parse(BytesIO(GENESIS_BLOCK))
# first_epoch_timestamp = previous.timestamp
# # We start with the expected difficulty at the genesis block.
# expected_bits = LOWEST_BITS
# count = 1
# # Create the node and make the handshake.
# node = SimpleNode('mainnet.programmingbitcoin.com', testnet=False)
# node.handshake()
# # For example purposes we're going to do the exercise for 20 headers.
# for _ in range(19):
#     # Create the getheaders message. We're asking for the headers from the genesis block
#     # onwards.
#     getheaders = GetHeadersMessage(start_block=previous.hash())
#     # Send the message
#     node.send(getheaders)
#     # Wait for the response
#     headers_message = node.wait_for(HeadersMessage)
#     # Loop through the headers received to verify the info. received.
#     for header in headers_message.blocks:
#         # Check that the PoW is valid.
#         if not header.check_pow():
#             raise RuntimeError(f"Bad PoW at block {count}")
#         # Check that the current block is after the previous one.
#         if header.prev_block != previous.hash():
#             raise RuntimeError(f"Discontinuous block at {count}")
#         # If 2016 blocks have passed (1 epoch has passed) then we need to re-calculate the difficulty.
#         if count % 2016 == 0:
#             time_diff = previous.timestamp - first_epoch_timestamp
#             # We calculate the new difficulty.
#             expected_bits = calculate_new_bits(previous.bits, time_diff)
#             print("expected bits", expected_bits.hex())
#             # We store the timestamp of the first block of the new epoch to be able to
#             # re-calculate bits when this epoch ends.
#             first_epoch_timestamp = header.timestamp
#         # Check that the difficulty is what we expect based on prev. calculation.
#         if header.bits != expected_bits:
#             raise RuntimeError(f"Bad bits at block {count}")
#         # Advance to the next block.
#         previous = header
#         # Increase block height.
#         count += 1

"""
Getting Transactions of Interest from a full node - page 218.
"""
# fee = 50000
# # Last block id, used to request blocks generated from that one onwards.
# last_block_hex = '0000000000000304934bf03adfd0f1a93be2971a711aa87e4a8453d6b03653c3'
# # My address.
# address = 'mqdZtV16UixrjvkW5eQfpMiyspZYEoJSxV'
# # Takes an address and returns the hash it came from.
# h160 = decode_base58(address)
# node = SimpleNode('testnet.programmingbitcoin.com',
#                   testnet=True, logging=False)
# # We are creating a bloom filter that's 30 bytes and uses 5 hash functions and 90210 as its tweak.
# bf = BloomFilter(size=30, function_count=5, tweak=90210)
# # We filter for our address.
# bf.add(h160)
# # Connect to the node.
# node.handshake()
# # We send the filterload command from the bloom filter we made.
# node.send(bf.filterload())
# start_block = bytes.fromhex(last_block_hex)
# # We ask for the headers after start_block. The full node already has our bloom filter.
# getheaders = GetHeadersMessage(start_block=start_block)
# node.send(getheaders)
# headers = node.wait_for(HeadersMessage)
# # We create a getdata message for merkle blocks that may have transactions of interest.
# getdata = GetDataMessage()
# for b in headers.blocks:
#     print("Here 1")
#     if not b.check_pow():
#         raise RuntimeError("Invalid proof of work.")
#     # We add the data type (in this case merkle block) and the block hash to the data we want to request.
#     # We are requesting a merkle block that has transactions of interest according to our bloom filter.
#     getdata.add_data(FILTERED_BLOCK_DATA_TYPE, b.hash())
# # The getdata message asks for 2.000 merkle blocks after the block defined by last_block_hex.
# print('Here 2')
# node.send(getdata)
# prev_tx, prev_index, prev_amount = None, None, None
# while prev_tx is None:
#     # We wait for the merkleblock command, which proves inclusion of a transaction of interest and the
#     # tx command, which gives us the transaction of interest.
#     message = node.wait_for(MerkleBlock, Tx)
#     # If it's a merkle block, we validate it.
#     if message.command == b'merkleblock':
#         if not message.is_valid():
#             raise RuntimeError('Invalid merkle proof.')
#     # Else, if it's a transaction, we do the following.
#     else:
#         for i, tx_out in enumerate(message.tx_outputs):
#             # We're looking for the output that points to our address.
#             if tx_out.script_pubkey.address(testnet=True) == address:
#                 # We found our utxo, set prev_tx, prev_index and prev_amount.
#                 prev_tx = message.hash()
#                 prev_index = i
#                 prev_amount = tx_out.amount
#                 print("uses vi", tx_out.script_pubkey.serialize())
#                 print(f"Found: {message.id()}:{i}")
#                 break
#         # We create the TxIn.
#         tx_in = TxIn(prev_tx, prev_index)
#         inputs = [tx_in]
#         # Calculate the output amount.
#         output_amount = prev_amount - fee
#         # We create the output.
#         script_pubkey = p2pkh_script(h160)
#         output = TxOut(output_amount, script_pubkey)
#         outputs = [output]
#         # Create the transaction.
#         transaction = Tx(1, inputs, outputs, 0, testnet=True)
#         # Sign the transaction.
#         passphrase = b'jonathanerlichloquesea123geryjj.erlich155@gmail.com'
#         secret = little_endian_to_int(hash256(passphrase))
#         pk = PrivateKey(secret=secret)
#         print(transaction.sign_input(0, pk))
#         # Send the transaction to the network.
#         node.send(transaction)
#         # Wait a sec for the message to go through.
#         time.sleep(30)
#         # Now ask for this transaction from the full node.
#         getdata = GetDataMessage()
#         getdata.add_data(TX_DATA_TYPE, transaction.hash())
#         node.send(getdata)
#         # Wait for a Tx response
#         received_tx = node.wait_for(Tx)
#         print("received", received_tx)
#         # If the received tx has the same id as our tx, we are done!
#         print(received_tx.id(), transaction.id())
#         if received_tx.id() == transaction.id():
#             print('Yeah!')

node = SimpleNode('54.188.160.243')
node.handshake()
getdata = GetDataMessage()
getdata.add_data(
    BLOCK_DATA_TYPE, bytes.fromhex('00000000000000000012c29be7f63728fd241f373bb85fd3e61507dc3d4b7c6b'))
node.send(getdata)
received_block = node.wait_for(BlockMessage)
parsed_block_message = BlockMessage.parse(received_block)
print(parsed_block_message.txn_count)
