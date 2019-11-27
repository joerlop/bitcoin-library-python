from io import BytesIO
from unittest import TestCase
from script import Script, p2pkh_script

import json
import requests

from helper import (
    hash256,
    hash160,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    encode_varint,
    SIGHASH_ALL
)

from ecc import (PrivateKey)

# class to be able to access the UTXO set end look up individual transactions and be able to get input amounts.


class TxFetcher:

    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'

    # fecthes a transaction from the UTXO set.
    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(
                    'unexpected response: {}'.format(response.text))
            tx = Tx.parse(BytesIO(raw), testnet=testnet)
            # make sure the tx we got matches to the hash we requested
            if tx.id() != tx_id:
                raise RuntimeError(
                    'server lied: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            cls.cache[k] = Tx.parse(BytesIO(bytes.fromhex(raw_hex)))

# class that represents a Bitcoin transaction - page 88


class Tx:

    # To be able to handle transaction messages.
    command = b'tx'

    def __init__(self, version, tx_inputs, tx_outputs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_inputs = tx_inputs
        self.tx_outputs = tx_outputs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_inputs = ''
        for tx_input in self.tx_inputs:
            tx_inputs += tx_input.__repr__() + '\n'
        tx_outputs = ''
        for tx_output in self.tx_outputs:
            tx_outputs += tx_output.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ninputs:\n{}\noutputs:\n{}locktime: {}'.format(self.id(), self.version, tx_inputs, tx_outputs, self.locktime)

    # hexadecimal value of transaction hash
    def id(self):
        return self.hash().hex()

    # binary hash of the legacy serialization in little endian.
    def hash(self):
        return hash256(self.serialize())[::-1]

    # method that defines which parse method to use: segwit or legacy - page 231.
    @classmethod
    def parse(cls, s, testnet=False):
        s.read(4)
        # if, after version (which is first 4 bytes), we have a 0 byte, it means the transaction is segwit.
        if s.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        # We put the stream back to the position where it was before examining the first 5 bytes.
        s.seek(-5, 1)
        return parse_method(s, testnet=testnet)

    # receives a stream of bytes and returns a Tx object
    @classmethod
    def parse_legacy(cls, stream, testnet=False):
        # s.read(n) will return n bytes
        # version has 4 bytes, little-endian, interpret as int
        version = little_endian_to_int(stream.read(4))
        # number of inputs
        num_inputs = read_varint(stream)
        # initialize inputs array
        inputs = []
        # loop num_inputs times to get all inputs from the stream.
        for _ in range(num_inputs):
            # appends a TxIn object to inputs array
            inputs.append(TxIn.parse(stream))
        # get the number of outputs
        num_outputs = read_varint(stream)
        outputs = []
        # loop num_outputs times to get all outputs from the stream.
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))
        # locktime is 4 bytes, little endian
        locktime = little_endian_to_int(stream.read(4))
        # return a Tx object
        return cls(version, inputs, outputs, locktime, testnet)

    # Parser when tx is segwit.
    @classmethod
    def parse_segwit(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))
        # Marker and flag are 2 bytes after version - page 232.
        marker_and_flag = s.read(2)
        # For transaction to be segwit, marker and flag need to be b'\x00\x01'.
        if marker_and_flag != b'\x00\x01':
            raise RuntimeError(
                'Not a segwit transaction {}'.format(marker_and_flag))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # This field corresponds to the witness, which contains items for each input.
        # The witness field in p2wpkh has the signature and pubkey as its 2 elements - this for each input.
        # Those 2 fields are used by upgraded nodes to validate the inputs.
        for tx_in in inputs:
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    # We add each element to the items list.
                    items.append(s.read(item_len))
            # This TxIn witness is the list of items.
            tx_in.witness = items
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime,
                   testnet=testnet, segwit=True)

    # Decides whether to serialize using serialize_legacy or serialize_segwit.
    def serialize(self):
        if self.segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()

    # returns the bytes serialization of the transaction
    def serialize_legacy(self):
        # version is 4 bytes, LE
        version = int_to_little_endian(self.version, 4)
        # number of inputs is a varint
        num_inputs = encode_varint(len(self.tx_inputs))
        # initialize inputs bytes concatenation
        inputs = b''
        for tx_input in self.tx_inputs:
            # concatenate inputs serializations
            inputs += tx_input.serialize()
        # number of outputs is a varint
        num_outputs = encode_varint(len(self.tx_outputs))
        # initialize outputs bytes concatenation
        outputs = b''
        for tx_output in self.tx_outputs:
            # concatenate outputs serializations
            outputs += tx_output.serialize()
        # locktime is 4 bytes, LE
        locktime = int_to_little_endian(self.locktime, 4)
        # return the concatenation of all the needed fields
        return version + num_inputs + inputs + num_outputs + outputs + locktime

    def serialize_segwit(self):
        result = int_to_little_endian(self.version, 4)
        # We add the segwit marker and the flag.
        result += b'\x00\x01'
        result += encode_varint(len(self.tx_inputs))
        for tx_in in self.tx_inputs:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outputs))
        for tx_out in self.tx_outputs:
            result += tx_out.serialize()
        # We serialize the witness.
        for tx_in in self.tx_inputs:
            result += int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if type(item) == int:
                    result += int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item
        result += int_to_little_endian(self.locktime, 4)
        return result

    # returns the implied fee of the transaction in satoshis.
    def fee(self):
        total_input = 0
        # loop over the inputs summing their values.
        for tx_input in self.tx_inputs:
            total_input += tx_input.value(self.testnet)
        total_output = 0
        # loop over the outputs summing their values.
        for tx_output in self.tx_outputs:
            total_output += tx_output.amount()
        # fee equals total inputs - total outputs
        return total_input - total_output

    # Returns the hash of the signature (z) for this transaction.
    def sig_hash(self, input_index, redeeem_script=None):
        # we need to manually start serializing the tx.
        result = int_to_little_endian(self.version, 4)
        # add number of inputs.
        result += encode_varint(len(self.tx_inputs))
        # loop inputs and replace the input's scriptsig at given index with prev_tx's scriptpubkey
        for i, tx_in in enumerate(self.tx_inputs):
            if i == input_index:
                # if it's a p2sh address, which means there's a redeem_script, we replace the ScriptSig
                # with the RedeemScript.
                if redeeem_script:
                    script_sig = redeeem_script
                else:
                    # if this is the input I want to find the hash for, script_sig is prev_tx's scriptpubkey
                    script_sig = tx_in.script_pubkey(self.testnet)
            else:
                # if it's not the input we're looking for, script_sig is left empty.
                script_sig = None
            # add the serialization of the input
            result += TxIn(tx_in.prev_tx, tx_in.prev_index,
                           script_sig, tx_in.sequence).serialize()
        # add the number of outputs as a varint.
        result += encode_varint(len(self.tx_outputs))
        # serialize each output.
        for tx_out in self.tx_outputs:
            result += tx_out.serialize()
        # add locktime.
        result += int_to_little_endian(self.locktime, 4)
        # add hash type in LE, 4 bytes.
        result += int_to_little_endian(SIGHASH_ALL, 4)
        # hash 256 the serialization.
        h256 = hash256(result)
        # convert the result to an integer using int.from_bytes(x, 'big')
        return int.from_bytes(h256, 'big')

    def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        tx_in = self.tx_inputs[input_index]
        # per BIP143 spec
        s = int_to_little_endian(self.version, 4)
        s += self.hash_prevouts() + self.hash_sequence()
        s += tx_in.prev_tx[::-1] + int_to_little_endian(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.cmds[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(
                self.testnet).cmds[1]).serialize()
        s += script_code
        s += int_to_little_endian(tx_in.value(), 8)
        s += int_to_little_endian(tx_in.sequence, 4)
        s += self.hash_outputs()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(hash256(s), 'big')

    # Method necessary for calculating z per BIP143 spec - method used in sig_hash_bip143()
    def hash_prevouts(self):
        if self._hash_prevouts is None:
            all_prevouts = b''
            all_sequence = b''
            for tx_in in self.tx_inputs:
                all_prevouts += tx_in.prev_tx[::-1] + \
                    int_to_little_endian(tx_in.prev_index, 4)
                all_sequence += int_to_little_endian(tx_in.sequence, 4)
            self._hash_prevouts = hash256(all_prevouts)
            self._hash_sequence = hash256(all_sequence)
        return self._hash_prevouts

    # Method necessary for calculating z per BIP143 spec - method used in sig_hash_bip143()
    def hash_sequence(self):
        if self._hash_sequence is None:
            self.hash_prevouts()  # this should calculate self._hash_prevouts
        return self._hash_sequence

    # Method necessary for calculating z per BIP143 spec - method used in sig_hash_bip143()
    def hash_outputs(self):
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outputs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash256(all_outputs)
        return self._hash_outputs

    # Returns whether the input at the given index (in self.tx_inputs array) has a valid signature.
    def verify_input(self, input_index):
        # get the wanted input.
        tx_in = self.tx_inputs[input_index]
        # check whether it's a p2sh input.
        if tx_in.script_pubkey(self.testnet).is_p2sh_script_pubkey():
            # If it is, we know the last cmd of the ScriptSig is the RedeemScript - page 151
            cmd = tx_in.script_sig.cmds[-1]
            # Now we parse it.
            # Parse the redeem script.
            raw_redeem = int_to_little_endian(len(cmd), 1) + cmd
            redeem_script = Script.parse(BytesIO(raw_redeem))
            # If the RedeemScript follows the p2wpkh special rule, which means the script is OP_0 followed by <20-byte hash>
            # This if handles the p2sh-p2wpkh case, as it's inside the p2sh if.
            if redeem_script.is_p2wpkh_script_pubkey():
                # The segwit transaction signature hash calculation is specified in BIP0143 - page 233.
                z = self.sig_hash_bip143(input_index, redeem_script)
                witness = tx_in.witness
            else:
                z = self.sig_hash(input_index, redeem_script)
                witness = None
        else:
            # This if handles the p2wpkh case.
            if tx_in.script_pubkey(self.testnet).is_p2wpkh_script_pubkey():
                z = self.sig_hash_bip143(input_index)
                witness = tx_in.witness
            else:
                # compute the signature hash for input.
                z = self.sig_hash(input_index)
                witness = None
        # combine scripts.
        combined_script = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
        # evaluate them.
        return combined_script.evaluate(z, witness=witness)

    # Returns whether this transaction is valid. page 135.
    def verify(self):
        # if tx is creating new bitcoins return False.
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_inputs)):
            # check if every input has the correct scriptsig.
            if not self.verify_input(i):
                return False
        return True

    # Generates the scriptsig for the input at the given index (in self.tx_inputs array) - page 141.
    # Returns True if the scriptsig was generated correctly, False otherwise.
    def sign_input(self, input_index, private_key):
        # calculate z for the given input.
        z = self.sig_hash(input_index)
        # create a signature object for the private key and z.
        sig_obj = private_key.sign(z)
        # get the DER signature from the signature object.
        der = sig_obj.der()
        # add the hash type to the DER signature.
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        # get the sec pubkey.
        sec = private_key.point.sec()
        # create the scriptsig, which is comprised of the sec pubkey and the signature.
        script_sig = Script([sig, sec])
        # add the ScriptSig to the given input.
        self.tx_inputs[input_index].script_sig = script_sig
        # verify the input was signed correctly.
        return self.verify_input(input_index)

    # returns whether the transaction is a coinbase transaction - page 164.
    def is_coinbase(self):
        return len(self.tx_inputs) == 1 and self.tx_inputs[0].prev_tx == b'\x00' * 32 and self.tx_inputs[0].prev_index == 0xffffffff

    # returns the height of the block for this coinbase transaction as an int - page 166
    def coinbase_height(self):
        # return None if it's not a coinbase transaction.
        if not self.is_coinbase:
            return None
        # get the scriptsig from the transaction input.
        script_sig = self.tx_inputs[0].script_sig
        # we know that the first command of the ScriptSig is the blockheight (in bytes), so we convert it to int.
        return little_endian_to_int(script_sig.cmds[0])

# class that represents a transaction input - page 95.


class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        # prev_tx is the hash256 of the previous transaction contents. It's a bytes obj. - page 93
        self.prev_tx = prev_tx
        # prev_index is the prev_tx's output index corresponding to this input.
        self.prev_index = prev_index
        self.script_sig = script_sig
        self.sequence = sequence

   # receives a bytes stream, returns a TxIn object
    @classmethod
    def parse(cls, stream):
        # prev_tx is 32 bytes, little endian, interpreted as bytes.
        prev_tx = stream.read(32)[::-1]
        # prev_index is 4 bytes, little endian, interpreted as integer.
        prev_index = little_endian_to_int(stream.read(4))
        # TODO:
        script_sig = Script.parse(stream)
        # sequence is 4 bytes, little endian, interpreted as integer.
        sequence = little_endian_to_int(stream.read(4))
        # returns an object of the same class.
        return cls(prev_tx, prev_index, script_sig, sequence)

    # returns the bytes serialization from a TxIn object
    def serialize(self):
        # just need to reverse order of previous tx hash.
        prev_tx = self.prev_tx[::-1]
        # get prev_index in byte format.
        prev_index = int_to_little_endian(self.prev_index, 4)
        # get script_sig in byte format.
        if self.script_sig is None:
            script_sig = b'\x00'
        else:
            script_sig = self.script_sig.serialize()
        # get sequence in byte_format.
        sequence = int_to_little_endian(self.sequence, 4)
        return prev_tx + prev_index + script_sig + sequence

    # fetches previous transaction. Done to be able to check this tx's inputs (prev tx's outputs) amounts.
    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    # returns the value of this tx input.
    def value(self, testnet=False):
        # we fetch the previous transaction
        tx = self.fetch_tx(testnet=testnet)
        # we return the amount of the tx output at the given index = this tx's spendable amount.
        return tx.tx_outputs[self.prev_index].amount

    # Returns the ScriptPubKey for the output that this inputs is trying to spend.
    def script_pubkey(self, testnet=False):
        '''Get the ScriptPubKey by looking up the tx hash
        Returns a Script object
        '''
        # use self.fetch_tx to get the transaction
        tx = self.fetch_tx(testnet=testnet)
        # get the output at self.prev_index
        # return the script_pubkey property
        return tx.tx_outputs[self.prev_index].script_pubkey

# class that represents a transaction output


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return f"{self.amount}:{self.script_pubkey}"

    # receives a bytes stream, returns a TxOut object
    @classmethod
    def parse(cls, stream):
        # amount is 8 bytes, little endian. Parsed this way because it's a hash.
        amount = little_endian_to_int(stream.read(8))
        # TODO:
        script_pubkey = Script.parse(stream)
        # returns an object of the same class.
        return cls(amount, script_pubkey)

    # returns the bytes serialization of a TxOut object
    def serialize(self):
        # get the amount in byte format.
        amount = int_to_little_endian(self.amount, 8)
        # get the script_pubkey in byte format.
        script_pubkey = self.script_pubkey.serialize()
        return amount + script_pubkey


class TxTest(TestCase):
    cache_file = './tx.cache'

    @classmethod
    def setUpClass(cls):
        # fill with cache so we don't have to be online to run these tests
        TxFetcher.load_cache(cls.cache_file)

    def test_parse_version(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.version, 1)

    def test_parse_inputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_inputs), 1)
        want = bytes.fromhex(
            'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
        self.assertEqual(tx.tx_inputs[0].prev_tx, want)
        self.assertEqual(tx.tx_inputs[0].prev_index, 0)
        want = bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
        self.assertEqual(tx.tx_inputs[0].script_sig.serialize(), want)
        self.assertEqual(tx.tx_inputs[0].sequence, 0xfffffffe)

    def test_parse_outputs(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(len(tx.tx_outputs), 2)
        want = 32454049
        self.assertEqual(tx.tx_outputs[0].amount, want)
        want = bytes.fromhex(
            '1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac')
        self.assertEqual(tx.tx_outputs[0].script_pubkey.serialize(), want)
        want = 10011545
        self.assertEqual(tx.tx_outputs[1].amount, want)
        want = bytes.fromhex(
            '1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac')
        self.assertEqual(tx.tx_outputs[1].script_pubkey.serialize(), want)

    def test_parse_locktime(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.locktime, 410393)

    def test_fee(self):
        raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 40000)
        raw_tx = bytes.fromhex('010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600')
        stream = BytesIO(raw_tx)
        tx = Tx.parse(stream)
        self.assertEqual(tx.fee(), 140500)
