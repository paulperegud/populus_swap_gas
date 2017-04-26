import ethereum.tester as tester
import bitcoin
import random
from rlp.utils import decode_hex, encode_hex
import ethereum.utils as utils
from secp256k1 import PublicKey, ALL_FLAGS, PrivateKey
import threading

def ops():
    pass

def fund_and_finalize(chain, gnt, x):
    for i, addr in enumerate(tester.accounts[:10]):
        v = random.randrange(15000 * utils.denoms.ether, 82000 * utils.denoms.ether)
        chain.wait.for_receipt(
            gnt.transact({'value': v, 'from': encode_hex(addr)}).create())
    chain.wait.for_receipt(
        gnt.transact().finalize())
    assert not gnt.call().funding()

def test_swap(chain):
    r_priv = tester.keys[9]
    r_pub = bitcoin.privtopub(r_priv)
    r_addr = tester.accounts[9]
    p_priv = tester.keys[2]
    p_pub = bitcoin.privtopub(p_priv)
    p_addr = tester.accounts[2]
    bn = chain.web3.eth.blockNumber
    start, finish = bn+2, bn+11
    args = [r_addr, r_addr, start, finish]
    gnt, _ = chain.provider.get_or_deploy_contract('GolemNetworkToken', deploy_args=args)
    fund_and_finalize(chain, gnt, chain.web3.eth.coinbase)
    args = [p_addr, gnt.address]
    swap, tx = chain.provider.get_or_deploy_contract('GolemSecretForPaymentSwap',
                                                     deploy_transaction={
                                                         'from': r_addr
                                                     },
                                                     deploy_args=args)
    gas = chain.wait.for_receipt(tx)
    print("contract deployment cost: {}".format(gas['gasUsed']))
    gas = chain.wait.for_receipt(
        gnt.transact({'from': r_addr}).transfer(swap.address, 100000))
    print("GNT initial transfer cost: {}".format(gas['gasUsed']))
    random.seed(0)

    def mb(x):
        if x == 0:
            return 1
        import math
        print("calc max number of bytes needed to represent: {}".format(x))
        return math.trunc(math.ceil(math.log(x, 256)))

    def tobyteslist(n, bts):
        return [ bts >> i & 0xff for i in reversed(range(0, n*8, 8)) ]

    def cpack(n, bts):
        """Packs int into bytesXX"""
        import struct
        fmt = "!{}B".format(n)
        return struct.pack(fmt, *tobyteslist(n, bts))

    def charpack(n, chars):
        """Use on bytes32 values returned by EVM"""
        import struct
        fmt = "!{}B".format(n)
        return struct.pack(fmt, *[ ord(c) for c in chars ])

    kdf_seed = random.getrandbits(32*8)
    i = random.randint(1, 100)
    # secret represents partial evaluation of KDF derivation function
    # where KDF(kdf_seed, i) = sha3(kdf_seed ++ i)
    secret = cpack(30, kdf_seed) + cpack(2, i)
    assert len(secret) == 32
    max_value = gnt.call().balanceOf(swap.address)
    value = random.randint(1, max_value)
    # in Solidity: sha3(sha3(secret), bytes32(_value)):
    msghash = utils.sha3(utils.sha3(secret) + cpack(32, value))
    assert len(msghash) == 32
    (V, R, S) = sign_eth(msghash, r_priv)
    ER = cpack(32, R)
    ES = cpack(32, S)
    assert gnt.address == swap.call().gnt()
    fin_txn_hash = swap.transact({"from": p_addr}).finalize(secret, value, ER, ES, V)
    txn = chain.wait.for_receipt(fin_txn_hash)
    print("finalize call costs: {}".format(txn['gasUsed']))
    assert False


def on_MyDebug(*args, **kwargs):
    print("args: {}".format(args))
    # print("mydebug event:{}, myvalue: {}".format(event.event, event.args.myvalue))

def sign_eth(rawhash, priv):
    pk = PrivateKey(priv, raw=True)
    signature = pk.ecdsa_recoverable_serialize(
        pk.ecdsa_sign_recoverable(rawhash, raw=True)
    )
    signature = signature[0] + utils.bytearray_to_bytestr([signature[1]])
    v = utils.safe_ord(signature[64]) + 27
    r = utils.big_endian_to_int(signature[0:32])
    s = utils.big_endian_to_int(signature[32:64])
    return (v, r, s)
