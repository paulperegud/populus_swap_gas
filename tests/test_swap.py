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
    # print("block: {}".format(chain.web3.eth.blockNumber))
    for i, addr in enumerate(tester.accounts[:10]):
        v = random.randrange(15000 * utils.denoms.ether, 82000 * utils.denoms.ether)
        # print("i: {}, addr: {}, x: {}".format(i, encode_hex(addr), x))
        chain.wait.for_receipt(
            gnt.transact({'value': v, 'from': encode_hex(addr)}).create())
        # print("block: {}".format(chain.web3.eth.blockNumber))
    # print("block: {}".format(chain.web3.eth.blockNumber))
    # print("finalize call")
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
    # print("start: {}, finish: {}".format(start, finish))
    args = [r_addr, r_addr, start, finish]
    gnt, _ = chain.provider.get_or_deploy_contract('GolemNetworkToken', deploy_args=args)
    fund_and_finalize(chain, gnt, chain.web3.eth.coinbase)
    args = [r_addr, p_addr]
    swap, _ = chain.provider.get_or_deploy_contract('GolemSecretForPaymentSwap',
                                                    deploy_transaction={
                                                        'from': r_addr
                                                    },
                                                    deploy_args=args)
    random.seed(0)

    def mb(x):
        if x == 0:
            return 1
        import math
        print("calc max number of bytes needed to represent: {}".format(x))
        return math.trunc(math.ceil(math.log(x, 256)))

    def tobyteslist(n, bts):
        return [ bts >> i & 0xff for i in reversed(range(0, n*8, 8)) ]

    def u2bl(ustr):
        r = []
        for x in ustr:
            n = mb(ord(x))
            r.extend(list(reversed(tobyteslist(n, ord(x)))))
        return r

    def cpack(n, bts):
        """Packs int into bytesXX"""
        import struct
        fmt = "!{}B".format(n)
        return struct.pack(fmt, *tobyteslist(n, bts))

    def charpack(n, chars):
        import struct
        fmt = "!{}B".format(n)
        return struct.pack(fmt, *[ ord(c) for c in chars ])

    kdf_seed = random.getrandbits(32*8)
    i = random.randint(1, 100)

    kdf_seed = "12345678901234567890123456789012"

    kdf_packed = unicode(kdf_seed)
    called = swap.call().enc(kdf_packed)
    assert bytes(kdf_packed) == bytes(called)

    called = swap.call().sha3(kdf_packed)
    assert bytes(utils.sha3(kdf_packed)) == bytes(charpack(32, called))

    kdf_seed = random.getrandbits(32*8)

    kdf_packed = bytes(cpack(32, kdf_seed))
    assert 32 == len(kdf_packed)
    called = swap.call().enc(kdf_packed)
    assert len(kdf_packed) == len(called)
    assert kdf_packed == bytes(charpack(32, called))

    # secret represents partial evaluation of KDF derivation function
    # where KDF(kdf_seed, i) = sha3(kdf_seed ++ i)
    secret = cpack(30, kdf_seed) + cpack(2, i)
    assert len(secret) == 32
    max_value = gnt.call().balanceOf(tester.accounts[9])
    value = random.randint(1, max_value)
    # in Solidity: sha3(sha3(secret), bytes32(_value)):
    msghash = utils.sha3(utils.sha3(secret) + cpack(32, value))
    assert len(msghash) == 32
    (V, R, S) = sign_eth(msghash, r_priv)
    ER = cpack(32, R)
    ES = cpack(32, S)
    fin_txn_hash = swap.transact({"from": p_addr}).finalize(secret, value, ER, ES, V)
    txn = chain.wait.for_receipt(fin_txn_hash)
    b0 = swap.call().b0()
    assert charpack(32, b0) == secret;
    sh = swap.call().b1()
    assert charpack(32, sh) == utils.sha3(secret);
    bytesvalue = swap.call().b2()
    assert charpack(32, bytesvalue) == cpack(32, value)

    req = swap.call().requestor()
    assert req == '0x'+encode_hex(r_addr)

    sender = swap.call().sendr()
    assert sender == '0x'+encode_hex(r_addr)

    recov = swap.call().recovered()
    assert recov == req
    assert recov == '0x'+encode_hex(r_addr)


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

# def sign_btc(msghash, priv, pub):
#     V, R, S = bitcoin.ecdsa_raw_sign(msghash, priv)
#     assert bitcoin.ecdsa_raw_verify(msghash, (V, R, S), pub)
#     Q = bitcoin.ecdsa_raw_recover(msghash, (V, R, S))
#     assert addr == bitcoin.encode_pubkey(Q, 'hex_compressed') if V >= 31 else bitcoin.encode_pubkey(Q, 'hex')
#     return (V, R, S)

# def test_greeter(chain):
#     storer, _ = chain.provider.get_or_deploy_contract('Storer')
#     greeter, _ = chain.provider.get_or_deploy_contract('Greeter')
#     print("greeter: {}".format(greeter))
#     zero = '0x0000000000000000000000000000000000000000'
#     assert zero == greeter.call().getStorer()
#     assert not greeter.call().checkStorer()
#     set_txn_hash = greeter.transact().setStorer(storer.address)
#     txn = chain.wait.for_receipt(set_txn_hash)
#     print("txn: {}".format(txn['gasUsed']))
#     assert False
#     assert zero != greeter.call().getStorer()
#     assert greeter.call().checkStorer()

#     greeting = greeter.call().greet()
#     assert greeting == 501
