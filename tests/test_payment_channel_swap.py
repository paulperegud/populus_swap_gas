import ethereum.tester as tester
import bitcoin
import random
from rlp.utils import decode_hex, encode_hex
import ethereum.utils as utils
from secp256k1 import PublicKey, ALL_FLAGS, PrivateKey
import threading

def fund_and_finalize(chain, gnt, x):
    for i, addr in enumerate(tester.accounts[:10]):
        v = random.randrange(15000 * utils.denoms.ether, 82000 * utils.denoms.ether)
        chain.wait.for_receipt(
            gnt.transact({'value': v, 'from': encode_hex(addr)}).create())
    chain.wait.for_receipt(
        gnt.transact().finalize())
    assert not gnt.call().funding()

def test_swap(chain):
    r_priv = tester.keys[1]
    r_pub = bitcoin.privtopub(r_priv)
    r_addr = tester.accounts[1]

    def p_pub(n):
        return bitcoin.privtopub(tester.keys[n])

    bn = chain.web3.eth.blockNumber
    start, finish = bn+2, bn+11
    args = [r_addr, r_addr, start, finish]
    gnt, _ = chain.provider.get_or_deploy_contract('GolemNetworkToken', deploy_args=args)
    fund_and_finalize(chain, gnt, chain.web3.eth.coinbase)
    providers_no = 5
    allowance = utils.denoms.ether * 1
    provrange = range(2, 2+providers_no)
    print(provrange)
    providers = [ tester.accounts[i] for i in provrange]
    hex_providers = [encode_hex(i) for i in providers]
    args = [providers, gnt.address, allowance]
    swap, tx = chain.provider.get_or_deploy_contract('GolemSwapChannels',
                                                     deploy_transaction={
                                                         'from': r_addr
                                                     },
                                                     deploy_args=args)
    gas = chain.wait.for_receipt(tx)
    assert 0 == gnt.call().balanceOf(swap.address)
    assert not swap.call().is_funded()
    print("contract deployment tx {}".format(gas))
    print("contract deployment cost for {} providers: {}".format(providers_no, gas['gasUsed']))
    print("adding one more provider")
    gas = chain.wait.for_receipt(
        swap.transact().add_provider(encode_hex(tester.accounts[9])) )
    providers.append(tester.accounts[9])
    print("add provider cost: {}".format(gas['gasUsed']))
    providers_no = swap.call().len_providers()
    gas = chain.wait.for_receipt(
        gnt.transact({'from': r_addr}).transfer(swap.address, providers_no * allowance))
    assert swap.call().is_funded()
    print("GNT initial transfer cost: {}".format(gas['gasUsed']))
    print("all providers: {}".format(swap.call().all_providers()))
    random.seed(0)

    fin_costs = []
    for p_addr in providers:
        gas = finalize_provider(chain, gnt, swap, r_priv, p_addr)
        fin_costs.append(gas)

    print("finalize call costs: {}".format(fin_costs))
    print("avg fin cost: {}".format(sum(fin_costs) / len(fin_costs)))
    assert False

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

def finalize_provider(chain, gnt, swap, r_priv, p_addr):
    kdf_seed = random.getrandbits(32*8)
    i = random.randint(1, 100)
    # secret represents partial evaluation of KDF derivation function
    # where KDF(kdf_seed, i) = sha3(kdf_seed ++ i)
    secret = cpack(30, kdf_seed) + cpack(2, i)
    assert len(secret) == 32
    max_value = swap.call().allowance()
    value = random.randint(1, max_value)
    # in Solidity: sha3(sha3(secret), sha3(msg.sender), bytes32(_value)):
    msghash = utils.sha3(utils.sha3(secret) + utils.sha3(p_addr) + cpack(32, value))
    assert len(msghash) == 32
    (V, R, S) = sign_eth(msghash, r_priv)
    ER = cpack(32, R)
    ES = cpack(32, S)
    assert gnt.address == swap.call().gnt()
    prov_balance = gnt.call().balanceOf(p_addr)
    fin_txn_hash = swap.transact({"from": p_addr}).finalize(secret, value, ER, ES, V)
    txn = chain.wait.for_receipt(fin_txn_hash)
    new_balance = gnt.call().balanceOf(p_addr)
    assert new_balance == prov_balance + value
    return txn['gasUsed']

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
