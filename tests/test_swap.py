def test_greeter(chain):

    storer, _ = chain.provider.get_or_deploy_contract('Storer')
    greeter, _ = chain.provider.get_or_deploy_contract('Greeter')

    print("greeter: {}".format(greeter))
    zero = '0x0000000000000000000000000000000000000000'
    assert zero == greeter.call().getStorer()
    assert not greeter.call().checkStorer()
    set_txn_hash = greeter.transact().setStorer(storer.address)
    txn = chain.wait.for_receipt(set_txn_hash)
    print("txn: {}".format(txn['gasUsed']))
    assert False
    assert zero != greeter.call().getStorer()
    assert greeter.call().checkStorer()

    greeting = greeter.call().greet()
    assert greeting == 501

def test_swap(chain):
    storer, _ = chain.provider.get_or_deploy_contract('GolemNetworkToken')
    greeter, _ = chain.provider.get_or_deploy_contract('GolemSecretForPaymentSwap')
