pragma solidity ^0.4.10;

import "./GolemNetworkToken.sol";

contract GolemSecretForPaymentSwap {
    address public requestor;
    address public provider;

    GolemNetworkToken public gnt;

    event MyDebug(bytes32 myvalue);

    function GolemSecretForPaymentSwap(address _provider, address _gnt) {
        gnt = GolemNetworkToken(_gnt);
        requestor = msg.sender;
        provider = _provider;
    }

    function finalize(bytes32 secret, uint _value, bytes32 r, bytes32 s, uint8 v)
        external {

        // Only the provider can resolve this. I think it is cheaper than including
        // the provider address in the signed message. Right?
        if (msg.sender != provider)
            throw;

        var sh = sha3(secret);
        
        var h = sha3(sh, bytes32(_value));

        var recoveredAddr = ecrecover(h, v, r, s);
        if (recoveredAddr != requestor) {
            throw;
        }

        // Here we confirmed the requestor signed the offchain payment.
        
        // We check the balance of the swap contract here allow the requestor
        // to increase the deposit after the contract is created.
        //
        // This has also a serious flaw: we are not able to create swap contract
        // and transfer a deposit here in a single transaction.

        var deposit = gnt.balanceOf(this);

        var value = _value;
        if (value > deposit)
            value = deposit;  // The provider was cheated, send as much as possible.
            
        var rem = deposit - value;

        if (!gnt.transfer(provider, value))
            throw;
            
        if (!gnt.transfer(requestor, rem))
            throw;

        selfdestruct(requestor);
    }
}
