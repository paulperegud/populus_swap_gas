pragma solidity ^0.4.10;

import "./GolemNetworkToken.sol";

contract GolemSecretForPaymentSwap {
    address public sendr;
    address public requestor;
    address public provider;

    address public recovered;

    bytes32 public b0;
    bytes32 public b1;
    bytes32 public b2;
    bytes32 public b3;

    GolemNetworkToken gnt;

    event MyDebug(bytes32 myvalue);

    function GolemSecretForPaymentSwap(address _requestor, address _provider) {
        sendr = msg.sender;
        requestor = _requestor;
        provider = _provider;
    }

    /* function gls() external returns (bytes32) { */
    /*     return debugslot; */
    /* } */

    function enc(bytes32 bts) external returns (bytes32) {
        return bts;
    }

    function sha3(bytes32 bts) external returns (bytes32) {
        return sha3(bts);
    }
    
    function finalize(bytes32 secret, uint _value, bytes32 r, bytes32 s, uint8 v)
        external returns (address) {


        // Only the provider can resolve this. I think it is cheaper than including
        // the provider address in the signed message. Right?
        if (msg.sender != provider)
            throw;

        b0 = secret;
        var sh = sha3(secret);
        b1 = sh;
        b2 = bytes32(_value);
        
        var h = sha3(sh, bytes32(_value));
        b3 = h;

        var recoveredAddr = ecrecover(h, v, r, s);
        recovered = recoveredAddr;
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

        return requestor;


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
