pragma solidity ^0.4.4;

import "./GolemNetworkToken.sol";

contract GolemSwapChannels {
    address public requestor;
    address public provider;

    mapping (address => bool) public isProvider;
    address[] public providers;

    uint public allowance;

    GolemNetworkToken public gnt;

    event MyDebug(bytes32 myvalue);

    function GolemSwapChannels(address[] _providers, address _gnt, uint _allowance) {
        gnt = GolemNetworkToken(_gnt);
        requestor = msg.sender;
        allowance = _allowance;
        providers = _providers;
    }

    function add_provider(address _provider) external {
        providers.push(_provider);
    }

    function all_providers() external returns (address[]) {
        return providers;
    }

    function is_funded() external returns (bool) {
        return providers.length * allowance <= gnt.balanceOf(this);
    }

    function len_providers() external returns (uint) {
        return providers.length;
    }

    function finalize(bytes32 secret, uint _value, bytes32 r, bytes32 s, uint8 v)
        external returns (bool) {

        // Allowing anyone but provider to close the channel allows requestor to
        // launch an "close channel with intermediate, low _value" attack
        var provider = msg.sender;

        // Check if requestor is not attempting double spent
        if (_value > allowance)
            throw;

        // validate the signature

        var sh = sha3(secret);
        
        var h = sha3(sh, sha3(provider), bytes32(_value));

        var recoveredAddr = ecrecover(h, v, r, s);
        if (recoveredAddr != requestor) {
            throw;
        }

        // Here we confirmed the requestor signed the offchain payment.
        //
        // This has also a serious flaw: we are not able to create swap contract
        // and transfer a deposit here in a single transaction.

        // Also, current GNT construction means that Swap contract separated from
        // GNT contract will necessary store all deposits for all tasks initiated on
        // in the Swap contract

        for (uint i = 0; i < providers.length - 1; i++)
            if (providers[i] == provider) {
                providers[i] = providers[providers.length - 1];
                break;
            }
        providers.length -= 1;

        if (!gnt.transfer(provider, _value))
            throw;
    }
}
