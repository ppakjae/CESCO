pragma solidity ^0.4.22;

contract FindThisHash{
    uint constant public hash = 12345;

    constructor() public payable{}

    function solve(uint solution) public{
        require(hash == solution);
        msg.sender.call(10 ether);
    }

}