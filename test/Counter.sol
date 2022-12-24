// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Counter {
    uint256 public number;

    receive() external payable virtual {}

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }
}
