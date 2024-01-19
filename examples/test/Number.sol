// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Number {
    uint256 private num;

    constructor(uint256 initNum) {
        num = initNum;
    }

    function add() public {
        num++;
    }


    function getNum() public view returns(uint256){
        return num;
    }
}