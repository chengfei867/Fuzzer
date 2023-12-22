// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Number {
    uint256 private num = 1 ;

    function add() public {
        num++;
    }


    function getNum() public view returns(uint256){
        return num;
    }
}