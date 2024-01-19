// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// 演示DoS和随机数生成漏洞的智能合约
contract VulnerableContract {
    address public owner;
    uint public lastReceived;

    constructor() {
        owner = msg.sender;
    }

    // 接收以太币的函数
    function receiveEth() public payable {
        require(msg.value > 0, "Must send ETH");
        lastReceived = block.number;
    }

    // 基于不安全的随机数生成器的函数
    function unsafeRandom() public view returns (uint) {
        return uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 100;
    }

    // 一个可能导致拒绝服务(DoS)的提款函数
    function withdraw() public {
        require(msg.sender == owner, "Only owner can withdraw");

        // 如果合约余额为零或发送失败，将导致DoS
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Failed to send Ether");
    }
}