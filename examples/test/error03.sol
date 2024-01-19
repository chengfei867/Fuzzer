// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract VulnerableContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // 接收以太币的回退函数
    receive() external payable {}

    // 一个可能锁定以太的提款函数
    function withdraw() public {
        require(msg.sender == owner, "Not the owner");

        // 这里没有检查send的返回值，可能导致未处理的异常
        payable(owner).send(address(this).balance);

        // 如果send失败，以太币将被锁定在合约中
    }

    // 查询合约余额
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
