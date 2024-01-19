// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// 简单的存储合约，故意包含重入漏洞
contract VulnerableContract {
    mapping(address => uint) public balances;

    // 存款函数
    function deposit() public payable {
        require(msg.value > 0, "Deposit value must be greater than 0");
        balances[msg.sender] += msg.value;
    }

    // 提款函数，包含重入漏洞
    function withdraw() public {
        uint balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // 调用者可在接收到ETH之前重新进入此合约
        (bool sent, ) = msg.sender.call{value: balance}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }

    // 获取合约余额
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}