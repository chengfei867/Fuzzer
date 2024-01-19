// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// 整数溢出和访问控制漏洞的示例合约
contract VulnerableContract {
    uint public balance;
    address public owner;

    constructor() {
        owner = msg.sender;
        balance = 0;
    }

    // 一个不安全的存款函数，可能导致整数溢出
    function deposit(uint amount) public {
        require(amount > 0, "Amount must be greater than 0");
        balance += amount;

        // 整数溢出检查（不安全）
        require(balance >= amount, "Integer overflow detected");
    }

    // 提款函数，没有适当的访问控制
    function withdraw(uint amount) public {
        require(amount <= balance, "Insufficient balance");

        // 没有检查调用者是否为合约所有者
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }

    // 一个不安全的函数，允许任何人更改所有者
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
}