// 简单的示例智能合约
// 请注意：此合约有安全漏洞，仅用于演示目的，不要在生产环境中使用。

pragma solidity ^0.8.21;

contract SimpleVulnerableContract {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
