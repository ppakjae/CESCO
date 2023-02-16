

contract Suicide {

  function kill(address addr) public {
    if (addr == address(0x0)) {
      suicide(addr);
    }
  }

}
