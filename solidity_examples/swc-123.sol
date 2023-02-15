contract A {

    function baz(int256 x) public pure returns (int256) {
        require(0 > x);
        return 42;
    }

    function doubleBaz() public pure returns (int256) {
        return baz(0);
    }
       
}
