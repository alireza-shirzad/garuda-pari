// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Pari.sol";  // Import your contract

contract PariGasTest is Test {
    Pari verifier;

    function setUp() public {
        verifier = new Pari();
    }

    function testGasVerify() public {
        uint256[6] memory proof = [
            0x1f3b4c6d8e9a0b123456789abcdef0123456789abcdef0123456789abcdef,
            0x2d4e5f60793a4b5c6d7e8f90123456789abcdef0123456789abcdef01234567,
            0x3c5d6e7f801a2b3c5e6f7890123456789abcdef0123456789abcdef012345678,
            0x4b6c7d8e9f0123456789abcdef0123459cdef0123456789abcdef0123456789,
            0x5a7b8c9d0e123456789abcdef012678bcdef0123456789abcdef01234567890,
            0x6789abcdef0123456789abcdef01789abcdef0123456789abcdef01234567890
        ];
        uint256[2] memory input = [
            0x789abcdef012349abcdef0123456789abcdef0123456789abcdef0123456789a,
            0x89abcdef016789abcdef0123456789abcdef0123456789abcdef0123456789ab
        ];

        // Expect the contract to revert but still measure gas
        vm.expectRevert("Pairing check failed");
        verifier.Verify(proof, input);
    }
}


// 1040420573
// 1040420572