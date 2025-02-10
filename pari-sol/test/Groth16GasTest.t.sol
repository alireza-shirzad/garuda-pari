// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Groth16Verifier.sol";  // Import your Groth16 contract

contract Groth16Test is Test {
    Groth16Verifier verifier;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    function testGasVerify() public {
        uint256[8] memory proof = [
            0x1f3b4c6d8e9a0b123456789abcdef0123456789abcdef0123456789abcdef0,
            0x2d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef012367,
            0x3c5d6e7f8091a2b3c4d5e6f7890123456789abcdef0123456789abcdef012348,
            0x4b6c79f0123456789acdef0123456789abcdef0123456789abcdef0123456789,
            0x5a7b8c123456789abcdef0123456789abcdef0123456789abcdef01234567890,
            0x6789abc01234567abcdef0123456789abcdef0123456789abcdef01234567890,
            0x789abcd23456789abcdef0123456789abcdef0123456789abcdef0123456789a,
            0x89abcde23456789acdef0123456789abcdef0123456789abcdef0123456789ab
        ];
        
        uint256[2] memory input = [
            0x9abcdef456789abcdef0123456789abcdef0123456789abcdef0123456789abc,
            0xabcdef456789abcdef0123456789abcdef0123456789abcdef0123456789abcd
        ];

        // Expect the contract to revert but still measure gas
        vm.expectRevert("ProofInvalid");
        verifier.Verify(proof, input);
    }
}