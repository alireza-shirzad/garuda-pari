// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 2
contract Pari {
    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field Fp order P and scalar field Fr order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FP =
        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 constant EXP_SQRT_FP =
        0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52; // (P + 1) / 4;

    // Preprocessing the input

    uint256 constant COSET_SIZE =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant COSET_OFFSET =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant COSET_OFFSET_TO_COSET_SIZE =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant NEG_H_G1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 constant NEG_H_G2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 constant V_1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 constant V_2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    // Elements in VK

    uint256 constant H_X_1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant H_Y_1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant H_X_2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant H_Y_2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant ALPHA_G_X =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant ALPHA_G_Y =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant BETA_G_X =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant BETA_G_Y =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant TAU_H_X_1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant TAU_H_Y_1 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant TAU_H_X_2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    uint256 constant TAU_H_Y_2 =
        17805874995975841540914202342111839520379459829704422454583296818431106115052;

    /// Exponentiation in Fp.
    /// @notice Returns a number x such that a ^ e = x in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @param e the exponent
    /// @return x the result
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    /// Invertsion in Fp.
    /// @notice Returns a number x such that a * x = 1 in Fp.
    /// @notice The input does not need to be reduced.
    /// @notice Reverts with ProofInvalid() if the inverse does not exist
    /// @param a the input
    /// @return x the solution
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    function compute_vanishing_poly(
        uint256 chall
    ) internal view returns (uint256 result) {
        uint256 tau_exp = exp(chall, COSET_SIZE); // Compute tau^COSET_SIZE mod P
        result = addmod(tau_exp, COSET_OFFSET_TO_COSET_SIZE, P); // Add COSET_OFFSET_TO_COSET_SIZE mod P
    }

    function comp_vq(
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {
        uint256 term1 = mulmod(addmod(chall, NEG_H_G1, P), V_1, P);
        uint256 term2 = mulmod(addmod(chall, NEG_H_G2, P), V_2, P);
        uint256 x_a = addmod(term1, term2, P);

        // Compute vanishing polynomial
        uint256 vanishing_poly = compute_vanishing_poly(chall);

        // Compute numerator: (((proof[0] + x_a)^2) - proof[1]) mod P
        uint256 numerator = addmod(proof[0], x_a, P);
        numerator = mulmod(numerator, numerator, P);
        numerator = addmod(numerator, P - proof[1], P);

        // Compute modular inverse of vanishing_poly
        uint256 vanishing_poly_inv = invert_Fp(vanishing_poly);

        // Compute v_q = numerator * vanishing_poly_inv mod P
        v_q = mulmod(numerator, vanishing_poly_inv, P);
    }
    function multi_pairing(
        uint256[6] memory g1_elements, // 3 x (G1_X, G1_Y)
        uint256[12] memory g2_elements // 3 x (G2_X1, G2_X2, G2_Y1, G2_Y2)
    ) internal view returns (bool success) {
        bool callSuccess;
        uint256 result;

        assembly {
            // Allocate memory for the input
            let memPtr := mload(0x40) // Load free memory pointer

            // Copy G1 elements into memory
            mstore(add(memPtr, 0x00), mload(add(g1_elements, 0x20))) // G1_1_X
            mstore(add(memPtr, 0x20), mload(add(g1_elements, 0x40))) // G1_1_Y
            mstore(add(memPtr, 0x40), mload(add(g2_elements, 0x20))) // G2_1_X1
            mstore(add(memPtr, 0x60), mload(add(g2_elements, 0x40))) // G2_1_X2
            mstore(add(memPtr, 0x80), mload(add(g2_elements, 0x60))) // G2_1_Y1
            mstore(add(memPtr, 0xa0), mload(add(g2_elements, 0x80))) // G2_1_Y2

            mstore(add(memPtr, 0xc0), mload(add(g1_elements, 0x60))) // G1_2_X
            mstore(add(memPtr, 0xe0), mload(add(g1_elements, 0x80))) // G1_2_Y
            mstore(add(memPtr, 0x100), mload(add(g2_elements, 0xa0))) // G2_2_X1
            mstore(add(memPtr, 0x120), mload(add(g2_elements, 0xc0))) // G2_2_X2
            mstore(add(memPtr, 0x140), mload(add(g2_elements, 0xe0))) // G2_2_Y1
            mstore(add(memPtr, 0x160), mload(add(g2_elements, 0x100))) // G2_2_Y2

            mstore(add(memPtr, 0x180), mload(add(g1_elements, 0xa0))) // G1_3_X
            mstore(add(memPtr, 0x1a0), mload(add(g1_elements, 0xc0))) // G1_3_Y
            mstore(add(memPtr, 0x1c0), mload(add(g2_elements, 0x120))) // G2_3_X1
            mstore(add(memPtr, 0x1e0), mload(add(g2_elements, 0x140))) // G2_3_X2
            mstore(add(memPtr, 0x200), mload(add(g2_elements, 0x160))) // G2_3_Y1
            mstore(add(memPtr, 0x220), mload(add(g2_elements, 0x180))) // G2_3_Y2

            // Call the BN254 pairing precompile (0x08)
            callSuccess := staticcall(
                gas(), // Gas available
                0x08, // Precompile address for pairing
                memPtr, // Input memory location
                0x240, // Input size (576 bytes for 3 pairings)
                memPtr, // Store output in the same memory
                0x20 // Output size (32 bytes)
            )

            // Load the result from memory
            result := mload(memPtr)
        }

        // The precompile returns 1 if the pairing holds, 0 otherwise
        success = callSuccess && (result == 1);
    }

    function compute_A(
        uint256 v_a,
        uint256 v_b,
        uint256 v_q,
        uint256 chall,
        uint256 u_g_x,
        uint256 u_g_y
    ) internal view returns (uint256 A_x, uint256 A_y) {
        bool success;
        uint256[2] memory P1;
        uint256[2] memory P2;
        uint256[2] memory P3;
        uint256[2] memory P4;

        // Compute P1 = α_g * v_a (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr, 0x20), ALPHA_G_Y)
            mstore(add(ptr, 0x40), v_a)

            success := staticcall(gas(), 0x07, ptr, 0x60, P1, 0x40)
        }
        require(success, "EC MUL failed for alpha_g * v_a");

        // Compute P2 = β_g * v_b (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BETA_G_X)
            mstore(add(ptr, 0x20), BETA_G_Y)
            mstore(add(ptr, 0x40), v_b)

            success := staticcall(gas(), 0x07, ptr, 0x60, P2, 0x40)
        }
        require(success, "EC MUL failed for beta_g * v_b");

        // Compute P3 = g * v_q (assuming g = (1, 2))
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 1)
            mstore(add(ptr, 0x20), 2)
            mstore(add(ptr, 0x40), v_q)

            success := staticcall(gas(), 0x07, ptr, 0x60, P3, 0x40)
        }
        require(success, "EC MUL failed for g * v_q");

        // Compute P4 = u_g * challenge (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, u_g_x)
            mstore(add(ptr, 0x20), u_g_y)
            mstore(add(ptr, 0x40), chall)

            success := staticcall(gas(), 0x07, ptr, 0x60, P4, 0x40)
        }
        require(success, "EC MUL failed for u_g * challenge");

        // Compute A = P1 + P2 + P3 - P4 (point addition using ecAdd)
        uint256[2] memory temp;

        // Step 1: temp = P1 + P2
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(P1))
            mstore(add(ptr, 0x20), mload(add(P1, 0x20)))
            mstore(add(ptr, 0x40), mload(P2))
            mstore(add(ptr, 0x60), mload(add(P2, 0x20)))

            success := staticcall(gas(), 0x06, ptr, 0x80, temp, 0x40)
        }
        require(success, "EC ADD failed for P1 + P2");

        // Step 2: temp = temp + P3
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(P3))
            mstore(add(ptr, 0x60), mload(add(P3, 0x20)))

            success := staticcall(gas(), 0x06, ptr, 0x80, temp, 0x40)
        }
        require(success, "EC ADD failed for (P1 + P2) + P3");

        // Step 3: A = temp - P4 (Point subtraction: A = temp + (-P4))
        // In elliptic curves, subtraction is adding the negated Y-coordinate.
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(P4))
            mstore(add(ptr, 0x60), sub(P, mload(add(P4, 0x20)))) // Negate P4_Y (mod P)

            success := staticcall(gas(), 0x06, ptr, 0x80, A_x, 0x40)
        }
        require(success, "EC ADD failed for final A computation");

        // Return final (A_x, A_y)
        assembly {
            A_y := mload(add(A_x, 0x20))
        }
    }

    function Verify(
        uint256[6] calldata proof,
        uint256[2] calldata input
    ) public view {
        // Compute challenge
        bytes32 hash = keccak256(
            abi.encodePacked(
                proof[0],
                proof[1],
                H_X_1,
                H_Y_1,
                H_X_2,
                H_Y_2,
                ALPHA_G_X,
                ALPHA_G_Y,
                BETA_G_X,
                BETA_G_Y,
                TAU_H_X_1,
                TAU_H_Y_1,
                TAU_H_X_2,
                TAU_H_Y_2
            )
        );
        uint256 chall = uint256(hash) % P;
        // Compute v_q using comp_vq
        uint256 v_q = comp_vq(proof, chall);

        // Compute A using elliptic curve precompiles
        (uint256 A_x, uint256 A_y) = compute_A(
            input[0],
            input[1],
            v_q,
            chall,
            proof[4],
            proof[5]
        );

        // Prepare G1 elements for pairing
        uint256[6] memory g1_elements = [
            proof[0],
            proof[1], // T (G1)
            proof[4],
            proof[5], // u_g (G1)
            A_x,
            A_y // A (computed G1)
        ];

        // Prepare G2 elements for pairing
        uint256[12] memory g2_elements = [
            H_X_1,
            H_X_2,
            H_Y_1,
            H_Y_2, // delta_2_H (G2)
            TAU_H_X_1,
            TAU_H_X_2,
            TAU_H_Y_1,
            TAU_H_Y_2, // tau_h (G2)
            H_X_1,
            H_X_2,
            H_Y_1,
            H_Y_2 // H (G2)
        ];

        // Perform the pairing check
        bool pairing_success = multi_pairing(g1_elements, g2_elements);

        // Require successful pairing
        require(pairing_success, "Pairing check failed");
    }
}
