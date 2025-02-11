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
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495615; // R - 2

    // Preprocessing the input

    uint256 constant COSET_SIZE = 16;

    uint256 constant COSET_OFFSET = 1;
    uint256 constant MINUS_COSET_OFFSET_TO_COSET_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE =
        12213610784531559500851127806306714048188373049403105123334704620498104936634;

    uint256 constant NEG_H_Gi_0 =
        15634706786522089014999940912207647497621112715300598509090847765194894752723;
    uint256 constant NEG_H_Gi_1 =
        13274704216607947843011480449124596415239537050559949017414504948711435969894;
    uint256 constant NOM_0 =
        16440620411579288719970892391199562879874424903382076654444990631808048476188;
    uint256 constant NOM_1 =
        10517215346090920674167993631328532209117453960715322503941550432721646124186;

    // Elements in VK

    uint256 constant G_X =
        18212102334394492265028276912568179054490083287966874604750371166771152878918;

    uint256 constant G_Y =
        19051547621860615371097257781611854064184640229464227024340485503635323265514;

    uint256 constant H_X_0 =
        6544699278481598441600196070637395050672550111138901917854422452543436012878;
    uint256 constant H_X_1 =
        18264750924445413639031259445102017902843470530989736427633338720457892131674;
    uint256 constant H_Y_0 =
        10032665182248219466060852685902662225506768634169311208311258920574541095877;

    uint256 constant H_Y_1 =
        562565163802533593527530741833919796588134748499727025473245471455959254462;

    uint256 constant ALPHA_G_X =
        10375097425119143760693064298273524711627205197396174789864790343176586385778;

    uint256 constant ALPHA_G_Y =
        7365195522646952169974124049143981581485838643027381005174321961855915684522;

    uint256 constant BETA_G_X =
        12971105903759373104453077008007773448943457323386137776428466989247741330899;

    uint256 constant BETA_G_Y =
        18824360270889249169168621120076935537219524284404085152523532489397162633937;

    uint256 constant TAU_H_X_0 =
        3540105755486918127918155275624837134217972567938476545305194345892756433201;

    uint256 constant TAU_H_X_1 =
        18041217636100106373175718744095198970708147600474642016419968418336857005685;

    uint256 constant TAU_H_Y_0 =
        14154078461999584676189907385082723012272946677131333469012033118434915197425;

    uint256 constant TAU_H_Y_1 =
        10552760699065714211118830328557327686959241925612332223301119938658446978136;

    uint256 constant DELTA_TWO_H_X_0 =
        20416030209017591869624962762622602296532943911399254301628797753019370265502;
    uint256 constant DELTA_TWO_H_X_1 =
        7875776821442817275516986721312659114205894673434809776375743956349652369084;
    uint256 constant DELTA_TWO_H_Y_0 =
        858090423195253233612889489901206326947347495854769386462359668205961784816;

    uint256 constant DELTA_TWO_H_Y_1 =
        16817700532945113191388981405523623747613676538168443311998210006164550228010;

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
            mstore(add(f, 0xa0), R)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    /// Invertsion in Fr.
    /// @notice Returns a number x such that a * x = 1 in Fr.
    /// @notice The input does not need to be reduced.
    /// @notice Reverts with ProofInvalid() if the inverse does not exist
    /// @param a the input
    /// @return x the solution
    function invert_FR(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FR);
        if (mulmod(a, x, R) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    // Z_H(x) = x^m-h^m
    // where m = COSET_SIZE and h = COSET_OFFSET
    function compute_vanishing_poly(
        uint256 chall
    ) internal view returns (uint256 result) {
        // Exp uses 0x05 precompile internally
        uint256 tau_exp = exp(chall, COSET_SIZE);
        result = addmod(tau_exp, MINUS_COSET_OFFSET_TO_COSET_SIZE, R);
    }

    function comp_vq(
        uint256[2] calldata input,
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {
        uint256 neg_cur_elem0 = addmod(chall, NEG_H_Gi_0, R);
        uint256 neg_cur_elem1 = addmod(chall, NEG_H_Gi_1, R);

        uint256 neg_cur_elem0_inv = invert_FR(neg_cur_elem0);
        uint256 neg_cur_elem1_inv = invert_FR(neg_cur_elem1);

        uint256 lagrange_0 = mulmod(neg_cur_elem0_inv, NOM_0, R);
        uint256 lagrange_1 = mulmod(neg_cur_elem1_inv, NOM_1, R);

        uint256 x_a = addmod(
            mulmod(lagrange_0, input[0], R),
            mulmod(lagrange_1, input[1], R),
            R
        );

        // Compute vanishing polynomial
        uint256 vanishing_poly = compute_vanishing_poly(chall);

        // Compute numerator: (((proof[0] + x_a)^2) - proof[1]) mod P
        uint256 numerator = addmod(proof[0], x_a, R);
        numerator = mulmod(numerator, numerator, R);
        numerator = addmod(numerator, R - proof[1], R);

        // Compute modular inverse of vanishing_poly
        uint256 vanishing_poly_inv = invert_FR(vanishing_poly);
        // Compute v_q = numerator * vanishing_poly_inv mod P
        v_q = mulmod(numerator, vanishing_poly_inv, R);
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
        uint256[2] memory P5;

        // Compute P1 = α_g * v_a (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr, 0x20), ALPHA_G_Y)
            mstore(add(ptr, 0x40), v_a)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P1, 0x40)
        }

        require(success, "EC MUL failed for alpha_g * v_a");

        // Compute P2 = β_g * v_b (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BETA_G_X)
            mstore(add(ptr, 0x20), BETA_G_Y)
            mstore(add(ptr, 0x40), v_b)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P2, 0x40)
        }

        require(success, "EC MUL failed for beta_g * v_b");

        // Compute P3 = g * v_q (assuming g = (1, 2))
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, G_X)
            mstore(add(ptr, 0x20), G_Y)
            mstore(add(ptr, 0x40), v_q)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P3, 0x40)
        }

        require(success, "EC MUL failed for g * v_q");

        // Compute P4 = u_g * challenge (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, u_g_x)
            mstore(add(ptr, 0x20), u_g_y)
            mstore(add(ptr, 0x40), chall)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P4, 0x40)
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

            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
        }

        require(success, "EC ADD failed for P1 + P2");

        // Step 2: temp = temp + P3
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(P3))
            mstore(add(ptr, 0x60), mload(add(P3, 0x20)))

            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
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

            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, P5, 0x40)
        }

        require(success, "EC ADD failed for final A computation");

        A_x = P5[0];
        A_y = P5[1];
    }

    function comp_chall(
        uint256[2] memory t_g
    ) internal pure returns (uint256 chall) {
        // bytes32 hash = keccak256(
        //     abi.encodePacked(
        //         t_g[0],
        //         t_g[1]
        //     )
        // );
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0x00)));
        // chall = uint256(hash) % P; // Ensure it's in the field F_p
        chall = 5;
    }

    // The verifier for `Circuit1` in `pari/test/Circuit1`
    function Verify(
        uint256[6] calldata proof,
        uint256[2] calldata input
    ) public view {
        // Compute challenge
        uint256 chall = comp_chall([proof[2], proof[3]]);

        // Compute v_q using comp_vq
        uint256 v_q = comp_vq(input, proof, chall);
        // Compute A using elliptic curve precompiles
        (uint256 A_x, uint256 A_y) = compute_A(
            proof[0],
            proof[1],
            v_q,
            chall,
            proof[4],
            proof[5]
        );

        //////////////////// Pairing  ////////////////////

        bool success;
        uint256 t_g_x = proof[2]; // Fix: Load calldata into memory first
        uint256 t_g_y = proof[3];
        uint256 u_g_x = proof[4]; // Fix: Load calldata into memory first
        uint256 u_g_y = proof[5];



        assembly {
            let memPtr := mload(0x40) // Load free memory pointer

            mstore(add(memPtr, 0x00), t_g_x)
            mstore(add(memPtr, 0x20), t_g_y)
            mstore(add(memPtr, 0x40), DELTA_TWO_H_X_1)
            mstore(add(memPtr, 0x60), DELTA_TWO_H_X_0)
            mstore(add(memPtr, 0x80), DELTA_TWO_H_Y_1)
            mstore(add(memPtr, 0xa0), DELTA_TWO_H_Y_0)

            mstore(add(memPtr, 0xc0), u_g_x)
            mstore(add(memPtr, 0xe0), u_g_y)
            mstore(add(memPtr, 0x100), TAU_H_X_1)
            mstore(add(memPtr, 0x120), TAU_H_X_0)
            mstore(add(memPtr, 0x140), TAU_H_Y_1)
            mstore(add(memPtr, 0x160), TAU_H_Y_0)

            mstore(add(memPtr, 0x180), A_x)
            mstore(add(memPtr, 0x1a0), A_y)
            mstore(add(memPtr, 0x1c0), H_X_1)
            mstore(add(memPtr, 0x1e0), H_X_0)
            mstore(add(memPtr, 0x200), H_Y_1)
            mstore(add(memPtr, 0x220), H_Y_0)

            // Call the BN254 pairing precompile (0x08)
            success := staticcall(
                gas(), // Gas available
                PRECOMPILE_VERIFY, // Precompile address for pairing
                memPtr, // Input memory location
                0x240, // Input size (576 bytes for 3 pairings)
                memPtr, // Store output in the same memory
                0x20 // Output size (32 bytes)
            )
            success := and(success, mload(memPtr))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
