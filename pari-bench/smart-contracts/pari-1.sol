// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 1
contract Pari {
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
    uint256 constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495615; // R - 2

    //////////////////////////////// constants for processing the input //////////////////////////////

    // FFT Coset information
    uint256 constant COSET_SIZE = 4096;
    uint256 constant COSET_OFFSET = 1;

    // Preprocessed intermediate values for computing the lagrande polynomials
    // This computation is done according to https://o1-labs.github.io/proof-systems/plonk/lagrange.html
    uint256 constant MINUS_COSET_OFFSET_TO_COSET_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE = 18054556265820234195946152430238664673837407741942405729392590827829900537638;

        uint256 constant NEG_H_Gi_0 = 4658854783519236281304787251426829785380272013053939496434657852755686889074;

        uint256 constant NOM_0 = 15117197861681116210664999616737025990923645154890205130423708291180769107200;


    ////////////////////////////////////// Preprocessed verification key ////////////////////////////////

    uint256 constant G_X = 19760134438617651871453468315483567841071605526694098053742883504090254514364;
    uint256 constant G_Y = 7793307282958081219582865225040306749427619588777494126095807997225038567914;
    uint256 constant H_X_0 = 15107519626438429753219536593708956924652976791314712957797314020274856024409;
    uint256 constant H_X_1 = 14122693296893380104129524497578004632443439377632543312641053195073048228943;
    uint256 constant H_Y_0 = 3755999432472398517198964599208617491776398181264958893260920167271302869584;
    uint256 constant H_Y_1 = 3628672316656067923136354629391974220973066651561656219744429303673984729133;
    uint256 constant ALPHA_G_X = 17117157057832940174282361915717324730879613848801909474443046625162937924738;
    uint256 constant ALPHA_G_Y = 4912946022067341086926247926576655921713090630212747124179044707234477330213;
    uint256 constant BETA_G_X = 6674938903558993035054571578365883078134800890104980674937713805994918596057;
    uint256 constant BETA_G_Y = 3063729283729914084118689934566456601745586698919252761693132744009991923320;
    uint256 constant TAU_H_X_0 = 19755739294702072308064810597738321137133863011448432042811737477294614186354;
    uint256 constant TAU_H_X_1 = 7402033671645717150240329576186857582846987457652861799749233285030402985398;
    uint256 constant TAU_H_Y_0 = 8088563936954206872933002633932719506006545552370278310585878994482044694722;
    uint256 constant TAU_H_Y_1 = 8755609046364811094992203899104917966328729103809389613205406784809722295327;
    uint256 constant DELTA_TWO_H_X_0 = 8444257463180828655082382641071723106553811213214499031744530464596715083038;
    uint256 constant DELTA_TWO_H_X_1 = 3078227587912202320482865994940325897112751752596849976866904527004632776724;
    uint256 constant DELTA_TWO_H_Y_0 = 1892704013847525363054549589001048916241549423418179546196529832810640362035;
    uint256 constant DELTA_TWO_H_Y_1 = 4052909182836464039553378618668476668081637576194760304751880353526624109889;

    /////////////////////////////////////// Helper functions ////////////////////////////////

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

    // Computes Z_H(challenge) as the vanishing polynomial for the coset
    // Z_H(x) = x^m-h^m
    // where m = COSET_SIZE and h = COSET_OFFSET
    function compute_vanishing_poly(
        uint256 chall
    ) internal view returns (uint256 result) {
        // Exp uses 0x05 precompile internally
        uint256 tau_exp = exp(chall, COSET_SIZE);
        result = addmod(tau_exp, MINUS_COSET_OFFSET_TO_COSET_SIZE, R);
    }

    function batch_invert(uint256[1] memory arr) internal view {
        // 1) forward pass
        uint256 running = 1;
        // We'll store partial_prod products in a separate local array of the same length
        // so we can do the backward pass easily
        uint256[1] memory partial_prod;
        for (uint256 i = 0; i < 1; i++) {
            partial_prod[i] = running; // store partial_prod
            running = mulmod(running, arr[i], R);
        }

        // 2) invert the running product once
        uint256 invRunning = exp(running, EXP_INVERSE_FR); // single exponentiation

        // 3) backward pass
        for (uint256 i = 1; i > 0; ) {
            // i goes from 1 down to 1
            // - 1 => i-1
            unchecked {
                i--;
        }
            // arr[i] = partial_prod[i] * invRunning
            uint256 orig = arr[i];
            arr[i] = mulmod(partial_prod[i], invRunning, R);
            // update invRunning *= orig
            invRunning = mulmod(invRunning, orig, R);
        }
        }


    // Computes v_q = (v_a^2-v_b)/Z_H(challenge)
    function comp_vq(
        uint256[1] calldata input,
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {
        uint256[1] memory denoms;

        denoms[0] = addmod(chall, NEG_H_Gi_0, R);

        batch_invert(denoms);

        uint256 x_a = 0;
        uint256 lag = 0;


                lag = mulmod(denoms[0], NOM_0, R);

        x_a = addmod(x_a, mulmod(lag, input[0], R), R);



        // 4) We then do the usual steps: compute vanish, numerator, etc.
        // vanish = (chall^COSET_SIZE + constant)
        uint256 vanish = compute_vanishing_poly(chall);

        // numerator = ( (proof[0] + x_a)^2 ) - proof[1]
        uint256 numerator = addmod(proof[0], x_a, R);
        numerator = mulmod(numerator, numerator, R);
        numerator = addmod(numerator, R - proof[1], R);

        // vanishInv
        uint256 vanishInv = invert_FR(vanish);

        // v_q
        v_q = mulmod(numerator, vanishInv, R);



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

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr, 0x20), ALPHA_G_Y)
            mstore(add(ptr, 0x40), v_a)
            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P1, 0x40)
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BETA_G_X)
            mstore(add(ptr, 0x20), BETA_G_Y)
            mstore(add(ptr, 0x40), v_b)
            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P2, 0x40)
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, G_X)
            mstore(add(ptr, 0x20), G_Y)
            mstore(add(ptr, 0x40), v_q)
            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P3, 0x40)
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, u_g_x)
            mstore(add(ptr, 0x20), u_g_y)
            mstore(add(ptr, 0x40), chall)
            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P4, 0x40)
        }

        uint256[2] memory temp;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mload(P1))
            mstore(add(ptr, 0x20), mload(add(P1, 0x20)))
            mstore(add(ptr, 0x40), mload(P2))
            mstore(add(ptr, 0x60), mload(add(P2, 0x20)))
            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(P3))
            mstore(add(ptr, 0x60), mload(add(P3, 0x20)))
            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
        }

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(P4))
            mstore(add(ptr, 0x60), sub(P, mload(add(P4, 0x20)))) // Negate Y-coordinate for subtraction
            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, P5, 0x40)
        }

        A_x = P5[0];
        A_y = P5[1];
    }

    // Compute the RO challenge, this is done by hashing all the available public data up to the evaluation step of the verification process
    // This public data includes T_g (Which is the batch commitment and is a part of the proof, i.e. Proof[2:3]), the public input, and the verification key
    // Dues to stack limitation, the input to Keccak256 is split into two parts
    function comp_chall(
        uint256[2] memory t_g,
        uint256[1] memory input
    ) public pure returns (uint256) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                t_g[0],
                t_g[1],
                input[0],

                G_X,
                G_Y,
                ALPHA_G_X,
                ALPHA_G_Y,
                BETA_G_X,
                BETA_G_Y,
                H_X_0,
                H_X_1,
                H_Y_0,
                H_Y_1,
                DELTA_TWO_H_X_0,
                DELTA_TWO_H_X_1,
                DELTA_TWO_H_Y_0,
                DELTA_TWO_H_Y_1,
                TAU_H_X_0,
                TAU_H_X_1,
                TAU_H_Y_0,
                TAU_H_Y_1
            )
        );


        // Compute challenge
        uint256 chall = uint256(hash) % R;

        return chall;
    }

    ///////////////////////// The main verification function of Pari ///////////////////////////

    // The verifier for `Circuit1` in `pari/test/Circuit1`
    function Verify(
        uint256[6] calldata proof,
        uint256[1] calldata input
    ) public view {
        uint256 chall = comp_chall([proof[2], proof[3]], input);
        (uint256 A_x, uint256 A_y) = compute_A(
            proof[0],
            proof[1],
            comp_vq(input, proof, chall),
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

        assembly ("memory-safe") {
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

    