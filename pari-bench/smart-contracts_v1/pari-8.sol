// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 8
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
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE = 9965032110155918912136623412538447287666306685604445954519607942272070931612;

        uint256 constant NEG_H_Gi_0 = 8079605893487706465419443248124013553006108151229160788329576673231114902445;
    uint256 constant NEG_H_Gi_1 = 4981661927714195369656200107933285617468833700345499358170854442908401395815;
    uint256 constant NEG_H_Gi_2 = 12440762551542242273675683618383631595954292953999532727115477729156134597367;
    uint256 constant NEG_H_Gi_3 = 14203032153590196571476052885275474146784370782462169257894120140489351277745;
    uint256 constant NEG_H_Gi_4 = 8393779185688740701943912343736700850891451863508419983866565500750504359668;
    uint256 constant NEG_H_Gi_5 = 17326006679871081895464613782037025807377422734460398221932224900581665921391;
    uint256 constant NEG_H_Gi_6 = 17486823114482376850047088023799789670584864047677596911639658200219728329575;
    uint256 constant NEG_H_Gi_7 = 8946720704061042197623031114898853816927375910210892048255120017832951137817;

        uint256 constant NOM_0 = 20041844510009376835323629464069279499422378613991522574440620019567840674298;
    uint256 constant NOM_1 = 4667566155469692870677996955694372562271096528243854467740763856414346944201;
    uint256 constant NOM_2 = 16525156301539667687763557736930738536299072520165726450340426190684800261148;
    uint256 constant NOM_3 = 9847953931277868084353297657878339394035719240427070346028949089173437661600;
    uint256 constant NOM_4 = 14224177736658382751451448295933591680398368239049377783636581575480550746292;
    uint256 constant NOM_5 = 12227528584096160464098920365897658042612476699219208041429413994969353078224;
    uint256 constant NOM_6 = 401778339771593301884378307053060329632716664567267447555763070222336353121;
    uint256 constant NOM_7 = 1302216768086851654201360568465893142950697146548493981961517334187563980205;


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

    // Computes v_q = (v_a^2-v_b)/Z_H(challenge)
    function comp_vq(
        uint256[8] calldata input,
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {

        uint256 neg_cur_elem0 = addmod(chall, NEG_H_Gi_0, R); 

                     uint256 neg_cur_elem0_inv = invert_FR(neg_cur_elem0); 

                     uint256 lagrange_0 = mulmod(neg_cur_elem0_inv, NOM_0, R);
 uint256 neg_cur_elem1 = addmod(chall, NEG_H_Gi_1, R); 

                     uint256 neg_cur_elem1_inv = invert_FR(neg_cur_elem1); 

                     uint256 lagrange_1 = mulmod(neg_cur_elem1_inv, NOM_1, R);
 uint256 neg_cur_elem2 = addmod(chall, NEG_H_Gi_2, R); 

                     uint256 neg_cur_elem2_inv = invert_FR(neg_cur_elem2); 

                     uint256 lagrange_2 = mulmod(neg_cur_elem2_inv, NOM_2, R);
 uint256 neg_cur_elem3 = addmod(chall, NEG_H_Gi_3, R); 

                     uint256 neg_cur_elem3_inv = invert_FR(neg_cur_elem3); 

                     uint256 lagrange_3 = mulmod(neg_cur_elem3_inv, NOM_3, R);
 uint256 neg_cur_elem4 = addmod(chall, NEG_H_Gi_4, R); 

                     uint256 neg_cur_elem4_inv = invert_FR(neg_cur_elem4); 

                     uint256 lagrange_4 = mulmod(neg_cur_elem4_inv, NOM_4, R);
 uint256 neg_cur_elem5 = addmod(chall, NEG_H_Gi_5, R); 

                     uint256 neg_cur_elem5_inv = invert_FR(neg_cur_elem5); 

                     uint256 lagrange_5 = mulmod(neg_cur_elem5_inv, NOM_5, R);
 uint256 neg_cur_elem6 = addmod(chall, NEG_H_Gi_6, R); 

                     uint256 neg_cur_elem6_inv = invert_FR(neg_cur_elem6); 

                     uint256 lagrange_6 = mulmod(neg_cur_elem6_inv, NOM_6, R);
 uint256 neg_cur_elem7 = addmod(chall, NEG_H_Gi_7, R); 

                     uint256 neg_cur_elem7_inv = invert_FR(neg_cur_elem7); 

                     uint256 lagrange_7 = mulmod(neg_cur_elem7_inv, NOM_7, R);


uint256 x_a = addmod(addmod(addmod(mulmod(lagrange_0, input[0], R), mulmod(lagrange_1, input[1], R), R), addmod(mulmod(lagrange_2, input[2], R), mulmod(lagrange_3, input[3], R), R), R), addmod(addmod(mulmod(lagrange_4, input[4], R), mulmod(lagrange_5, input[5], R), R), addmod(mulmod(lagrange_6, input[6], R), mulmod(lagrange_7, input[7], R), R), R), R);

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

    // Computes A = α_g * v_a + β_g * v_b + g * v_q - u_g * challenge
    // This is used in pairing check
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
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr, 0x20), ALPHA_G_Y)
            mstore(add(ptr, 0x40), v_a)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P1, 0x40)
        }

        // Compute P2 = β_g * v_b (scalar multiplication)
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, BETA_G_X)
            mstore(add(ptr, 0x20), BETA_G_Y)
            mstore(add(ptr, 0x40), v_b)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P2, 0x40)
        }

        // Compute P3 = g * v_q (assuming g = (1, 2))
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, G_X)
            mstore(add(ptr, 0x20), G_Y)
            mstore(add(ptr, 0x40), v_q)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P3, 0x40)
        }

        // Compute P4 = u_g * challenge (scalar multiplication)
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, u_g_x)
            mstore(add(ptr, 0x20), u_g_y)
            mstore(add(ptr, 0x40), chall)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P4, 0x40)
        }

        // Compute A = P1 + P2 + P3 - P4 (point addition using ecAdd)
        uint256[2] memory temp;

        // Step 1: temp = P1 + P2
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mload(P1))
            mstore(add(ptr, 0x20), mload(add(P1, 0x20)))
            mstore(add(ptr, 0x40), mload(P2))
            mstore(add(ptr, 0x60), mload(add(P2, 0x20)))

            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
        }

        require(success, "EC ADD failed for P1 + P2");

        // Step 2: temp = temp + P3
        assembly ("memory-safe") {
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
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(P4))
            mstore(add(ptr, 0x60), sub(P, mload(add(P4, 0x20)))) // Negate P4_Y (mod P)

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
        uint256[8] memory input
    ) public pure returns (uint256) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                t_g[0],
                t_g[1],
                input[0],
input[1],
input[2],
input[3],
input[4],
input[5],
input[6],
input[7],

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
        uint256[8] calldata input
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

    