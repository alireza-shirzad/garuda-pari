// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Polymath verifier for input size 2
contract Polymath {
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

    //////////////////////////////// constants for processing the input //////////////////////////////
    //TODO: Fix this
    uint256 constant N = 33554432;
    uint256 constant M0_N_INV =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;
    uint256 constant M0 = 2;
    uint256 constant SIGMA = N + 3;
    uint256 constant MINUS_GAMMA = 5;
    uint256 constant MINUS_ALPHA = 5;

    // FFT Coset information
    uint256 constant H_COSET_SIZE = 33554432;
    uint256 constant H_COSET_OFFSET = 1;

    uint256 constant K_COSET_SIZE = 2;
    uint256 constant K_COSET_OFFSET = 1;

    // Preprocessed intermediate values for computing the lagrande polynomials
    // This computation is done according to https://o1-labs.github.io/proof-systems/plonk/lagrange.html
    uint256 constant MINUS_H_COSET_OFFSET_TO_H_COSET_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;
    uint256 constant H_COSET_OFFSET_TO_H_COSET_SIZE_INVERSE =
        8405086447822313838752646273194456000031217045728360237704343779480766987115;

    uint256 constant NEG_H_Gi_0 =
        13326885000311358912287078648031726819564990472170503574014291661505430978205;
    uint256 constant NEG_H_Gi_1 =
        4849392470595825263046812474188855353535321188723106867993138455938662753942;

    uint256 constant NOM_0 =
        14220450601458511673532606231352176427117945320416516159190713724478490024550;
    uint256 constant NOM_1 =
        5548614325997279117816616015086394390005228669711183081159836678771404380761;

    ////////////////////////////////////// Preprocessed verification key ////////////////////////////////

    uint256 constant G_X =
        19760134438617651871453468315483567841071605526694098053742883504090254514364;
    uint256 constant G_Y =
        7793307282958081219582865225040306749427619588777494126095807997225038567914;
    uint256 constant H_X_0 =
        15107519626438429753219536593708956924652976791314712957797314020274856024409;
    uint256 constant H_X_1 =
        14122693296893380104129524497578004632443439377632543312641053195073048228943;
    uint256 constant H_Y_0 =
        3755999432472398517198964599208617491776398181264958893260920167271302869584;
    uint256 constant H_Y_1 =
        3628672316656067923136354629391974220973066651561656219744429303673984729133;
    uint256 constant X_H_X_0 =
        19755739294702072308064810597738321137133863011448432042811737477294614186354;
    uint256 constant X_H_X_1 =
        7402033671645717150240329576186857582846987457652861799749233285030402985398;
    uint256 constant X_H_Y_0 =
        8088563936954206872933002633932719506006545552370278310585878994482044694722;
    uint256 constant X_H_Y_1 =
        8755609046364811094992203899104917966328729103809389613205406784809722295327;
    uint256 constant Z_H_X_0 =
        8444257463180828655082382641071723106553811213214499031744530464596715083038;
    uint256 constant Z_H_X_1 =
        3078227587912202320482865994940325897112751752596849976866904527004632776724;
    uint256 constant Z_H_Y_0 =
        1892704013847525363054549589001048916241549423418179546196529832810640362035;
    uint256 constant Z_H_Y_1 =
        4052909182836464039553378618668476668081637576194760304751880353526624109889;

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
    // where m = H_COSET_SIZE and h = H_COSET_OFFSET
    function compute_domain_normalizer_at_x1(
        uint256 x1
    ) internal view returns (uint256 result) {
        uint256 nom = (R - exp(x1, H_COSET_SIZE) - 1) % R;
        uint256 denom = (R - exp(x1, K_COSET_SIZE) - 1) % R;
        uint256 denom_inv = invert_FR(denom);
        uint256 res = mulmod(nom, denom_inv, R);
        result = mulmod(res, M0_N_INV, R);
    }

    function batch_invert(uint256[2] memory arr) internal view {
        // 1) forward pass
        uint256 running = 1;
        // We'll store partial_prod products in a separate local array of the same length
        // so we can do the backward pass easily
        uint256[2] memory partial_prod;
        for (uint256 i = 0; i < 2; i++) {
            partial_prod[i] = running; // store partial_prod
            running = mulmod(running, arr[i], R);
        }

        // 2) invert the running product once
        uint256 invRunning = exp(running, EXP_INVERSE_FR); // single exponentiation

        // 3) backward pass
        for (uint256 i = 2; i > 0; ) {
            // i goes from 2 down to 1
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

    function compute_pi_at_x1(
        uint256[2] calldata input,
        uint256 x1,
        uint256 y1_to_gamma
    ) internal view returns (uint256 pi_at_x1) {
        uint256[2] memory denoms;

        denoms[0] = addmod(x1, NEG_H_Gi_0, R);
        denoms[1] = addmod(x1, NEG_H_Gi_1, R);

        batch_invert(denoms);

        uint256 x_a = 0;
        uint256 lag = 0;

        lag = mulmod(denoms[0], NOM_0, R);

        x_a = addmod(x_a, mulmod(lag, input[0], R), R);
        lag = mulmod(denoms[1], NOM_1, R);

        x_a = addmod(x_a, mulmod(lag, input[1], R), R);
        pi_at_x1 = mulmod(x_a, y1_to_gamma, R);
    }

    function comp_x1(
        uint256[2] memory a,
        uint256[2] memory c,
        uint256[2] memory input
    ) public pure returns (uint256) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                a[0],
                a[1],
                c[0],
                c[1],
                input[0],
                input[1],
                G_X,
                G_Y,
                H_X_0,
                H_X_1,
                H_Y_0,
                H_Y_1,
                X_H_X_0,
                X_H_X_1,
                X_H_Y_0,
                X_H_Y_1,
                Z_H_X_0,
                Z_H_X_1,
                Z_H_Y_0,
                Z_H_Y_1
            )
        );

        // Compute challenge
        uint256 chall = uint256(hash) % R;

        return chall;
    }

    function comp_x2(uint256 x1, uint256 ax1) public pure returns (uint256) {
        bytes32 hash = keccak256(abi.encodePacked(x1, ax1));
        // Compute challenge
        uint256 chall = uint256(hash) % R;

        return chall;
    }

    ///////////////////////// The main verification function of Polymath ///////////////////////////

    // The verifier for `Circuit1` in `polymath/test/Circuit1`
    function Verify(
        uint256[7] calldata proof,
        uint256[2] calldata input
    ) public view {
        //////////////////// Parsing the proof  ////////////////////

        bool success;
        uint256 a_x = proof[0];
        uint256 a_y = proof[1];
        uint256 c_x = proof[2];
        uint256 c_y = proof[3];
        uint256 ax1 = proof[4];
        uint256 d_x = proof[5];
        uint256 d_y = proof[6];
        //////////////////////// Compute the challenges //////////////
        uint256 x1 = comp_x1([a_x, a_y], [c_x, c_y], input);
        uint256 x2 = comp_x2(x1, ax1);

        //////////////////// Compute some needed variables //////////////
        uint256 y1 = exp(x1, SIGMA);
        uint256 y1_inverse = exp(x1, SIGMA);
        uint256 y1_to_gamma = exp(y1, MINUS_GAMMA);
        uint256 y1_to_minus_alpha = exp(y1_inverse, MINUS_ALPHA);

        ////////////////////// Compute PI(x1) //////////////
        uint256 pi_at_x1 = compute_pi_at_x1(input, x1, y1_to_gamma);
        uint256 domain_normalizer_at_x1 = compute_domain_normalizer_at_x1(x1);
        uint256 normalized_pi_at_x1 = mulmod(
            pi_at_x1,
            domain_normalizer_at_x1,
            R
        );
        // /////////////////// Compute cx1 ///////////////

        uint256 cx1 = addmod(ax1, y1_to_gamma, R);
        cx1 = mulmod(cx1, ax1, R);
        //TODO: Check if subtraction is correct
        cx1 = addmod(cx1, R - normalized_pi_at_x1, R);
        cx1 = mulmod(cx1, y1_to_minus_alpha, R);

        // //////////////////// Compute the left hand side of the first pairing arguemnt //////////////

        uint256[2] memory first_left_2;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, c_x)
            mstore(add(ptr, 0x20), c_y)
            mstore(add(ptr, 0x40), x2)
            success := staticcall(
                gas(),
                PRECOMPILE_MUL,
                ptr,
                0x60,
                first_left_2,
                0x40
            )
        }

        uint256 first_left_3_exp = addmod(ax1, mulmod(x2, cx1, R), R);
        uint256[2] memory first_left_3;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, G_X)
            mstore(add(ptr, 0x20), G_Y)
            mstore(add(ptr, 0x40), first_left_3_exp)
            success := staticcall(
                gas(),
                PRECOMPILE_MUL,
                ptr,
                0x60,
                first_left_3,
                0x40
            )
        }

        uint256[2] memory temp;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, a_x)
            mstore(add(ptr, 0x20), a_y)
            mstore(add(ptr, 0x40), mload(first_left_2))
            mstore(add(ptr, 0x60), mload(add(first_left_2, 0x20)))
            success := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
        }

        uint256[2] memory first_left;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mload(temp))
            mstore(add(ptr, 0x20), mload(add(temp, 0x20)))
            mstore(add(ptr, 0x40), mload(first_left_3))
            mstore(add(ptr, 0x60), mload(add(first_left_3, 0x20)))
            success := staticcall(
                gas(),
                PRECOMPILE_ADD,
                ptr,
                0x80,
                first_left,
                0x40
            )
        }

        // ////////////////////// Compute the pairing  //////////////

        // Compute the x1.G
        uint256[2] memory x1_g;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, G_X)
            mstore(add(ptr, 0x20), G_Y)
            mstore(add(ptr, 0x40), x1)
            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, x1_g, 0x40)
        }
        // Compute -d
        uint256[2] memory minus_d;
        minus_d[0] = d_x;
        minus_d[1] = R - d_y;

        // Compute the multipairing
        assembly ("memory-safe") {
            let memPtr := mload(0x40) // Load free memory pointer

            mstore(add(memPtr, 0x00), first_left)
            mstore(add(memPtr, 0x20), mload(add(first_left, 0x20)))
            mstore(add(memPtr, 0x40), Z_H_X_1)
            mstore(add(memPtr, 0x60), Z_H_X_0)
            mstore(add(memPtr, 0x80), Z_H_Y_1)
            mstore(add(memPtr, 0xa0), Z_H_Y_0)

            mstore(add(memPtr, 0xc0), d_x)
            mstore(add(memPtr, 0xe0), d_y)
            mstore(add(memPtr, 0x100), X_H_X_1)
            mstore(add(memPtr, 0x120), X_H_X_0)
            mstore(add(memPtr, 0x140), X_H_Y_1)
            mstore(add(memPtr, 0x160), X_H_Y_0)

            mstore(add(memPtr, 0x180), mload(minus_d))
            mstore(add(memPtr, 0x1a0), mload(add(minus_d, 0x20)))
            mstore(add(memPtr, 0x1c0), H_X_1)
            mstore(add(memPtr, 0x1e0), H_X_0)
            mstore(add(memPtr, 0x200), H_Y_1)
            mstore(add(memPtr, 0x220), H_Y_0)
            // Call the BN254 pairing precompile (0x08)
            //     success := staticcall(
            //         gas(), // Gas available
            //         PRECOMPILE_VERIFY, // Precompile address for pairing
            //         memPtr, // Input memory location
            //         240, // Input size (576 bytes for 2 pairings)
            //         memPtr, // Store output in the same memory
            //         0x20 // Output size (32 bytes)
            //     )
            //     success := and(success, mload(memPtr))
            // }
            // if (!success) {
            //     // Either proof or verification key invalid.
            //     // We assume the contract is correctly generated, so the verification key is valid.
            //     revert ProofInvalid();
        }
    }
}
