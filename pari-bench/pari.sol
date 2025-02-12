// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 2
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
    uint256 constant P = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787;
    uint256 constant R = 52435875175126190479447740508185965837690552500527637822603658699938581184513;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FR = 52435875175126190479447740508185965837690552500527637822603658699938581184511; // R - 2

    //////////////////////////////// constants for processing the input //////////////////////////////

    // FFT Coset information
    uint256 constant COSET_SIZE = 16;
    uint256 constant COSET_OFFSET = 1;

    // Preprocessed intermediate values for computing the lagrande polynomials
    // This computation is done according to https://o1-labs.github.io/proof-systems/plonk/lagrange.html
    uint256 constant MINUS_COSET_OFFSET_TO_COSET_SIZE = 52435875175126190479447740508185965837690552500527637822603658699938581184512;
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE = 8428356928836461080698194096363261455131944012505496372152069217659203927348;

        uint256 constant NEG_H_Gi_0 = 36778637658359875386191427521799144323339218770729793579985470490234698174701;
    uint256 constant NEG_H_Gi_1 = 33923620635880093435197881356488220169110847130123043063181396935206100924630;

        uint256 constant NOM_0 = 20547331026234864512205796021477798782567127223727544863312747872571191105997;
    uint256 constant NOM_1 = 46746022065573126323190565375469995393161334296728713724967295506164833827995;


    ////////////////////////////////////// Preprocessed verification key ////////////////////////////////

    uint256 constant G_X = 1290022321203963772128330736443540044122488336450569469040438148402680195147630954730578641028026931409605384848210;
    uint256 constant G_Y = 1695942484656505052417240533760236781757104478830485370728788163465821689743043273185613256283060773145153626102892;
    uint256 constant H_X_0 = 377234751025885235092652518577955332465306714888645453308439032064800296938418199706613419715196309212619497779388;
    uint256 constant H_X_1 = 3135549632826895925582979901664322719786888598778472366790637798403359003162919890389383996220045584659367279400472;
    uint256 constant H_Y_0 = 390922676746401579315876509906215469388504567985829321695601642557749904156777758695713633512726119584045649845214;
    uint256 constant H_Y_1 = 103149831337215166543402392169268778980391899166795465619753804270799213740233559036255270428963281424773278553287;
    uint256 constant ALPHA_G_X = 1084986620591109623773086481283475183375700581507818835013826968624161923022747497318006891464889518426084890231915;
    uint256 constant ALPHA_G_Y = 447014098867037364773360622850524601450852131542330041452421152384387355815446309717705415540058931851402096722124;
    uint256 constant BETA_G_X = 442642969088062434182304578315640219876644333213991933907115007748719474936165093204977471768210338634794544690780;
    uint256 constant BETA_G_Y = 2797314136354365602241605941162129496841434896630222342815388629345908284172276261768928882305971893249345801211242;
    uint256 constant TAU_H_X_0 = 1803186162298383441453315273874823088721350087615090475315366541595744566404215008102548875284126317695153716184210;
    uint256 constant TAU_H_X_1 = 2506048255844661935599655087680935417950104235321477314038693835650349267326666697916731061488433747803934347915360;
    uint256 constant TAU_H_Y_0 = 2492140046900855955860247035764533194580046419590438100803305019824966055137894736863743058777941802371985020646002;
    uint256 constant TAU_H_Y_1 = 1952848033977629460277957107698286010555530074306034023662835967416826657258352664028238743585110637537877358903568;
    uint256 constant DELTA_TWO_H_X_0 = 344139955478100243590819312255353937771810065545646206183423247007329261258046897906776261626726562195040554364777;
    uint256 constant DELTA_TWO_H_X_1 = 910459110578565108863004015048825637178202066453981858575139725630079466671375266387374430267810287567016977479975;
    uint256 constant DELTA_TWO_H_Y_0 = 3812619526112507662630118632350408709573564625391410111696882468760108541987931976204047785827442102143180931566268;
    uint256 constant DELTA_TWO_H_Y_1 = 1047468057972525084115375499561863472428588811990107339227738852897617125053406861437618577226220604000695878373541;

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
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr, 0x20), ALPHA_G_Y)
            mstore(add(ptr, 0x40), v_a)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P1, 0x40)
        }

        // Compute P2 = β_g * v_b (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, BETA_G_X)
            mstore(add(ptr, 0x20), BETA_G_Y)
            mstore(add(ptr, 0x40), v_b)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P2, 0x40)
        }

        // Compute P3 = g * v_q (assuming g = (1, 2))
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, G_X)
            mstore(add(ptr, 0x20), G_Y)
            mstore(add(ptr, 0x40), v_q)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P3, 0x40)
        }

        // Compute P4 = u_g * challenge (scalar multiplication)
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, u_g_x)
            mstore(add(ptr, 0x20), u_g_y)
            mstore(add(ptr, 0x40), chall)

            success := staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P4, 0x40)
        }

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

        A_x = P5[0];
        A_y = P5[1];
    }

    // Compute the RO challenge, this is done by hashing all the available public data up to the evaluation step of the verification process
    // This public data includes T_g (Which is the batch commitment and is a part of the proof, i.e. Proof[2:3]), the public input, and the verification key
    // Dues to stack limitation, the input to Keccak256 is split into two parts
    function comp_chall(
        uint256[2] memory t_g,
        uint256[2] memory input
    ) public pure returns (uint256) {
        // Encode the first part
        bytes memory part1 = abi.encodePacked(
            t_g[0],
            t_g[1],
            input[0],
            input[1],
            G_X,
            G_Y,
            ALPHA_G_X,
            ALPHA_G_Y,
            BETA_G_X,
            BETA_G_Y
        );

        // Encode the second part
        bytes memory part2 = abi.encodePacked(
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
        );

        // Compute Keccak-256 hash
        bytes32 hash = keccak256(abi.encodePacked(part1, part2));

        // Compute challenge
        uint256 chall = uint256(hash) % R;

        return chall;
    }

    ///////////////////////// The main verification function of Pari ///////////////////////////

    // The verifier for `Circuit1` in `pari/test/Circuit1`
    function Verify(
        uint256[6] calldata proof,
        uint256[2] calldata input
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

    