// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 16
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
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE = 18574728712703342382468304726644321675499157051772581279854338724568844915692;

        uint256 constant NEG_H_Gi_0 = 17435385924875514206545592299168736157342584446790124633336572929350793635775;
    uint256 constant NEG_H_Gi_1 = 16211590536225191417031113770455059651342958034816077726842228382428518412489;
    uint256 constant NEG_H_Gi_2 = 19577543728477085273119264950929009729995778579804563653429754522577822571795;
    uint256 constant NEG_H_Gi_3 = 7280260855168663458014580474386187104499049629108863450633988962192467561003;
    uint256 constant NEG_H_Gi_4 = 11831404157783916412129778999734528385991290020289373642752100759217681467803;
    uint256 constant NEG_H_Gi_5 = 15014055153973496876148321139254258105527252913759832319177414032014014571289;
    uint256 constant NEG_H_Gi_6 = 7735038603608633004372973129623088122651468970435314054492854426661430068351;
    uint256 constant NEG_H_Gi_7 = 4328467529464431663573211246882225826664797424125109236582242625967239358240;
    uint256 constant NEG_H_Gi_8 = 13525867520835474970480132386116697814398522203388406067427930322684607857779;
    uint256 constant NEG_H_Gi_9 = 11151148604753929324964617175144095785201977170673120043590103477027223526562;
    uint256 constant NEG_H_Gi_10 = 11402241986229940588183806966511831483742642211623532394041645710508401236073;
    uint256 constant NEG_H_Gi_11 = 17434075727859231943494356590950808414265320884531652929726133310812979511731;
    uint256 constant NEG_H_Gi_12 = 3198299320091003838305577816381426212542726647049241598649137265546033876128;
    uint256 constant NEG_H_Gi_13 = 5539167756466398758977672375255152735237828739538692561794035511222537325072;
    uint256 constant NEG_H_Gi_14 = 11041511419023089680936447598386440963609272232399221596085093562666574710216;
    uint256 constant NEG_H_Gi_15 = 9109943995669496816017608531830393155749561038998402231467954739813243564944;

        uint256 constant NOM_0 = 17964257411686003802795731282848237981982832970872415492580560546936294336006;
    uint256 constant NOM_1 = 17085887458441529745625019176705208451934455650037114642015185423278218910244;
    uint256 constant NOM_2 = 11065302684399548677067244645649630704456004862364665706128697605262972382106;
    uint256 constant NOM_3 = 2202210674068557888204484930674404959669707494313903739424407198717938752383;
    uint256 constant NOM_4 = 21202402579390942706636782683418681267451561407420297223372539479050872390936;
    uint256 constant NOM_5 = 8828014715410977312317484512072917771085378878162435115622482790896380667470;
    uint256 constant NOM_6 = 2075082176593536079835087867889880474363849307463265138282443844886668376302;
    uint256 constant NOM_7 = 14454847963844548969462882720745627263064588666965143787055837536025041319421;
    uint256 constant NOM_8 = 9844108560268706355755109343130628089940089776631966404462808273861054892195;
    uint256 constant NOM_9 = 19662032383862002186227054148472775566092711655889907514384643140554048776542;
    uint256 constant NOM_10 = 11261166492500504290023412367437712950026348470048270949279400239792893276482;
    uint256 constant NOM_11 = 682429869676273881537724530397930771589468376525620849579347712721814167824;
    uint256 constant NOM_12 = 20606296009553497626375685456971450713739317931112346850156631796082234656501;
    uint256 constant NOM_13 = 21053011056787287387156584738874290161504500072178257379096858692992407114218;
    uint256 constant NOM_14 = 4805675202162281757232183514961932146861578169382868080246794674833228000267;
    uint256 constant NOM_15 = 13221142871714663926060010334176157828668696727166667822343563651337235934202;


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

    function batch_invert(uint256[16] memory arr) internal view {
        // 1) forward pass
        uint256 running = 1;
        // We'll store partial_prod products in a separate local array of the same length
        // so we can do the backward pass easily
        uint256[16] memory partial_prod;
        for (uint256 i = 0; i < 16; i++) {
            partial_prod[i] = running; // store partial_prod
            running = mulmod(running, arr[i], R);
        }

        // 2) invert the running product once
        uint256 invRunning = exp(running, EXP_INVERSE_FR); // single exponentiation

        // 3) backward pass
        for (uint256 i = 16; i > 0; ) {
            // i goes from 16 down to 1
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
        uint256[16] calldata input,
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {
        uint256[16] memory denoms;

        denoms[0] = addmod(chall, NEG_H_Gi_0, R);
denoms[1] = addmod(chall, NEG_H_Gi_1, R);
denoms[2] = addmod(chall, NEG_H_Gi_2, R);
denoms[3] = addmod(chall, NEG_H_Gi_3, R);
denoms[4] = addmod(chall, NEG_H_Gi_4, R);
denoms[5] = addmod(chall, NEG_H_Gi_5, R);
denoms[6] = addmod(chall, NEG_H_Gi_6, R);
denoms[7] = addmod(chall, NEG_H_Gi_7, R);
denoms[8] = addmod(chall, NEG_H_Gi_8, R);
denoms[9] = addmod(chall, NEG_H_Gi_9, R);
denoms[10] = addmod(chall, NEG_H_Gi_10, R);
denoms[11] = addmod(chall, NEG_H_Gi_11, R);
denoms[12] = addmod(chall, NEG_H_Gi_12, R);
denoms[13] = addmod(chall, NEG_H_Gi_13, R);
denoms[14] = addmod(chall, NEG_H_Gi_14, R);
denoms[15] = addmod(chall, NEG_H_Gi_15, R);

        batch_invert(denoms);

        uint256 x_a = 0;
        uint256 lag = 0;


                lag = mulmod(denoms[0], NOM_0, R);

        x_a = addmod(x_a, mulmod(lag, input[0], R), R);
        lag = mulmod(denoms[1], NOM_1, R);

        x_a = addmod(x_a, mulmod(lag, input[1], R), R);
        lag = mulmod(denoms[2], NOM_2, R);

        x_a = addmod(x_a, mulmod(lag, input[2], R), R);
        lag = mulmod(denoms[3], NOM_3, R);

        x_a = addmod(x_a, mulmod(lag, input[3], R), R);
        lag = mulmod(denoms[4], NOM_4, R);

        x_a = addmod(x_a, mulmod(lag, input[4], R), R);
        lag = mulmod(denoms[5], NOM_5, R);

        x_a = addmod(x_a, mulmod(lag, input[5], R), R);
        lag = mulmod(denoms[6], NOM_6, R);

        x_a = addmod(x_a, mulmod(lag, input[6], R), R);
        lag = mulmod(denoms[7], NOM_7, R);

        x_a = addmod(x_a, mulmod(lag, input[7], R), R);
        lag = mulmod(denoms[8], NOM_8, R);

        x_a = addmod(x_a, mulmod(lag, input[8], R), R);
        lag = mulmod(denoms[9], NOM_9, R);

        x_a = addmod(x_a, mulmod(lag, input[9], R), R);
        lag = mulmod(denoms[10], NOM_10, R);

        x_a = addmod(x_a, mulmod(lag, input[10], R), R);
        lag = mulmod(denoms[11], NOM_11, R);

        x_a = addmod(x_a, mulmod(lag, input[11], R), R);
        lag = mulmod(denoms[12], NOM_12, R);

        x_a = addmod(x_a, mulmod(lag, input[12], R), R);
        lag = mulmod(denoms[13], NOM_13, R);

        x_a = addmod(x_a, mulmod(lag, input[13], R), R);
        lag = mulmod(denoms[14], NOM_14, R);

        x_a = addmod(x_a, mulmod(lag, input[14], R), R);
        lag = mulmod(denoms[15], NOM_15, R);

        x_a = addmod(x_a, mulmod(lag, input[15], R), R);



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
        uint256[16] memory input
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
input[8],
input[9],
input[10],
input[11],
input[12],
input[13],
input[14],
input[15],

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
        uint256[16] calldata input
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

    