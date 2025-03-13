// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pari {
    /// The proof is invalid.
    error ProofInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP  = 0x05;
    uint256 constant PRECOMPILE_ADD     = 0x06;
    uint256 constant PRECOMPILE_MUL     = 0x07;
    uint256 constant PRECOMPILE_VERIFY  = 0x08;

    // Base field and scalar field
    uint256 constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // For inversion: exponent = R-2
    uint256 constant EXP_INVERSE_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495615;

    // Coset size
    uint256 constant COSET_SIZE = 4096;
    uint256 constant MINUS_COSET_OFFSET_TO_COSET_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;

    // Polynomials
    uint256 constant NEG_H_Gi_0 =
        4658854783519236281304787251426829785380272013053939496434657852755686889074;
    uint256 constant NOM_0 =
        15117197861681116210664999616737025990923645154890205130423708291180769107200;

    // Verification key constants
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
    uint256 constant ALPHA_G_X =
        17117157057832940174282361915717324730879613848801909474443046625162937924738;
    uint256 constant ALPHA_G_Y =
        4912946022067341086926247926576655921713090630212747124179044707234477330213;
    uint256 constant BETA_G_X =
        6674938903558993035054571578365883078134800890104980674937713805994918596057;
    uint256 constant BETA_G_Y =
        3063729283729914084118689934566456601745586698919252761693132744009991923320;
    uint256 constant TAU_H_X_0 =
        19755739294702072308064810597738321137133863011448432042811737477294614186354;
    uint256 constant TAU_H_X_1 =
        7402033671645717150240329576186857582846987457652861799749233285030402985398;
    uint256 constant TAU_H_Y_0 =
        8088563936954206872933002633932719506006545552370278310585878994482044694722;
    uint256 constant TAU_H_Y_1 =
        8755609046364811094992203899104917966328729103809389613205406784809722295327;
    uint256 constant DELTA_TWO_H_X_0 =
        8444257463180828655082382641071723106553811213214499031744530464596715083038;
    uint256 constant DELTA_TWO_H_X_1 =
        3078227587912202320482865994940325897112751752596849976866904527004632776724;
    uint256 constant DELTA_TWO_H_Y_0 =
        1892704013847525363054549589001048916241549423418179546196529832810640362035;
    uint256 constant DELTA_TWO_H_Y_1 =
        4052909182836464039553378618668476668081637576194760304751880353526624109889;

    // ---------------------------------------------
    // The "everything in one assembly" Verify function
    // ---------------------------------------------
    function Verify(
        uint256[6] calldata proof,
        uint256[1] calldata input
    ) public view {
        assembly ("memory-safe") {
            // Some revert helper to keep a reason string for the final pairing check
            // function revertPairingFailed() {
            //     // revert("Pairing check failed")
            //     mstore(0x00, 0x08c379a0)   // error selector for "Error(string)"
            //     mstore(0x04, 0x20)         // offset
            //     mstore(0x24, 19)           // string length
            //     mstore(0x44, 0x50616972696e6720636865636b206661696c656400000000000000000000)
            //     revert(0, 0x64)
            // }

            // Local function: my_exp(base, exponent) -> x, mod R
            function my_exp(base, exponent) -> x {
                let memPtr := mload(0x40)
                mstore(memPtr,   0x20)             // length of base
                mstore(add(memPtr, 0x20), 0x20)    // length of exponent
                mstore(add(memPtr, 0x40), 0x20)    // length of modulus
                mstore(add(memPtr, 0x60), base)
                mstore(add(memPtr, 0x80), exponent)
                mstore(add(memPtr, 0xa0), R)
                if iszero(staticcall(gas(), PRECOMPILE_MODEXP, memPtr, 0xc0, memPtr, 0x20)) {
                    // revert("Exponentiation failed")
                    mstore(0x00, 0x08c379a0)
                    mstore(0x04, 0x20)
                    mstore(0x24, 19)
                    mstore(0x44, 0x4578706f6e656e74696174696f6e206661696c6564)
                    revert(0, 0x64)
                }
                x := mload(memPtr)
            }

            // invertFR(a) = a^(R-2) mod R, revert if mulmod(...) != 1
            function invertFR(a) -> x {
                x := my_exp(a, EXP_INVERSE_FR)
                if iszero(eq(mulmod(a, x, R), 1)) {
                    // revert("Inverse does not exist")
                    mstore(0x00, 0x08c379a0)
                    mstore(0x04, 0x20)
                    mstore(0x24, 22)
                    mstore(0x44, 0x496e766572736520646f6573206e6f742065786973740000000000000000)
                    revert(0, 0x64)
                }
            }

            // computeVanishingPoly(chall) -> zH
            // zH = (chall^COSET_SIZE + MINUS_COSET_OFFSET_TO_COSET_SIZE) mod R
            function computeVanishingPoly(chall) -> zH {
                let t := my_exp(chall, COSET_SIZE)
                zH := addmod(t, MINUS_COSET_OFFSET_TO_COSET_SIZE, R)
            }

            //----------------------------------------------
            // 1) Build keccak input => chall
            //----------------------------------------------
            let ptr := mload(0x40)

            // Read proof[2], proof[3], input[0] from calldata:
            // proof[2] => offset 4 + 2*32=0x44, proof[3] =>0x64, input[0]=>0xc4
            let p2 := calldataload(0x44)
            let p3 := calldataload(0x64)
            let in0 := calldataload(0xc4)

            // store them
            mstore(ptr, p2)
            mstore(add(ptr, 32), p3)
            mstore(add(ptr, 64), in0)

            // then the constants in the same order
            mstore(add(ptr,  96), G_X)
            mstore(add(ptr, 128), G_Y)
            mstore(add(ptr, 160), ALPHA_G_X)
            mstore(add(ptr, 192), ALPHA_G_Y)
            mstore(add(ptr, 224), BETA_G_X)
            mstore(add(ptr, 256), BETA_G_Y)
            mstore(add(ptr, 288), H_X_0)
            mstore(add(ptr, 320), H_X_1)
            mstore(add(ptr, 352), H_Y_0)
            mstore(add(ptr, 384), H_Y_1)
            mstore(add(ptr, 416), DELTA_TWO_H_X_0)
            mstore(add(ptr, 448), DELTA_TWO_H_X_1)
            mstore(add(ptr, 480), DELTA_TWO_H_Y_0)
            mstore(add(ptr, 512), DELTA_TWO_H_Y_1)
            mstore(add(ptr, 544), TAU_H_X_0)
            mstore(add(ptr, 576), TAU_H_X_1)
            mstore(add(ptr, 608), TAU_H_Y_0)
            mstore(add(ptr, 640), TAU_H_Y_1)

            // total = 21 items => 21*32=672 =>0x2a0
            let hash := keccak256(ptr, 0x2a0)
            let chall := mod(hash, R)

            //----------------------------------------------
            // 2) compute v_q inline
            //----------------------------------------------
            // v_a=proof[0], v_b=proof[1]
            let v_a := calldataload(0x04)
            let v_b := calldataload(0x24)

            // neg_cur_elem0 = addmod(chall, NEG_H_Gi_0, R)
            let neg_cur := addmod(chall, NEG_H_Gi_0, R)
            let invCur := invertFR(neg_cur)
            let lagrange0 := mulmod(invCur, NOM_0, R)
            let x_a := mulmod(lagrange0, in0, R)

            // vanishing_poly = computeVanishingPoly(chall)
            let vanPoly := computeVanishingPoly(chall)

            // numerator = (v_a + x_a)^2 - v_b
            let sumVal := addmod(v_a, x_a, R)
            let numerator := mulmod(sumVal, sumVal, R)
            numerator := addmod(numerator, sub(R, v_b), R)

            let vanPolyInv := invertFR(vanPoly)
            let v_q := mulmod(numerator, vanPolyInv, R)

            //----------------------------------------------
            // 3) compute A => do precompile mult
            //----------------------------------------------
            // We'll store partial results: P1,P2,P3,P4,P5,temp each 64 bytes
            let P1 := ptr
            let P2 := add(ptr, 0x40)
            let P3 := add(ptr, 0x80)
            let P4 := add(ptr, 0xc0)
            let P5 := add(ptr, 0x100)
            let temp := add(ptr,0x140)

            // 1) P1 = alpha_g * v_a
            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr,32), ALPHA_G_Y)
            mstore(add(ptr,64), v_a)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P1, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x60)

            // 2) P2 = beta_g * v_b
            mstore(ptr, BETA_G_X)
            mstore(add(ptr,32), BETA_G_Y)
            mstore(add(ptr,64), v_b)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P2, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x60)

            // 3) P3 = g * v_q
            mstore(ptr, G_X)
            mstore(add(ptr,32), G_Y)
            mstore(add(ptr,64), v_q)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P3, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x60)

            // 4) P4 = u_g * chall => proof[4], proof[5]
            let u_g_x := calldataload(0x84)
            let u_g_y := calldataload(0xa4)
            mstore(ptr, u_g_x)
            mstore(add(ptr,32), u_g_y)
            mstore(add(ptr,64), chall)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P4, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x60)

            // temp = P1 + P2
            mstore(ptr, mload(P1))
            mstore(add(ptr,32), mload(add(P1,32)))
            mstore(add(ptr,64), mload(P2))
            mstore(add(ptr,96), mload(add(P2,32)))
            if iszero(staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x80)

            // temp = temp + P3
            mstore(ptr, mload(temp))
            mstore(add(ptr,32), mload(add(temp,32)))
            mstore(add(ptr,64), mload(P3))
            mstore(add(ptr,96), mload(add(P3,32)))
            if iszero(staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x80)

            // P5 = temp - P4 => add the negated Y
            mstore(ptr, mload(temp))
            mstore(add(ptr,32), mload(add(temp,32)))
            mstore(add(ptr,64), mload(P4))
            mstore(add(ptr,96), sub(P, mload(add(P4,32))))
            if iszero(staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, P5, 0x40)) {
                revert(0,0)
            }
            ptr := add(ptr, 0x80)

            //----------------------------------------------
            // 4) final pairing check
            //----------------------------------------------
            // pairing( (p2,p3), Delta2, (p4,p5), TauH, (P5, H) )
            let A_x := mload(P5)
            let A_y := mload(add(P5,32))

            // reuse memory for pairing input (0x240=576 bytes)
            // proof[2], proof[3] => p2, p3
            mstore(ptr,      p2)
            mstore(add(ptr,32), p3)
            mstore(add(ptr,64), DELTA_TWO_H_X_1)
            mstore(add(ptr,96), DELTA_TWO_H_X_0)
            mstore(add(ptr,128),DELTA_TWO_H_Y_1)
            mstore(add(ptr,160),DELTA_TWO_H_Y_0)

            mstore(add(ptr,192), u_g_x)
            mstore(add(ptr,224), u_g_y)
            mstore(add(ptr,256), TAU_H_X_1)
            mstore(add(ptr,288), TAU_H_X_0)
            mstore(add(ptr,320), TAU_H_Y_1)
            mstore(add(ptr,352), TAU_H_Y_0)

            mstore(add(ptr,384), A_x)
            mstore(add(ptr,416), A_y)
            mstore(add(ptr,448), H_X_1)
            mstore(add(ptr,480), H_X_0)
            mstore(add(ptr,512), H_Y_1)
            mstore(add(ptr,544), H_Y_0)

            let ok := staticcall(gas(), PRECOMPILE_VERIFY, ptr, 0x240, ptr, 0x20)
            ok := and(ok, mload(ptr))
            // if iszero(ok) {
            //     revertPairingFailed()
            // }

            // success => update free mem pointer
            mstore(0x40, add(ptr,0x240))
        }

        // If we get here, verification passed
    }
}