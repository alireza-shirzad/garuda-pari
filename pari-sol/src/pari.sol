// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 32
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
    uint256 constant COSET_SIZE = 8192;
    uint256 constant COSET_OFFSET = 1;

    // Preprocessed intermediate values for computing the lagrande polynomials
    // This computation is done according to https://o1-labs.github.io/proof-systems/plonk/lagrange.html
    uint256 constant MINUS_COSET_OFFSET_TO_COSET_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE = 11747009059618832746382481016144469544869765606533829122607677336248821316720;

        uint256 constant NEG_H_Gi_0 = 7960915511780528367277157905446844123500829388569991084559361711479039322207;
    uint256 constant NEG_H_Gi_1 = 14989126023867151156171307775100055264583145823322822447155468504172591483418;
    uint256 constant NEG_H_Gi_2 = 6731165095968120576731890203512250144135197325454534934136795548922523772811;
    uint256 constant NEG_H_Gi_3 = 3478517300119284901893091970156912948790432420133812234316178878452092729974;
    uint256 constant NEG_H_Gi_4 = 2214682338792630021038515253076569153145672745944538753096934421471413827950;
    uint256 constant NEG_H_Gi_5 = 11429882295878902992676286393866102414087839115021170513670286626371843302178;
    uint256 constant NEG_H_Gi_6 = 18961514692108238385716145922373675894689857907291733126339276937743427255472;
    uint256 constant NEG_H_Gi_7 = 10284794029950114870720111219548260578895246569212151122770212680848196912459;
    uint256 constant NEG_H_Gi_8 = 2316666857619008916583617305520242139486424334524415377886092669331941976708;
    uint256 constant NEG_H_Gi_9 = 21782066678107774213783701546925669789264816346384907590715650928652764536484;
    uint256 constant NEG_H_Gi_10 = 4373726634667394541340262120794216720752172374696246339961257148201066152830;
    uint256 constant NEG_H_Gi_11 = 4181869544145721538458247542859579030174847694655087478064411097601949636938;
    uint256 constant NEG_H_Gi_12 = 419524410649023461587794201182770936266552239200293722585064706813337651514;
    uint256 constant NEG_H_Gi_13 = 13684858221575877444035877088432410635659962814610886845186227164009321244619;
    uint256 constant NEG_H_Gi_14 = 15684219865672502007432956108530818219718256541510116531356613681198371239173;
    uint256 constant NEG_H_Gi_15 = 12902113644630614262983130712380002620066504174871945726138072959421273229826;
    uint256 constant NEG_H_Gi_16 = 16676267524561775998856413954782916321757297859341949978436436449105378237776;
    uint256 constant NEG_H_Gi_17 = 6969639281561709021057520087052923507200133143177490686394175508453887741581;
    uint256 constant NEG_H_Gi_18 = 1801134504048034600894585668091417479364901233113579610262424767652700268537;
    uint256 constant NEG_H_Gi_19 = 8312391202049336565780914761868109660621252673211382626986247561330092866159;
    uint256 constant NEG_H_Gi_20 = 6703895078210426959677547974343085354399421855641410594578922112783288652888;
    uint256 constant NEG_H_Gi_21 = 3306298829614037125864334192671993227105504878629516338853722726973443720655;
    uint256 constant NEG_H_Gi_22 = 281289026870275153961424811659906573307982743404302408402265471298603232925;
    uint256 constant NEG_H_Gi_23 = 12391241529990809961228699275154223409952982288366329851335585853532229080656;
    uint256 constant NEG_H_Gi_24 = 246360232014005015036819967383670699412609093114586134927896558722733566530;
    uint256 constant NEG_H_Gi_25 = 5987472916485514324754411301897089357532733985439143268595911735850228467301;
    uint256 constant NEG_H_Gi_26 = 14416119953731567799770933764389386444838702860602256833037503729873189488746;
    uint256 constant NEG_H_Gi_27 = 7020877352033153652855433461334427673938254807542999009891051633369964442773;
    uint256 constant NEG_H_Gi_28 = 17589156939601269955942272147966341431243993907126324624631257137141306099469;
    uint256 constant NEG_H_Gi_29 = 8240032726095680281171677742430810121231766911368514118685361935905917900183;
    uint256 constant NEG_H_Gi_30 = 21204441470125362600670751974827650332411552074710752056934538950445053933985;
    uint256 constant NEG_H_Gi_31 = 20415904760389140577477728769620865747370887243148859002679921665808700210270;

        uint256 constant NOM_0 = 10983922237817231892716529350906304008323009008181198866229498599627544228734;
    uint256 constant NOM_1 = 9091935997739052751545774409542779956652662953850062590210331128132226763325;
    uint256 constant NOM_2 = 10846624376253289769235957349908704001384979083308283582118837250273051122258;
    uint256 constant NOM_3 = 10565301885416413661623954506765870378268139979103580393784549115386985947140;
    uint256 constant NOM_4 = 13920299026694187720819625176231636357769066142835801042181216548170359748825;
    uint256 constant NOM_5 = 10944834441717922075145901421950855166244733210886259104176913048583034313379;
    uint256 constant NOM_6 = 15615757928051846183206933392004838412441702423268188263645420364746820023669;
    uint256 constant NOM_7 = 3350273119885248057838154326466036128806860423439533647020497401558816695532;
    uint256 constant NOM_8 = 13900595564799494050118013138443570001331486830986911868444115623217906677205;
    uint256 constant NOM_9 = 10206430109772385962359738159320972393028778339283991918505732694442957762716;
    uint256 constant NOM_10 = 654917903940021525359892635194242494429817201662877075483846024265735821101;
    uint256 constant NOM_11 = 5177783030523998969124465826119116001617941347086915034784603745982674954690;
    uint256 constant NOM_12 = 19687846318392647547833565974919841447016270581884124208216527170445534057774;
    uint256 constant NOM_13 = 20833824196118402680215562615562900973868822346742250683912064105962804146347;
    uint256 constant NOM_14 = 4943700188164680349716628432288839479224625654064688082632434510756447956901;
    uint256 constant NOM_15 = 3877807981297725620390020352672715255232024105049212814126945066450084250062;
    uint256 constant NOM_16 = 13003497155328422443879915920723672397554685361008837431055505198839035324357;
    uint256 constant NOM_17 = 15432087200978319716946623733141338014688523378748440185810669873903774443757;
    uint256 constant NOM_18 = 6471351339232887342844060135188358458492073792461242685222118950718658541827;
    uint256 constant NOM_19 = 6325742897703055777315874577897333411868160712155635048824902734151967179639;
    uint256 constant NOM_20 = 12926164375987963776833101838441147707856148882229429392674888967624157095769;
    uint256 constant NOM_21 = 5964497930155099256706068603596452596915747936203945745704520761100751614166;
    uint256 constant NOM_22 = 18104458579615054868332198239294495682303164337009758957807707936515704267713;
    uint256 constant NOM_23 = 5871737379002571068492076624358817128664085931460848522310862624669961898717;
    uint256 constant NOM_24 = 20800532953244236973058619101906046325859698811560451913347505061946572233310;
    uint256 constant NOM_25 = 6642501480563198365719184476527134297399826495556524489891517854536098404313;
    uint256 constant NOM_26 = 8419740911414796960596984630827724616444345867688616308424314951060593562535;
    uint256 constant NOM_27 = 5978720676460501830124268356584784428927532338494023873844335432417689714074;
    uint256 constant NOM_28 = 2521169322599559321815694708953321123734035517190918632126390369570304306919;
    uint256 constant NOM_29 = 2203173301831349290696776787708503487668130650810775256783866557980215330914;
    uint256 constant NOM_30 = 12924864599460304567434412085103509632280965192780357209979452733180433525483;
    uint256 constant NOM_31 = 450842944868797719505160066679795481091873504143581135126981106259925144626;


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

    function batch_invert(uint256[32] memory arr) internal view {
        // 1) forward pass
        uint256 running = 1;
        // We'll store partial_prod products in a separate local array of the same length
        // so we can do the backward pass easily
        uint256[32] memory partial_prod;
        for (uint256 i = 0; i < 32; i++) {
            partial_prod[i] = running; // store partial_prod
            running = mulmod(running, arr[i], R);
        }

        // 2) invert the running product once
        uint256 invRunning = exp(running, EXP_INVERSE_FR); // single exponentiation

        // 3) backward pass
        for (uint256 i = 32; i > 0; ) {
            // i goes from 32 down to 1
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
        uint256[32] calldata input,
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {
        uint256[32] memory denoms;

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
denoms[16] = addmod(chall, NEG_H_Gi_16, R);
denoms[17] = addmod(chall, NEG_H_Gi_17, R);
denoms[18] = addmod(chall, NEG_H_Gi_18, R);
denoms[19] = addmod(chall, NEG_H_Gi_19, R);
denoms[20] = addmod(chall, NEG_H_Gi_20, R);
denoms[21] = addmod(chall, NEG_H_Gi_21, R);
denoms[22] = addmod(chall, NEG_H_Gi_22, R);
denoms[23] = addmod(chall, NEG_H_Gi_23, R);
denoms[24] = addmod(chall, NEG_H_Gi_24, R);
denoms[25] = addmod(chall, NEG_H_Gi_25, R);
denoms[26] = addmod(chall, NEG_H_Gi_26, R);
denoms[27] = addmod(chall, NEG_H_Gi_27, R);
denoms[28] = addmod(chall, NEG_H_Gi_28, R);
denoms[29] = addmod(chall, NEG_H_Gi_29, R);
denoms[30] = addmod(chall, NEG_H_Gi_30, R);
denoms[31] = addmod(chall, NEG_H_Gi_31, R);

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
        lag = mulmod(denoms[16], NOM_16, R);

        x_a = addmod(x_a, mulmod(lag, input[16], R), R);
        lag = mulmod(denoms[17], NOM_17, R);

        x_a = addmod(x_a, mulmod(lag, input[17], R), R);
        lag = mulmod(denoms[18], NOM_18, R);

        x_a = addmod(x_a, mulmod(lag, input[18], R), R);
        lag = mulmod(denoms[19], NOM_19, R);

        x_a = addmod(x_a, mulmod(lag, input[19], R), R);
        lag = mulmod(denoms[20], NOM_20, R);

        x_a = addmod(x_a, mulmod(lag, input[20], R), R);
        lag = mulmod(denoms[21], NOM_21, R);

        x_a = addmod(x_a, mulmod(lag, input[21], R), R);
        lag = mulmod(denoms[22], NOM_22, R);

        x_a = addmod(x_a, mulmod(lag, input[22], R), R);
        lag = mulmod(denoms[23], NOM_23, R);

        x_a = addmod(x_a, mulmod(lag, input[23], R), R);
        lag = mulmod(denoms[24], NOM_24, R);

        x_a = addmod(x_a, mulmod(lag, input[24], R), R);
        lag = mulmod(denoms[25], NOM_25, R);

        x_a = addmod(x_a, mulmod(lag, input[25], R), R);
        lag = mulmod(denoms[26], NOM_26, R);

        x_a = addmod(x_a, mulmod(lag, input[26], R), R);
        lag = mulmod(denoms[27], NOM_27, R);

        x_a = addmod(x_a, mulmod(lag, input[27], R), R);
        lag = mulmod(denoms[28], NOM_28, R);

        x_a = addmod(x_a, mulmod(lag, input[28], R), R);
        lag = mulmod(denoms[29], NOM_29, R);

        x_a = addmod(x_a, mulmod(lag, input[29], R), R);
        lag = mulmod(denoms[30], NOM_30, R);

        x_a = addmod(x_a, mulmod(lag, input[30], R), R);
        lag = mulmod(denoms[31], NOM_31, R);

        x_a = addmod(x_a, mulmod(lag, input[31], R), R);



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
        uint256[32] memory input
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
input[16],
input[17],
input[18],
input[19],
input[20],
input[21],
input[22],
input[23],
input[24],
input[25],
input[26],
input[27],
input[28],
input[29],
input[30],
input[31],

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
        uint256[32] calldata input
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

    