// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Pari verifier for input size 64
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
    uint256 constant COSET_OFFSET_TO_COSET_SIZE_INVERSE = 11347194993091718065046243966023418845395298417436403564330549161691187507473;

        uint256 constant NEG_H_Gi_0 = 306152679900829056086141504258595363518398997114048064065815651945186942758;
    uint256 constant NEG_H_Gi_1 = 2182699283299795909684794160381351560848499343314581443664979651476842494751;
    uint256 constant NEG_H_Gi_2 = 6472863981318646733915884850593245364090579826143664720216047218902831236821;
    uint256 constant NEG_H_Gi_3 = 9088801421649573101014283686030284801466796108869023335878462724291607593530;
    uint256 constant NEG_H_Gi_4 = 12683362046624333915715725390682993077427039231210942616804564282911542924200;
    uint256 constant NEG_H_Gi_5 = 18485221119680322648952465676236615172266828655812812339471785718495551617793;
    uint256 constant NEG_H_Gi_6 = 7451996856915618105697583703156871869888991688145925915877464669984521642606;
    uint256 constant NEG_H_Gi_7 = 21460548446424545059825903513467115425751221113144607680066949763315316496294;
    uint256 constant NEG_H_Gi_8 = 11099103011373818839685046734970287158531712403636294569451121017777026260537;
    uint256 constant NEG_H_Gi_9 = 20052120512685714397389810696004594977669995231943178718536734764237672883765;
    uint256 constant NEG_H_Gi_10 = 16974800396085881485842121082262826019062656508204397864888854869617813885635;
    uint256 constant NEG_H_Gi_11 = 20968676469215405540578045342749426165090334475490530043421232967476022080973;
    uint256 constant NEG_H_Gi_12 = 10735081352256588979614269653811842496388911391341312728785285294676528007919;
    uint256 constant NEG_H_Gi_13 = 7709167398745143316363160291363827613027915960514812156417975121964527188093;
    uint256 constant NEG_H_Gi_14 = 17904030001601903779936267292498026811901593828891759028786389874281770981021;
    uint256 constant NEG_H_Gi_15 = 14879068458267284102382396514308894256441419800779693039134676124482785243120;
    uint256 constant NEG_H_Gi_16 = 15069683166406810118396980299434025198863421369057553153754099813828526101776;
    uint256 constant NEG_H_Gi_17 = 3661602413387243277046903307158321769195503952982136072557948152441520492182;
    uint256 constant NEG_H_Gi_18 = 16319004281183609897523476975997870548121421815417886920930569178145990599328;
    uint256 constant NEG_H_Gi_19 = 16032817356096813969652342882055165387854056276082502592286863041930017366589;
    uint256 constant NEG_H_Gi_20 = 3478871800437630736841186594887503052108079964074319196878750757318422891008;
    uint256 constant NEG_H_Gi_21 = 15427819322379689425329419111224844327424978809243747615642239907504856393000;
    uint256 constant NEG_H_Gi_22 = 5782248482543004090376202923648970867929901935707279359346323659812103745954;
    uint256 constant NEG_H_Gi_23 = 19160213976605953569435474998394518120127348859860305459090210143167354037610;
    uint256 constant NEG_H_Gi_24 = 8859879265385614109665290443010152014855409064267806408815895184562631803200;
    uint256 constant NEG_H_Gi_25 = 4602516023170994308891258506885060348892400947580840296701211877150906589340;
    uint256 constant NEG_H_Gi_26 = 13532745525560388916830961573298389421315956963078582978399696147380974183805;
    uint256 constant NEG_H_Gi_27 = 9240864450953690799657809247329381021160821812151702151115487140630611683793;
    uint256 constant NEG_H_Gi_28 = 8034676956877985466633893884673937030872337074455212930605717174926123026162;
    uint256 constant NEG_H_Gi_29 = 15341497363785227518084706408984882372282986044475559920388693899531302270822;
    uint256 constant NEG_H_Gi_30 = 6496935748147031209159843715101117277138665584387598464387743251495503806288;
    uint256 constant NEG_H_Gi_31 = 14497204362208086511634267186350398411635784140180115858261885881374812445877;
    uint256 constant NEG_H_Gi_32 = 7936326290078006128711977173515482706021795039014249828212492771921230171177;
    uint256 constant NEG_H_Gi_33 = 12783654071702763576586294699555040922577858016749768331403202361559281194470;
    uint256 constant NEG_H_Gi_34 = 8406821777353633441498474214023397629595666447553393900227852362776708025529;
    uint256 constant NEG_H_Gi_35 = 12556247105234630933062265759476741050431407090313217783758742657728319787143;
    uint256 constant NEG_H_Gi_36 = 21202845455497781877679846204268380858622124508313803814830238646470733719219;
    uint256 constant NEG_H_Gi_37 = 9247455193241384735641440019465647095415293415705096978791116758901726499336;
    uint256 constant NEG_H_Gi_38 = 8397305193125568232889607175806224497255386086602200116020406830179862651937;
    uint256 constant NEG_H_Gi_39 = 6470990625610955431683774411739618546270252307008026596162676299817971961806;
    uint256 constant NEG_H_Gi_40 = 1012213022521037145234615145375587845032687603564553275074831172262027304463;
    uint256 constant NEG_H_Gi_41 = 396924529825281969222635796217782617444482904985865175524214939731794364119;
    uint256 constant NEG_H_Gi_42 = 10381780338843625169631260809253968313955312595833903517693476975557410412315;
    uint256 constant NEG_H_Gi_43 = 19602263751751560326623308796757055261699437558932740987671885782620374941638;
    uint256 constant NEG_H_Gi_44 = 20672709383923047848334338061351037155400274680662498714489940810305118383992;
    uint256 constant NEG_H_Gi_45 = 10378998553656474320775588930959982882233003461710741054392940663127059174926;
    uint256 constant NEG_H_Gi_46 = 14856596787726912187586409245831033743433384920594147438014079397503205920775;
    uint256 constant NEG_H_Gi_47 = 6398205404820866886916603106643803960305910182679488590520715116843179019557;
    uint256 constant NEG_H_Gi_48 = 12667328593082887457415193028336882772756821186688020592917227994235922827792;
    uint256 constant NEG_H_Gi_49 = 12929871765897912963061006786216838529932294963252914631917146383032451500661;
    uint256 constant NEG_H_Gi_50 = 20480203125109183901162204778704805290468933619230654535022215952165646385369;
    uint256 constant NEG_H_Gi_51 = 20552643753632295265602709452445764722837155377046144496581457529279444172004;
    uint256 constant NEG_H_Gi_52 = 19151658378259414150596125620849201339245950302384503529268130976581667249028;
    uint256 constant NEG_H_Gi_53 = 17657818268791377739158380278033099629028161476733448961672082344814318974029;
    uint256 constant NEG_H_Gi_54 = 20596708480406953105955564233180882331279416037432992494638724132498525866046;
    uint256 constant NEG_H_Gi_55 = 20480595584519629244941688402570275286760801509777161452176702963608257553140;
    uint256 constant NEG_H_Gi_56 = 15939515425865516176444247236983936512159274870599028265396782531119788163556;
    uint256 constant NEG_H_Gi_57 = 515831470999206376180040179255212025671764116992750770065100806932657979235;
    uint256 constant NEG_H_Gi_58 = 13581772705312050979736186531098927373874316437917098236174453132719663500400;
    uint256 constant NEG_H_Gi_59 = 15838372529020872315254568514785579227855350489076785939486093129850308155928;
    uint256 constant NEG_H_Gi_60 = 6337114218974816571445588245077388176585796745526723227158602200679384076897;
    uint256 constant NEG_H_Gi_61 = 8675217527776771267110788214589133352123611141163375251805290710391577717775;
    uint256 constant NEG_H_Gi_62 = 2037019432901088726757579881322000328933087434404442680258786046983774511114;
    uint256 constant NEG_H_Gi_63 = 20053176473862673770839733921828467609583085375147499723854645825669087182063;

        uint256 constant NOM_0 = 12678585817244807249458519522215882182317473319138010826254054054735575908071;
    uint256 constant NOM_1 = 3706700786451870874822138999340490520462532983440114291859723724501747751190;
    uint256 constant NOM_2 = 2389919713229474793281048300864592187373821925557412552302321353175227209206;
    uint256 constant NOM_3 = 11551089477987118857161133623119593025636642956740740728115485658125880760709;
    uint256 constant NOM_4 = 15400806279498067346545443573512987398664344086501141077427532610788145159772;
    uint256 constant NOM_5 = 17869689058986292564873826691721266749073742848189175395805938727307054586296;
    uint256 constant NOM_6 = 17027916212543217140700911064601578793729471658935448112215159629123398218607;
    uint256 constant NOM_7 = 5111576240937890835538586027041700100284045998050641800741175999019884897397;
    uint256 constant NOM_8 = 5557729241360870264867346097027975648414756244369395706124157481399831067349;
    uint256 constant NOM_9 = 11243384365276979717161560350549347088573260729391074845012731762659807609176;
    uint256 constant NOM_10 = 8513712674677070252521678039618422561946111680164572141755081241656772232290;
    uint256 constant NOM_11 = 9245506126687701289966631778446164656852230554278393232158096915480088898353;
    uint256 constant NOM_12 = 20533426064537224867526913867852812502447757581895705889355673497532111776259;
    uint256 constant NOM_13 = 16682433734855215617581008439863307980368212202136814577982499501280441102500;
    uint256 constant NOM_14 = 21768714277483553506510715699756620018648857816122710867480364621093563793716;
    uint256 constant NOM_15 = 15514330488393793315171150911587568363512622483187629855280889198548795886904;
    uint256 constant NOM_16 = 12288225520391101304764344471114105792863183498821499039036821058925466280828;
    uint256 constant NOM_17 = 17761377455286022420235235053725821811664518087810390076725845212977423943151;
    uint256 constant NOM_18 = 18083076274393982356891324169713754694213558389988119522932495828665640779940;
    uint256 constant NOM_19 = 17784950470389755761131595395460994543632980967991980221414409841842934661887;
    uint256 constant NOM_20 = 3015493229574683002229072649205873425031991725872819736401595405450009221075;
    uint256 constant NOM_21 = 5791707037965710076256104343844337506726094487860950150149947649778325314435;
    uint256 constant NOM_22 = 11348851712973876202367571540488994641617923832196591446530201150101104106070;
    uint256 constant NOM_23 = 11591099148374677159200225960207162008909793981729706962015355637973037979913;
    uint256 constant NOM_24 = 19082900224972261862216378341630124653215092296530620215935155436081043667833;
    uint256 constant NOM_25 = 1781068896127281253396713339517570681189812580445291115632067533284450046325;
    uint256 constant NOM_26 = 11166976705981933836564549564388466108265737166634099130183045344644186249789;
    uint256 constant NOM_27 = 9923894592775422688498039692007637928117400574360533212728871230167516266496;
    uint256 constant NOM_28 = 19026348536564804361286484909017565805247480620603671714767292026166574245308;
    uint256 constant NOM_29 = 5528734631090181701077972851106527303650224696692781301852329339337964413010;
    uint256 constant NOM_30 = 9570556737394018126995568253892349852921051549922362234123510919928735678580;
    uint256 constant NOM_31 = 18926453423207131698957894347575659300891392556112911464072582716582844715366;
    uint256 constant NOM_32 = 8055646841073687373460457361168972940362641319950868350148314623656903203214;
    uint256 constant NOM_33 = 13019534775810539816986474746482565229634395758700186111250059298425100542025;
    uint256 constant NOM_34 = 12974487409908021772463390313531160014267397827855124083885986709255387452943;
    uint256 constant NOM_35 = 10791618164310983115768817028498391023483328658055834773084395004056324675675;
    uint256 constant NOM_36 = 4348237339121709559075854963096519954393524562987123891821518116160990799927;
    uint256 constant NOM_37 = 14258936121919127411711419281171484475255779284836794742160874427938211041501;
    uint256 constant NOM_38 = 3501848782985089220430472708731325160375900993528092883272354694533653427469;
    uint256 constant NOM_39 = 21632936741247940316210039292936434619180192986283604309382438122239495381660;
    uint256 constant NOM_40 = 12279511709894178699473313301393986773545223905526700250339206052962744491089;
    uint256 constant NOM_41 = 13377792152895050527575478924099506961359493753015702523217280444282610249706;
    uint256 constant NOM_42 = 14331488272807864175725305197292854153390788430050840145286819802405002544583;
    uint256 constant NOM_43 = 3688384438114081878946365926591997890116925526223599735456902854111263980228;
    uint256 constant NOM_44 = 14641999406656061588485723839465565413952700797469764801516142555730547992793;
    uint256 constant NOM_45 = 5886611416141296399734557487843580704295853572753016781981258325622890512831;
    uint256 constant NOM_46 = 7225274312202709723301632114630773880616416090790367796648025889989672944603;
    uint256 constant NOM_47 = 7757204998955652345852750761398335253869748625393541272876156589694768298184;
    uint256 constant NOM_48 = 14885361202117058058184318450304135306556423946678928440626312014048457357001;
    uint256 constant NOM_49 = 13046549888648410524483007959242204188241202519348998748264542566976457794283;
    uint256 constant NOM_50 = 14564696248451071895004387921829394411964182993103603413763991728916317056188;
    uint256 constant NOM_51 = 14654265968202267656340951107611404963569551037915988626912851834863119569694;
    uint256 constant NOM_52 = 16357839210011395749794867336486754615596131577678825663932764326053714926289;
    uint256 constant NOM_53 = 9359931427390668919342364245727108574092988352811814351609058714253692844353;
    uint256 constant NOM_54 = 18274059892862060309186252205428407954706134755256206670816610790952994347811;
    uint256 constant NOM_55 = 4732906908014413602977945164210039137661209997063468672503011670567210516616;
    uint256 constant NOM_56 = 6164507204957488065813973181001285466017862126128259804181751195553588147011;
    uint256 constant NOM_57 = 2922711931912044634901407594664681053950356066085037021423620294288688664714;
    uint256 constant NOM_58 = 15173292957672274616942554607777123253346713538713674933638635389207283738750;
    uint256 constant NOM_59 = 12778137464711879172321861597003078334167196861345871820021725090325886077066;
    uint256 constant NOM_60 = 4349525005700321807627690412766584046389529091243214546649057343805964170353;
    uint256 constant NOM_61 = 23804307647166908169291413245111737823717501650182483124295412031503174351;
    uint256 constant NOM_62 = 15780208433966584501442373317534554548386638317739603067472116825899804616207;
    uint256 constant NOM_63 = 12040830530344532254868943200507046815269472790262167339837284828201024220627;


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

    function batch_invert(uint256[64] memory arr) internal view {
        // 1) forward pass
        uint256 running = 1;
        // We'll store partial_prod products in a separate local array of the same length
        // so we can do the backward pass easily
        uint256[64] memory partial_prod;
        for (uint256 i = 0; i < 64; i++) {
            partial_prod[i] = running; // store partial_prod
            running = mulmod(running, arr[i], R);
        }

        // 2) invert the running product once
        uint256 invRunning = exp(running, EXP_INVERSE_FR); // single exponentiation

        // 3) backward pass
        for (uint256 i = 64; i > 0; ) {
            // i goes from 64 down to 1
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
        uint256[64] calldata input,
        uint256[6] calldata proof,
        uint256 chall
    ) internal view returns (uint256 v_q) {
        uint256[64] memory denoms;

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
denoms[32] = addmod(chall, NEG_H_Gi_32, R);
denoms[33] = addmod(chall, NEG_H_Gi_33, R);
denoms[34] = addmod(chall, NEG_H_Gi_34, R);
denoms[35] = addmod(chall, NEG_H_Gi_35, R);
denoms[36] = addmod(chall, NEG_H_Gi_36, R);
denoms[37] = addmod(chall, NEG_H_Gi_37, R);
denoms[38] = addmod(chall, NEG_H_Gi_38, R);
denoms[39] = addmod(chall, NEG_H_Gi_39, R);
denoms[40] = addmod(chall, NEG_H_Gi_40, R);
denoms[41] = addmod(chall, NEG_H_Gi_41, R);
denoms[42] = addmod(chall, NEG_H_Gi_42, R);
denoms[43] = addmod(chall, NEG_H_Gi_43, R);
denoms[44] = addmod(chall, NEG_H_Gi_44, R);
denoms[45] = addmod(chall, NEG_H_Gi_45, R);
denoms[46] = addmod(chall, NEG_H_Gi_46, R);
denoms[47] = addmod(chall, NEG_H_Gi_47, R);
denoms[48] = addmod(chall, NEG_H_Gi_48, R);
denoms[49] = addmod(chall, NEG_H_Gi_49, R);
denoms[50] = addmod(chall, NEG_H_Gi_50, R);
denoms[51] = addmod(chall, NEG_H_Gi_51, R);
denoms[52] = addmod(chall, NEG_H_Gi_52, R);
denoms[53] = addmod(chall, NEG_H_Gi_53, R);
denoms[54] = addmod(chall, NEG_H_Gi_54, R);
denoms[55] = addmod(chall, NEG_H_Gi_55, R);
denoms[56] = addmod(chall, NEG_H_Gi_56, R);
denoms[57] = addmod(chall, NEG_H_Gi_57, R);
denoms[58] = addmod(chall, NEG_H_Gi_58, R);
denoms[59] = addmod(chall, NEG_H_Gi_59, R);
denoms[60] = addmod(chall, NEG_H_Gi_60, R);
denoms[61] = addmod(chall, NEG_H_Gi_61, R);
denoms[62] = addmod(chall, NEG_H_Gi_62, R);
denoms[63] = addmod(chall, NEG_H_Gi_63, R);

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
        lag = mulmod(denoms[32], NOM_32, R);

        x_a = addmod(x_a, mulmod(lag, input[32], R), R);
        lag = mulmod(denoms[33], NOM_33, R);

        x_a = addmod(x_a, mulmod(lag, input[33], R), R);
        lag = mulmod(denoms[34], NOM_34, R);

        x_a = addmod(x_a, mulmod(lag, input[34], R), R);
        lag = mulmod(denoms[35], NOM_35, R);

        x_a = addmod(x_a, mulmod(lag, input[35], R), R);
        lag = mulmod(denoms[36], NOM_36, R);

        x_a = addmod(x_a, mulmod(lag, input[36], R), R);
        lag = mulmod(denoms[37], NOM_37, R);

        x_a = addmod(x_a, mulmod(lag, input[37], R), R);
        lag = mulmod(denoms[38], NOM_38, R);

        x_a = addmod(x_a, mulmod(lag, input[38], R), R);
        lag = mulmod(denoms[39], NOM_39, R);

        x_a = addmod(x_a, mulmod(lag, input[39], R), R);
        lag = mulmod(denoms[40], NOM_40, R);

        x_a = addmod(x_a, mulmod(lag, input[40], R), R);
        lag = mulmod(denoms[41], NOM_41, R);

        x_a = addmod(x_a, mulmod(lag, input[41], R), R);
        lag = mulmod(denoms[42], NOM_42, R);

        x_a = addmod(x_a, mulmod(lag, input[42], R), R);
        lag = mulmod(denoms[43], NOM_43, R);

        x_a = addmod(x_a, mulmod(lag, input[43], R), R);
        lag = mulmod(denoms[44], NOM_44, R);

        x_a = addmod(x_a, mulmod(lag, input[44], R), R);
        lag = mulmod(denoms[45], NOM_45, R);

        x_a = addmod(x_a, mulmod(lag, input[45], R), R);
        lag = mulmod(denoms[46], NOM_46, R);

        x_a = addmod(x_a, mulmod(lag, input[46], R), R);
        lag = mulmod(denoms[47], NOM_47, R);

        x_a = addmod(x_a, mulmod(lag, input[47], R), R);
        lag = mulmod(denoms[48], NOM_48, R);

        x_a = addmod(x_a, mulmod(lag, input[48], R), R);
        lag = mulmod(denoms[49], NOM_49, R);

        x_a = addmod(x_a, mulmod(lag, input[49], R), R);
        lag = mulmod(denoms[50], NOM_50, R);

        x_a = addmod(x_a, mulmod(lag, input[50], R), R);
        lag = mulmod(denoms[51], NOM_51, R);

        x_a = addmod(x_a, mulmod(lag, input[51], R), R);
        lag = mulmod(denoms[52], NOM_52, R);

        x_a = addmod(x_a, mulmod(lag, input[52], R), R);
        lag = mulmod(denoms[53], NOM_53, R);

        x_a = addmod(x_a, mulmod(lag, input[53], R), R);
        lag = mulmod(denoms[54], NOM_54, R);

        x_a = addmod(x_a, mulmod(lag, input[54], R), R);
        lag = mulmod(denoms[55], NOM_55, R);

        x_a = addmod(x_a, mulmod(lag, input[55], R), R);
        lag = mulmod(denoms[56], NOM_56, R);

        x_a = addmod(x_a, mulmod(lag, input[56], R), R);
        lag = mulmod(denoms[57], NOM_57, R);

        x_a = addmod(x_a, mulmod(lag, input[57], R), R);
        lag = mulmod(denoms[58], NOM_58, R);

        x_a = addmod(x_a, mulmod(lag, input[58], R), R);
        lag = mulmod(denoms[59], NOM_59, R);

        x_a = addmod(x_a, mulmod(lag, input[59], R), R);
        lag = mulmod(denoms[60], NOM_60, R);

        x_a = addmod(x_a, mulmod(lag, input[60], R), R);
        lag = mulmod(denoms[61], NOM_61, R);

        x_a = addmod(x_a, mulmod(lag, input[61], R), R);
        lag = mulmod(denoms[62], NOM_62, R);

        x_a = addmod(x_a, mulmod(lag, input[62], R), R);
        lag = mulmod(denoms[63], NOM_63, R);

        x_a = addmod(x_a, mulmod(lag, input[63], R), R);



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
        uint256[64] memory input
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
input[32],
input[33],
input[34],
input[35],
input[36],
input[37],
input[38],
input[39],
input[40],
input[41],
input[42],
input[43],
input[44],
input[45],
input[46],
input[47],
input[48],
input[49],
input[50],
input[51],
input[52],
input[53],
input[54],
input[55],
input[56],
input[57],
input[58],
input[59],
input[60],
input[61],
input[62],
input[63],

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
        uint256[64] calldata input
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

    