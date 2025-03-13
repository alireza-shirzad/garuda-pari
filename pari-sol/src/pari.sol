// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Pari {
    /// The proof is invalid.
    error ProofInvalid();

    // BN254 precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Fields
    uint256 constant P =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // For inversion in Fr
    uint256 constant EXP_INVERSE_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495615;

    // Coset size etc.
    uint256 constant COSET_SIZE = 8192;
    uint256 constant MINUS_COSET_OFFSET_TO_COSET_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495616;

    // 64 constants for NEG_H_Gi_i
    uint256 constant NEG_H_Gi_0 =
        306152679900829056086141504258595363518398997114048064065815651945186942758;
    uint256 constant NEG_H_Gi_1 =
        2182699283299795909684794160381351560848499343314581443664979651476842494751;
    uint256 constant NEG_H_Gi_2 =
        6472863981318646733915884850593245364090579826143664720216047218902831236821;
    uint256 constant NEG_H_Gi_3 =
        9088801421649573101014283686030284801466796108869023335878462724291607593530;
    uint256 constant NEG_H_Gi_4 =
        12683362046624333915715725390682993077427039231210942616804564282911542924200;
    uint256 constant NEG_H_Gi_5 =
        18485221119680322648952465676236615172266828655812812339471785718495551617793;
    uint256 constant NEG_H_Gi_6 =
        7451996856915618105697583703156871869888991688145925915877464669984521642606;
    uint256 constant NEG_H_Gi_7 =
        21460548446424545059825903513467115425751221113144607680066949763315316496294;
    uint256 constant NEG_H_Gi_8 =
        11099103011373818839685046734970287158531712403636294569451121017777026260537;
    uint256 constant NEG_H_Gi_9 =
        20052120512685714397389810696004594977669995231943178718536734764237672883765;
    uint256 constant NEG_H_Gi_10 =
        16974800396085881485842121082262826019062656508204397864888854869617813885635;
    uint256 constant NEG_H_Gi_11 =
        20968676469215405540578045342749426165090334475490530043421232967476022080973;
    uint256 constant NEG_H_Gi_12 =
        10735081352256588979614269653811842496388911391341312728785285294676528007919;
    uint256 constant NEG_H_Gi_13 =
        7709167398745143316363160291363827613027915960514812156417975121964527188093;
    uint256 constant NEG_H_Gi_14 =
        17904030001601903779936267292498026811901593828891759028786389874281770981021;
    uint256 constant NEG_H_Gi_15 =
        14879068458267284102382396514308894256441419800779693039134676124482785243120;
    uint256 constant NEG_H_Gi_16 =
        15069683166406810118396980299434025198863421369057553153754099813828526101776;
    uint256 constant NEG_H_Gi_17 =
        3661602413387243277046903307158321769195503952982136072557948152441520492182;
    uint256 constant NEG_H_Gi_18 =
        16319004281183609897523476975997870548121421815417886920930569178145990599328;
    uint256 constant NEG_H_Gi_19 =
        16032817356096813969652342882055165387854056276082502592286863041930017366589;
    uint256 constant NEG_H_Gi_20 =
        3478871800437630736841186594887503052108079964074319196878750757318422891008;
    uint256 constant NEG_H_Gi_21 =
        15427819322379689425329419111224844327424978809243747615642239907504856393000;
    uint256 constant NEG_H_Gi_22 =
        5782248482543004090376202923648970867929901935707279359346323659812103745954;
    uint256 constant NEG_H_Gi_23 =
        19160213976605953569435474998394518120127348859860305459090210143167354037610;
    uint256 constant NEG_H_Gi_24 =
        8859879265385614109665290443010152014855409064267806408815895184562631803200;
    uint256 constant NEG_H_Gi_25 =
        4602516023170994308891258506885060348892400947580840296701211877150906589340;
    uint256 constant NEG_H_Gi_26 =
        13532745525560388916830961573298389421315956963078582978399696147380974183805;
    uint256 constant NEG_H_Gi_27 =
        9240864450953690799657809247329381021160821812151702151115487140630611683793;
    uint256 constant NEG_H_Gi_28 =
        8034676956877985466633893884673937030872337074455212930605717174926123026162;
    uint256 constant NEG_H_Gi_29 =
        15341497363785227518084706408984882372282986044475559920388693899531302270822;
    uint256 constant NEG_H_Gi_30 =
        6496935748147031209159843715101117277138665584387598464387743251495503806288;
    uint256 constant NEG_H_Gi_31 =
        14497204362208086511634267186350398411635784140180115858261885881374812445877;
    uint256 constant NEG_H_Gi_32 =
        7936326290078006128711977173515482706021795039014249828212492771921230171177;
    uint256 constant NEG_H_Gi_33 =
        12783654071702763576586294699555040922577858016749768331403202361559281194470;
    uint256 constant NEG_H_Gi_34 =
        8406821777353633441498474214023397629595666447553393900227852362776708025529;
    uint256 constant NEG_H_Gi_35 =
        12556247105234630933062265759476741050431407090313217783758742657728319787143;
    uint256 constant NEG_H_Gi_36 =
        21202845455497781877679846204268380858622124508313803814830238646470733719219;
    uint256 constant NEG_H_Gi_37 =
        9247455193241384735641440019465647095415293415705096978791116758901726499336;
    uint256 constant NEG_H_Gi_38 =
        8397305193125568232889607175806224497255386086602200116020406830179862651937;
    uint256 constant NEG_H_Gi_39 =
        6470990625610955431683774411739618546270252307008026596162676299817971961806;
    uint256 constant NEG_H_Gi_40 =
        1012213022521037145234615145375587845032687603564553275074831172262027304463;
    uint256 constant NEG_H_Gi_41 =
        396924529825281969222635796217782617444482904985865175524214939731794364119;
    uint256 constant NEG_H_Gi_42 =
        10381780338843625169631260809253968313955312595833903517693476975557410412315;
    uint256 constant NEG_H_Gi_43 =
        19602263751751560326623308796757055261699437558932740987671885782620374941638;
    uint256 constant NEG_H_Gi_44 =
        20672709383923047848334338061351037155400274680662498714489940810305118383992;
    uint256 constant NEG_H_Gi_45 =
        10378998553656474320775588930959982882233003461710741054392940663127059174926;
    uint256 constant NEG_H_Gi_46 =
        14856596787726912187586409245831033743433384920594147438014079397503205920775;
    uint256 constant NEG_H_Gi_47 =
        6398205404820866886916603106643803960305910182679488590520715116843179019557;
    uint256 constant NEG_H_Gi_48 =
        12667328593082887457415193028336882772756821186688020592917227994235922827792;
    uint256 constant NEG_H_Gi_49 =
        12929871765897912963061006786216838529932294963252914631917146383032451500661;
    uint256 constant NEG_H_Gi_50 =
        20480203125109183901162204778704805290468933619230654535022215952165646385369;
    uint256 constant NEG_H_Gi_51 =
        20552643753632295265602709452445764722837155377046144496581457529279444172004;
    uint256 constant NEG_H_Gi_52 =
        19151658378259414150596125620849201339245950302384503529268130976581667249028;
    uint256 constant NEG_H_Gi_53 =
        17657818268791377739158380278033099629028161476733448961672082344814318974029;
    uint256 constant NEG_H_Gi_54 =
        20596708480406953105955564233180882331279416037432992494638724132498525866046;
    uint256 constant NEG_H_Gi_55 =
        20480595584519629244941688402570275286760801509777161452176702963608257553140;
    uint256 constant NEG_H_Gi_56 =
        15939515425865516176444247236983936512159274870599028265396782531119788163556;
    uint256 constant NEG_H_Gi_57 =
        515831470999206376180040179255212025671764116992750770065100806932657979235;
    uint256 constant NEG_H_Gi_58 =
        13581772705312050979736186531098927373874316437917098236174453132719663500400;
    uint256 constant NEG_H_Gi_59 =
        15838372529020872315254568514785579227855350489076785939486093129850308155928;
    uint256 constant NEG_H_Gi_60 =
        6337114218974816571445588245077388176585796745526723227158602200679384076897;
    uint256 constant NEG_H_Gi_61 =
        8675217527776771267110788214589133352123611141163375251805290710391577717775;
    uint256 constant NEG_H_Gi_62 =
        2037019432901088726757579881322000328933087434404442680258786046983774511114;
    uint256 constant NEG_H_Gi_63 =
        20053176473862673770839733921828467609583085375147499723854645825669087182063;

    // 64 constants for NOM_i
    uint256 constant NOM_0 =
        12678585817244807249458519522215882182317473319138010826254054054735575908071;
    uint256 constant NOM_1 =
        3706700786451870874822138999340490520462532983440114291859723724501747751190;
    uint256 constant NOM_2 =
        2389919713229474793281048300864592187373821925557412552302321353175227209206;
    uint256 constant NOM_3 =
        11551089477987118857161133623119593025636642956740740728115485658125880760709;
    uint256 constant NOM_4 =
        15400806279498067346545443573512987398664344086501141077427532610788145159772;
    uint256 constant NOM_5 =
        17869689058986292564873826691721266749073742848189175395805938727307054586296;
    uint256 constant NOM_6 =
        17027916212543217140700911064601578793729471658935448112215159629123398218607;
    uint256 constant NOM_7 =
        5111576240937890835538586027041700100284045998050641800741175999019884897397;
    uint256 constant NOM_8 =
        5557729241360870264867346097027975648414756244369395706124157481399831067349;
    uint256 constant NOM_9 =
        11243384365276979717161560350549347088573260729391074845012731762659807609176;
    uint256 constant NOM_10 =
        8513712674677070252521678039618422561946111680164572141755081241656772232290;
    uint256 constant NOM_11 =
        9245506126687701289966631778446164656852230554278393232158096915480088898353;
    uint256 constant NOM_12 =
        20533426064537224867526913867852812502447757581895705889355673497532111776259;
    uint256 constant NOM_13 =
        16682433734855215617581008439863307980368212202136814577982499501280441102500;
    uint256 constant NOM_14 =
        21768714277483553506510715699756620018648857816122710867480364621093563793716;
    uint256 constant NOM_15 =
        15514330488393793315171150911587568363512622483187629855280889198548795886904;
    uint256 constant NOM_16 =
        12288225520391101304764344471114105792863183498821499039036821058925466280828;
    uint256 constant NOM_17 =
        17761377455286022420235235053725821811664518087810390076725845212977423943151;
    uint256 constant NOM_18 =
        18083076274393982356891324169713754694213558389988119522932495828665640779940;
    uint256 constant NOM_19 =
        17784950470389755761131595395460994543632980967991980221414409841842934661887;
    uint256 constant NOM_20 =
        3015493229574683002229072649205873425031991725872819736401595405450009221075;
    uint256 constant NOM_21 =
        5791707037965710076256104343844337506726094487860950150149947649778325314435;
    uint256 constant NOM_22 =
        11348851712973876202367571540488994641617923832196591446530201150101104106070;
    uint256 constant NOM_23 =
        11591099148374677159200225960207162008909793981729706962015355637973037979913;
    uint256 constant NOM_24 =
        19082900224972261862216378341630124653215092296530620215935155436081043667833;
    uint256 constant NOM_25 =
        1781068896127281253396713339517570681189812580445291115632067533284450046325;
    uint256 constant NOM_26 =
        11166976705981933836564549564388466108265737166634099130183045344644186249789;
    uint256 constant NOM_27 =
        9923894592775422688498039692007637928117400574360533212728871230167516266496;
    uint256 constant NOM_28 =
        19026348536564804361286484909017565805247480620603671714767292026166574245308;
    uint256 constant NOM_29 =
        5528734631090181701077972851106527303650224696692781301852329339337964413010;
    uint256 constant NOM_30 =
        9570556737394018126995568253892349852921051549922362234123510919928735678580;
    uint256 constant NOM_31 =
        18926453423207131698957894347575659300891392556112911464072582716582844715366;
    uint256 constant NOM_32 =
        8055646841073687373460457361168972940362641319950868350148314623656903203214;
    uint256 constant NOM_33 =
        13019534775810539816986474746482565229634395758700186111250059298425100542025;
    uint256 constant NOM_34 =
        12974487409908021772463390313531160014267397827855124083885986709255387452943;
    uint256 constant NOM_35 =
        10791618164310983115768817028498391023483328658055834773084395004056324675675;
    uint256 constant NOM_36 =
        4348237339121709559075854963096519954393524562987123891821518116160990799927;
    uint256 constant NOM_37 =
        14258936121919127411711419281171484475255779284836794742160874427938211041501;
    uint256 constant NOM_38 =
        3501848782985089220430472708731325160375900993528092883272354694533653427469;
    uint256 constant NOM_39 =
        21632936741247940316210039292936434619180192986283604309382438122239495381660;
    uint256 constant NOM_40 =
        12279511709894178699473313301393986773545223905526700250339206052962744491089;
    uint256 constant NOM_41 =
        13377792152895050527575478924099506961359493753015702523217280444282610249706;
    uint256 constant NOM_42 =
        14331488272807864175725305197292854153390788430050840145286819802405002544583;
    uint256 constant NOM_43 =
        3688384438114081878946365926591997890116925526223599735456902854111263980228;
    uint256 constant NOM_44 =
        14641999406656061588485723839465565413952700797469764801516142555730547992793;
    uint256 constant NOM_45 =
        5886611416141296399734557487843580704295853572753016781981258325622890512831;
    uint256 constant NOM_46 =
        7225274312202709723301632114630773880616416090790367796648025889989672944603;
    uint256 constant NOM_47 =
        7757204998955652345852750761398335253869748625393541272876156589694768298184;
    uint256 constant NOM_48 =
        14885361202117058058184318450304135306556423946678928440626312014048457357001;
    uint256 constant NOM_49 =
        13046549888648410524483007959242204188241202519348998748264542566976457794283;
    uint256 constant NOM_50 =
        14564696248451071895004387921829394411964182993103603413763991728916317056188;
    uint256 constant NOM_51 =
        14654265968202267656340951107611404963569551037915988626912851834863119569694;
    uint256 constant NOM_52 =
        16357839210011395749794867336486754615596131577678825663932764326053714926289;
    uint256 constant NOM_53 =
        9359931427390668919342364245727108574092988352811814351609058714253692844353;
    uint256 constant NOM_54 =
        18274059892862060309186252205428407954706134755256206670816610790952994347811;
    uint256 constant NOM_55 =
        4732906908014413602977945164210039137661209997063468672503011670567210516616;
    uint256 constant NOM_56 =
        6164507204957488065813973181001285466017862126128259804181751195553588147011;
    uint256 constant NOM_57 =
        2922711931912044634901407594664681053950356066085037021423620294288688664714;
    uint256 constant NOM_58 =
        15173292957672274616942554607777123253346713538713674933638635389207283738750;
    uint256 constant NOM_59 =
        12778137464711879172321861597003078334167196861345871820021725090325886077066;
    uint256 constant NOM_60 =
        4349525005700321807627690412766584046389529091243214546649057343805964170353;
    uint256 constant NOM_61 =
        23804307647166908169291413245111737823717501650182483124295412031503174351;
    uint256 constant NOM_62 =
        15780208433966584501442373317534554548386638317739603067472116825899804616207;
    uint256 constant NOM_63 =
        12040830530344532254868943200507046815269472790262167339837284828201024220627;

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

    function Verify(
        uint256[6] calldata proof,
        uint256[64] calldata input
    ) public view {
        assembly ("memory-safe") {
            function my_exp(base, exponent) -> x {
                let memPtr := mload(0x40)
                mstore(memPtr, 0x20) // length of base
                mstore(add(memPtr, 0x20), 0x20) // length of exponent
                mstore(add(memPtr, 0x40), 0x20) // length of modulus
                mstore(add(memPtr, 0x60), base)
                mstore(add(memPtr, 0x80), exponent)
                mstore(add(memPtr, 0xa0), R)
                let res := staticcall(
                    gas(),
                    PRECOMPILE_MODEXP,
                    memPtr,
                    0xc0,
                    memPtr,
                    0x20
                )

                x := mload(memPtr)
            }

            // invertFR(a) = a^(R-2) mod R, revert if mulmod(...) != 1
            function invertFR(a) -> x {
                x := my_exp(a, EXP_INVERSE_FR)
            }

            // // computeVanishingPoly(chall) -> zH
            // // zH = (chall^COSET_SIZE + MINUS_COSET_OFFSET_TO_COSET_SIZE) mod R
            // function computeVanishingPoly(chall) -> zH {
            //     let t := my_exp(chall, COSET_SIZE)
            //     zH := addmod(t, MINUS_COSET_OFFSET_TO_COSET_SIZE, R)
            // }

            let ptr := mload(0x40)

            let p2 := calldataload(0x44)
            let p3 := calldataload(0x64)

            mstore(ptr, p2)
            mstore(add(ptr, 32), p3)

            {
                let off := add(ptr, 64)
                let dataStart := 0xc4
                let i := 0
                for {

                } lt(i, 64) {
                    i := add(i, 1)
                } {
                    mstore(off, calldataload(dataStart))
                    off := add(off, 32)
                    dataStart := add(dataStart, 32)
                }
            }

            let off2 := add(ptr, 64)
            off2 := add(off2, mul(64, 32))
            mstore(off2, G_X)
            mstore(add(off2, 32), G_Y)
            mstore(add(off2, 64), ALPHA_G_X)
            mstore(add(off2, 96), ALPHA_G_Y)
            mstore(add(off2, 128), BETA_G_X)
            mstore(add(off2, 160), BETA_G_Y)
            mstore(add(off2, 192), H_X_0)
            mstore(add(off2, 224), H_X_1)
            mstore(add(off2, 256), H_Y_0)
            mstore(add(off2, 288), H_Y_1)
            mstore(add(off2, 320), DELTA_TWO_H_X_0)
            mstore(add(off2, 352), DELTA_TWO_H_X_1)
            mstore(add(off2, 384), DELTA_TWO_H_Y_0)
            mstore(add(off2, 416), DELTA_TWO_H_Y_1)
            mstore(add(off2, 448), TAU_H_X_0)
            mstore(add(off2, 480), TAU_H_X_1)
            mstore(add(off2, 512), TAU_H_Y_0)
            mstore(add(off2, 544), TAU_H_Y_1)

            let hash := keccak256(ptr, 0xa80)
            let chall := mod(hash, R)

            let v_a := calldataload(0x04)
            let v_b := calldataload(0x24)

            function getIn(i) -> val {
                val := calldataload(add(0xc4, mul(i, 32)))
            }

            let x_a := 0

            {
                // i=0
                let neg0 := addmod(chall, NEG_H_Gi_0, R)
                let inv0 := invertFR(addmod(chall, NEG_H_Gi_0, R))
                let lag0 := mulmod(inv0, NOM_0, R)
                x_a := addmod(x_a, mulmod(lag0, getIn(0), R), R)

                // i=1
                let neg1 := addmod(chall, NEG_H_Gi_1, R)
                let inv1 := invertFR(neg1)
                let lag1 := mulmod(inv1, NOM_1, R)
                x_a := addmod(x_a, mulmod(lag1, getIn(1), R), R)

                // i=2
                let neg2 := addmod(chall, NEG_H_Gi_2, R)
                let inv2 := invertFR(neg2)
                let lag2 := mulmod(inv2, NOM_2, R)
                x_a := addmod(x_a, mulmod(lag2, getIn(2), R), R)

                // i=3
                let neg3 := addmod(chall, NEG_H_Gi_3, R)
                let inv3 := invertFR(neg3)
                let lag3 := mulmod(inv3, NOM_3, R)
                x_a := addmod(x_a, mulmod(lag3, getIn(3), R), R)

                // i=4
                let neg4 := addmod(chall, NEG_H_Gi_4, R)
                let inv4 := invertFR(neg4)
                let lag4 := mulmod(inv4, NOM_4, R)
                x_a := addmod(x_a, mulmod(lag4, getIn(4), R), R)

                // i=5
                let neg5 := addmod(chall, NEG_H_Gi_5, R)
                let inv5 := invertFR(neg5)
                let lag5 := mulmod(inv5, NOM_5, R)
                x_a := addmod(x_a, mulmod(lag5, getIn(5), R), R)

                // i=6
                let neg6 := addmod(chall, NEG_H_Gi_6, R)
                let inv6 := invertFR(neg6)
                let lag6 := mulmod(inv6, NOM_6, R)
                x_a := addmod(x_a, mulmod(lag6, getIn(6), R), R)

                // i=7
                let neg7 := addmod(chall, NEG_H_Gi_7, R)
                let inv7 := invertFR(neg7)
                let lag7 := mulmod(inv7, NOM_7, R)
                x_a := addmod(x_a, mulmod(lag7, getIn(7), R), R)

                // i=8
                let neg8 := addmod(chall, NEG_H_Gi_8, R)
                let inv8 := invertFR(neg8)
                let lag8 := mulmod(inv8, NOM_8, R)
                x_a := addmod(x_a, mulmod(lag8, getIn(8), R), R)

                // i=9
                let neg9 := addmod(chall, NEG_H_Gi_9, R)
                let inv9 := invertFR(neg9)
                let lag9 := mulmod(inv9, NOM_9, R)
                x_a := addmod(x_a, mulmod(lag9, getIn(9), R), R)

                // i=10
                let neg10 := addmod(chall, NEG_H_Gi_10, R)
                let inv10 := invertFR(neg10)
                let lag10 := mulmod(inv10, NOM_10, R)
                x_a := addmod(x_a, mulmod(lag10, getIn(10), R), R)

                // i=11
                let neg11 := addmod(chall, NEG_H_Gi_11, R)
                let inv11 := invertFR(neg11)
                let lag11 := mulmod(inv11, NOM_11, R)
                x_a := addmod(x_a, mulmod(lag11, getIn(11), R), R)

                // i=12
                let neg12 := addmod(chall, NEG_H_Gi_12, R)
                let inv12 := invertFR(neg12)
                let lag12 := mulmod(inv12, NOM_12, R)
                x_a := addmod(x_a, mulmod(lag12, getIn(12), R), R)

                // i=13
                let neg13 := addmod(chall, NEG_H_Gi_13, R)
                let inv13 := invertFR(neg13)
                let lag13 := mulmod(inv13, NOM_13, R)
                x_a := addmod(x_a, mulmod(lag13, getIn(13), R), R)

                // i=14
                let neg14 := addmod(chall, NEG_H_Gi_14, R)
                let inv14 := invertFR(neg14)
                let lag14 := mulmod(inv14, NOM_14, R)
                x_a := addmod(x_a, mulmod(lag14, getIn(14), R), R)

                // i=15
                let neg15 := addmod(chall, NEG_H_Gi_15, R)
                let inv15 := invertFR(neg15)
                let lag15 := mulmod(inv15, NOM_15, R)
                x_a := addmod(x_a, mulmod(lag15, getIn(15), R), R)

                // i=16
                let neg16 := addmod(chall, NEG_H_Gi_16, R)
                let inv16 := invertFR(neg16)
                let lag16 := mulmod(inv16, NOM_16, R)
                x_a := addmod(x_a, mulmod(lag16, getIn(16), R), R)

                // i=17
                let neg17 := addmod(chall, NEG_H_Gi_17, R)
                let inv17 := invertFR(neg17)
                let lag17 := mulmod(inv17, NOM_17, R)
                x_a := addmod(x_a, mulmod(lag17, getIn(17), R), R)

                // i=18
                let neg18 := addmod(chall, NEG_H_Gi_18, R)
                let inv18 := invertFR(neg18)
                let lag18 := mulmod(inv18, NOM_18, R)
                x_a := addmod(x_a, mulmod(lag18, getIn(18), R), R)

                // i=19
                let neg19 := addmod(chall, NEG_H_Gi_19, R)
                let inv19 := invertFR(neg19)
                let lag19 := mulmod(inv19, NOM_19, R)
                x_a := addmod(x_a, mulmod(lag19, getIn(19), R), R)

                // i=20
                let neg20 := addmod(chall, NEG_H_Gi_20, R)
                let inv20 := invertFR(neg20)
                let lag20 := mulmod(inv20, NOM_20, R)
                x_a := addmod(x_a, mulmod(lag20, getIn(20), R), R)

                // i=21
                let neg21 := addmod(chall, NEG_H_Gi_21, R)
                let inv21 := invertFR(neg21)
                let lag21 := mulmod(inv21, NOM_21, R)
                x_a := addmod(x_a, mulmod(lag21, getIn(21), R), R)

                // i=22
                let neg22 := addmod(chall, NEG_H_Gi_22, R)
                let inv22 := invertFR(neg22)
                let lag22 := mulmod(inv22, NOM_22, R)
                x_a := addmod(x_a, mulmod(lag22, getIn(22), R), R)

                // i=23
                let neg23 := addmod(chall, NEG_H_Gi_23, R)
                let inv23 := invertFR(neg23)
                let lag23 := mulmod(inv23, NOM_23, R)
                x_a := addmod(x_a, mulmod(lag23, getIn(23), R), R)

                // i=24
                let neg24 := addmod(chall, NEG_H_Gi_24, R)
                let inv24 := invertFR(neg24)
                let lag24 := mulmod(inv24, NOM_24, R)
                x_a := addmod(x_a, mulmod(lag24, getIn(24), R), R)

                // i=25
                let neg25 := addmod(chall, NEG_H_Gi_25, R)
                let inv25 := invertFR(neg25)
                let lag25 := mulmod(inv25, NOM_25, R)
                x_a := addmod(x_a, mulmod(lag25, getIn(25), R), R)

                // i=26
                let neg26 := addmod(chall, NEG_H_Gi_26, R)
                let inv26 := invertFR(neg26)
                let lag26 := mulmod(inv26, NOM_26, R)
                x_a := addmod(x_a, mulmod(lag26, getIn(26), R), R)

                // i=27
                let neg27 := addmod(chall, NEG_H_Gi_27, R)
                let inv27 := invertFR(neg27)
                let lag27 := mulmod(inv27, NOM_27, R)
                x_a := addmod(x_a, mulmod(lag27, getIn(27), R), R)

                // i=28
                let neg28 := addmod(chall, NEG_H_Gi_28, R)
                let inv28 := invertFR(neg28)
                let lag28 := mulmod(inv28, NOM_28, R)
                x_a := addmod(x_a, mulmod(lag28, getIn(28), R), R)

                // i=29
                let neg29 := addmod(chall, NEG_H_Gi_29, R)
                let inv29 := invertFR(neg29)
                let lag29 := mulmod(inv29, NOM_29, R)
                x_a := addmod(x_a, mulmod(lag29, getIn(29), R), R)

                // i=30
                let neg30 := addmod(chall, NEG_H_Gi_30, R)
                let inv30 := invertFR(neg30)
                let lag30 := mulmod(inv30, NOM_30, R)
                x_a := addmod(x_a, mulmod(lag30, getIn(30), R), R)

                // i=31
                let neg31 := addmod(chall, NEG_H_Gi_31, R)
                let inv31 := invertFR(neg31)
                let lag31 := mulmod(inv31, NOM_31, R)
                x_a := addmod(x_a, mulmod(lag31, getIn(31), R), R)

                // i=32
                let neg32 := addmod(chall, NEG_H_Gi_32, R)
                let inv32 := invertFR(neg32)
                let lag32 := mulmod(inv32, NOM_32, R)
                x_a := addmod(x_a, mulmod(lag32, getIn(32), R), R)

                // i=33
                let neg33 := addmod(chall, NEG_H_Gi_33, R)
                let inv33 := invertFR(neg33)
                let lag33 := mulmod(inv33, NOM_33, R)
                x_a := addmod(x_a, mulmod(lag33, getIn(33), R), R)

                // i=34
                let neg34 := addmod(chall, NEG_H_Gi_34, R)
                let inv34 := invertFR(neg34)
                let lag34 := mulmod(inv34, NOM_34, R)
                x_a := addmod(x_a, mulmod(lag34, getIn(34), R), R)

                // i=35
                let neg35 := addmod(chall, NEG_H_Gi_35, R)
                let inv35 := invertFR(neg35)
                let lag35 := mulmod(inv35, NOM_35, R)
                x_a := addmod(x_a, mulmod(lag35, getIn(35), R), R)

                // i=36
                let neg36 := addmod(chall, NEG_H_Gi_36, R)
                let inv36 := invertFR(neg36)
                let lag36 := mulmod(inv36, NOM_36, R)
                x_a := addmod(x_a, mulmod(lag36, getIn(36), R), R)

                // i=37
                let neg37 := addmod(chall, NEG_H_Gi_37, R)
                let inv37 := invertFR(neg37)
                let lag37 := mulmod(inv37, NOM_37, R)
                x_a := addmod(x_a, mulmod(lag37, getIn(37), R), R)

                // i=38
                let neg38 := addmod(chall, NEG_H_Gi_38, R)
                let inv38 := invertFR(neg38)
                let lag38 := mulmod(inv38, NOM_38, R)
                x_a := addmod(x_a, mulmod(lag38, getIn(38), R), R)

                // i=39
                let neg39 := addmod(chall, NEG_H_Gi_39, R)
                let inv39 := invertFR(neg39)
                let lag39 := mulmod(inv39, NOM_39, R)
                x_a := addmod(x_a, mulmod(lag39, getIn(39), R), R)

                // i=40
                let neg40 := addmod(chall, NEG_H_Gi_40, R)
                let inv40 := invertFR(neg40)
                let lag40 := mulmod(inv40, NOM_40, R)
                x_a := addmod(x_a, mulmod(lag40, getIn(40), R), R)

                // i=41
                let neg41 := addmod(chall, NEG_H_Gi_41, R)
                let inv41 := invertFR(neg41)
                let lag41 := mulmod(inv41, NOM_41, R)
                x_a := addmod(x_a, mulmod(lag41, getIn(41), R), R)

                // i=42
                let neg42 := addmod(chall, NEG_H_Gi_42, R)
                let inv42 := invertFR(neg42)
                let lag42 := mulmod(inv42, NOM_42, R)
                x_a := addmod(x_a, mulmod(lag42, getIn(42), R), R)

                // i=43
                let neg43 := addmod(chall, NEG_H_Gi_43, R)
                let inv43 := invertFR(neg43)
                let lag43 := mulmod(inv43, NOM_43, R)
                x_a := addmod(x_a, mulmod(lag43, getIn(43), R), R)

                // i=44
                let neg44 := addmod(chall, NEG_H_Gi_44, R)
                let inv44 := invertFR(neg44)
                let lag44 := mulmod(inv44, NOM_44, R)
                x_a := addmod(x_a, mulmod(lag44, getIn(44), R), R)

                // i=45
                let neg45 := addmod(chall, NEG_H_Gi_45, R)
                let inv45 := invertFR(neg45)
                let lag45 := mulmod(inv45, NOM_45, R)
                x_a := addmod(x_a, mulmod(lag45, getIn(45), R), R)

                // i=46
                let neg46 := addmod(chall, NEG_H_Gi_46, R)
                let inv46 := invertFR(neg46)
                let lag46 := mulmod(inv46, NOM_46, R)
                x_a := addmod(x_a, mulmod(lag46, getIn(46), R), R)

                // i=47
                let neg47 := addmod(chall, NEG_H_Gi_47, R)
                let inv47 := invertFR(neg47)
                let lag47 := mulmod(inv47, NOM_47, R)
                x_a := addmod(x_a, mulmod(lag47, getIn(47), R), R)

                // i=48
                let neg48 := addmod(chall, NEG_H_Gi_48, R)
                let inv48 := invertFR(neg48)
                let lag48 := mulmod(inv48, NOM_48, R)
                x_a := addmod(x_a, mulmod(lag48, getIn(48), R), R)

                // i=49
                let neg49 := addmod(chall, NEG_H_Gi_49, R)
                let inv49 := invertFR(neg49)
                let lag49 := mulmod(inv49, NOM_49, R)
                x_a := addmod(x_a, mulmod(lag49, getIn(49), R), R)

                // i=50
                let neg50 := addmod(chall, NEG_H_Gi_50, R)
                let inv50 := invertFR(neg50)
                let lag50 := mulmod(inv50, NOM_50, R)
                x_a := addmod(x_a, mulmod(lag50, getIn(50), R), R)

                // i=51
                let neg51 := addmod(chall, NEG_H_Gi_51, R)
                let inv51 := invertFR(neg51)
                let lag51 := mulmod(inv51, NOM_51, R)
                x_a := addmod(x_a, mulmod(lag51, getIn(51), R), R)

                // i=52
                let neg52 := addmod(chall, NEG_H_Gi_52, R)
                let inv52 := invertFR(neg52)
                let lag52 := mulmod(inv52, NOM_52, R)
                x_a := addmod(x_a, mulmod(lag52, getIn(52), R), R)

                // i=53
                let neg53 := addmod(chall, NEG_H_Gi_53, R)
                let inv53 := invertFR(neg53)
                let lag53 := mulmod(inv53, NOM_53, R)
                x_a := addmod(x_a, mulmod(lag53, getIn(53), R), R)

                // i=54
                let neg54 := addmod(chall, NEG_H_Gi_54, R)
                let inv54 := invertFR(neg54)
                let lag54 := mulmod(inv54, NOM_54, R)
                x_a := addmod(x_a, mulmod(lag54, getIn(54), R), R)

                // i=55
                let neg55 := addmod(chall, NEG_H_Gi_55, R)
                let inv55 := invertFR(neg55)
                let lag55 := mulmod(inv55, NOM_55, R)
                x_a := addmod(x_a, mulmod(lag55, getIn(55), R), R)

                // i=56
                let neg56 := addmod(chall, NEG_H_Gi_56, R)
                let inv56 := invertFR(neg56)
                let lag56 := mulmod(inv56, NOM_56, R)
                x_a := addmod(x_a, mulmod(lag56, getIn(56), R), R)

                // i=57
                let neg57 := addmod(chall, NEG_H_Gi_57, R)
                let inv57 := invertFR(neg57)
                let lag57 := mulmod(inv57, NOM_57, R)
                x_a := addmod(x_a, mulmod(lag57, getIn(57), R), R)

                // i=58
                let neg58 := addmod(chall, NEG_H_Gi_58, R)
                let inv58 := invertFR(neg58)
                let lag58 := mulmod(inv58, NOM_58, R)
                x_a := addmod(x_a, mulmod(lag58, getIn(58), R), R)

                // i=59
                let neg59 := addmod(chall, NEG_H_Gi_59, R)
                let inv59 := invertFR(neg59)
                let lag59 := mulmod(inv59, NOM_59, R)
                x_a := addmod(x_a, mulmod(lag59, getIn(59), R), R)

                // i=60
                let neg60 := addmod(chall, NEG_H_Gi_60, R)
                let inv60 := invertFR(neg60)
                let lag60 := mulmod(inv60, NOM_60, R)
                x_a := addmod(x_a, mulmod(lag60, getIn(60), R), R)

                // i=61
                let neg61 := addmod(chall, NEG_H_Gi_61, R)
                let inv61 := invertFR(neg61)
                let lag61 := mulmod(inv61, NOM_61, R)
                x_a := addmod(x_a, mulmod(lag61, getIn(61), R), R)

                // i=62
                let neg62 := addmod(chall, NEG_H_Gi_62, R)
                let inv62 := invertFR(neg62)
                let lag62 := mulmod(inv62, NOM_62, R)
                x_a := addmod(x_a, mulmod(lag62, getIn(62), R), R)

                // i=63
                let neg63 := addmod(chall, NEG_H_Gi_63, R)
                let inv63 := invertFR(neg63)
                let lag63 := mulmod(inv63, NOM_63, R)
                x_a := addmod(x_a, mulmod(lag63, getIn(63), R), R)
            }

            let sumVal := addmod(v_a, x_a, R)
            let numerator := mulmod(sumVal, sumVal, R)
            numerator := addmod(numerator, sub(R, v_b), R)

            let t := my_exp(chall, COSET_SIZE)
            let vanish := addmod(t, MINUS_COSET_OFFSET_TO_COSET_SIZE, R)
            let vanishInv := invertFR(vanish)
            let v_q := mulmod(numerator, vanishInv, R)

            let P1 := ptr
            let P2 := add(ptr, 0x40)
            let P3 := add(ptr, 0x80)
            let P4 := add(ptr, 0xc0)
            let P5 := add(ptr, 0x100)
            let temp := add(ptr, 0x140)

            mstore(ptr, ALPHA_G_X)
            mstore(add(ptr, 32), ALPHA_G_Y)
            mstore(add(ptr, 64), v_a)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P1, 0x40)) {
                revert(0, 0)
            }
            ptr := add(ptr, 0x60)

            mstore(ptr, BETA_G_X)
            mstore(add(ptr, 32), BETA_G_Y)
            mstore(add(ptr, 64), v_b)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P2, 0x40)) {
                revert(0, 0)
            }
            ptr := add(ptr, 0x60)

            mstore(ptr, G_X)
            mstore(add(ptr, 32), G_Y)
            mstore(add(ptr, 64), v_q)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P3, 0x40)) {
                revert(0, 0)
            }
            ptr := add(ptr, 0x60)

            let ugx := calldataload(0x84)
            let ugy := calldataload(0xa4)
            mstore(ptr, ugx)
            mstore(add(ptr, 32), ugy)
            mstore(add(ptr, 64), chall)
            if iszero(staticcall(gas(), PRECOMPILE_MUL, ptr, 0x60, P4, 0x40)) {
                revert(0, 0)
            }
            ptr := add(ptr, 0x60)

            mstore(ptr, mload(P1))
            mstore(add(ptr, 32), mload(add(P1, 32)))
            mstore(add(ptr, 64), mload(P2))
            mstore(add(ptr, 96), mload(add(P2, 32)))
            if iszero(
                staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
            ) {
                revert(0, 0)
            }
            ptr := add(ptr, 0x80)

            mstore(ptr, mload(temp))
            mstore(add(ptr, 32), mload(add(temp, 32)))
            mstore(add(ptr, 64), mload(P3))
            mstore(add(ptr, 96), mload(add(P3, 32)))
            if iszero(
                staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, temp, 0x40)
            ) {
                revert(0, 0)
            }
            ptr := add(ptr, 0x80)

            mstore(ptr, mload(temp))
            mstore(add(ptr, 32), mload(add(temp, 32)))
            mstore(add(ptr, 64), mload(P4))
            mstore(add(ptr, 96), sub(P, mload(add(P4, 32))))
            let res := staticcall(gas(), PRECOMPILE_ADD, ptr, 0x80, P5, 0x40)
            ptr := add(ptr, 0x80)

            let A_x := mload(P5)
            let A_y := mload(add(P5, 32))

            mstore(ptr, p2)
            mstore(add(ptr, 32), p3)
            mstore(add(ptr, 64), DELTA_TWO_H_X_1)
            mstore(add(ptr, 96), DELTA_TWO_H_X_0)
            mstore(add(ptr, 128), DELTA_TWO_H_Y_1)
            mstore(add(ptr, 160), DELTA_TWO_H_Y_0)

            mstore(add(ptr, 192), ugx)
            mstore(add(ptr, 224), ugy)
            mstore(add(ptr, 256), TAU_H_X_1)
            mstore(add(ptr, 288), TAU_H_X_0)
            mstore(add(ptr, 320), TAU_H_Y_1)
            mstore(add(ptr, 352), TAU_H_Y_0)

            mstore(add(ptr, 384), A_x)
            mstore(add(ptr, 416), A_y)
            mstore(add(ptr, 448), H_X_1)
            mstore(add(ptr, 480), H_X_0)
            mstore(add(ptr, 512), H_Y_1)
            mstore(add(ptr, 544), H_Y_0)

            let ok := staticcall(
                gas(),
                PRECOMPILE_VERIFY,
                ptr,
                0x240,
                ptr,
                0x20
            )
            ok := and(ok, mload(ptr))
            mstore(0x40, add(ptr, 0x240))
        }
    }
}
