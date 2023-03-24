"""
q = 2^49 - 2^30 + 1
sqr1 = sqrt(-1) mod q
i2 = 2^(-1) mod q
"""
q = 562948879679489
sqr1 = 265459796065751
i2 = 281474439839745
i2sqr1 = 148744541806869

"""
Primitive roots of unity
"""
roots_dict = {
    2: [265459796065751],
    4: [37370127601750, 235735039664474],
    8: [227698218839833, 86195001386456, 188881578792319, 258916802457493],
    16: [27181846851921, 87900481764890, 11501956986462, 179508604414279, 138235299582787, 188879393624992, 292557447346890, 166662479652834],
    32: [51287973105033, 93479800836515, 120279644274116, 148293439668386, 52141923149216, 205894838465293, 233512057791583, 73921467784380, 435676065998743, 335387937878067, 73587970667072, 217963712694217, 58280274963940, 292123836674682, 268019057416942, 143564720798630],
    64: [273535649900791, 59743011522175, 258229246279829, 255530057825109, 94931817785584, 106443024076536, 197867441249803, 3297213429184, 46684548616238, 202062622215258, 118309077568832, 141393745541658, 28177940081249, 108836680186998, 180704109844027, 54692034236391, 389894149664507, 14537612764627, 472326070313759, 332825933482851, 33175491585139, 158843638319955, 126467183666580, 346190372284856, 527244882174273, 544891317935701, 495555728190825, 291558784389496, 126686396800605, 144635301292961, 227573146175853, 49584099121857],
    128: [222555332654727, 27495934535943, 156320928430022, 12219572370973, 87662929396186, 268431169047477, 190283756387823, 120709681541651, 277433638601137, 2909895790881, 66944080658262, 58691346414032, 252933880646124, 181249907133153, 178724582876738, 84026447836368, 33908633641083, 192042392431722, 279228468038619, 190178225493597, 46706177697932, 35326932910794, 240662604460690, 31587934406377, 280738968780509, 197287502558104, 252506109566741, 138077386526118, 129074157206363, 123779464783703, 224793425425111, 110744589887208, 353605375945546, 394913852921458, 448735480354109, 302131179592649, 438217856677023, 334843792105723, 427986136518849, 71826959975587, 322390652400265, 133628796163651, 551296205589152, 292151288635717, 301732406656561, 282330184729441, 479867992238328, 427298440408832, 51287724564894, 337448293539880, 115842121691846, 220634568972530, 386132576078912, 414046191580166, 138394578999531, 324036768005023, 20988306557203, 463017626568705, 89083295815873, 61194665625534, 171830831171625, 61722610225846, 150246713541807, 232362216056755],
    256: [113018722815114, 195164702896354, 97204808446326, 85444900079065, 267180896603590, 9305214632501, 48158128066844, 31073855928929, 274862685789681, 4753319831984, 264143983838841, 54198361309703, 20016101756423, 17250713661864, 116976906096973, 230414054137162, 34158889761662, 195598479548089, 245290457414857, 56284239419903, 251515647400387, 7821798718428, 255739993624752, 58174248614037, 212271349997272, 147777400808754, 125846339611997, 16960006299585, 223079112629164, 99625960360297, 2927086233604, 209716231985456, 260464397117203, 189131025578636, 30860389237552, 271395552727563, 33093879690921, 252823889918594, 135104474417970, 116247622190335, 90244620285563, 90578040696496, 165961240519726, 138646726651219, 28901082433389, 120104155273205, 199055183549826, 50529082043655, 67690077188708, 160781751109599, 66366661244094, 200800432177687, 168468406806375, 147630330782029, 15627345408949, 140021817536658, 17478690055985, 186822176989136, 176112754973256, 202753013222201, 255796997504108, 184442115593185, 242626219673599, 99666342405702, 474781929344332, 212840198037367, 70579609959972, 401603801136122, 51910593037564, 406633535425296, 245239092610963, 354077009253714, 421525724766797, 485804028301713, 355008634633986, 554467018408309, 249838081575538, 326079218965151, 252685814173476, 135798786043244, 114296355398694, 355393209892747, 216846590311233, 89152988665176, 185180265800270, 79023411647607, 218750865681154, 46200129909320, 196992430799167, 343539382677186, 394343590866179, 176945003171915, 30726326332495, 234238634446244, 387350847565195, 319108006285957, 144403082554392, 520746708742150, 443830660202354, 346632485947897, 92147855742476, 462538801331701, 228511799603160, 255666680769573, 242021843858600, 398482871802024, 23482393897848, 170277220292236, 52765275259941, 518754079538461, 143357295505490, 48904636653767, 499396987350639, 50412118724121, 165292822345308, 230197825439033, 204376914402620, 206682040094671, 420615821072848, 314030256607467, 491188817284998, 1138650617345, 270415468243657, 198839624222291, 170406685406335, 387206442042038, 212037398860599, 441666583995853],
    512: [14829417563548, 559420395217, 89609889777416, 244399910344573, 139901352183205, 215334598691993, 95667815246078, 205319778710334, 126299726507451, 202340662893694, 94115848378332, 184214629129339, 46273366766727, 274817693713008, 266457318004842, 267188952931539, 11962064596781, 160952771422775, 146435539709634, 73651437944435, 12229820017863, 100577454838663, 118804677073177, 51548324762114, 175157315933781, 231966901520780, 273776372095928, 154771545188157, 19406900199503, 275592602698648, 110191568734695, 165000978235325, 87549310675417, 95574826941651, 117373455811023, 104436979524453, 105487761676926, 44105459895917, 122353323598, 99989781395327, 113054275339028, 39797042062619, 71678183925624, 114945392672947, 267089137426911, 166201632118638, 244335479567332, 249041062947447, 55882842534738, 58632608141880, 273137875778427, 143095221597033, 157018248208089, 241525690090133, 28707278152276, 157428970569177, 66565446486098, 208903000971745, 11853767881004, 83857688140559, 226084676366091, 259093132221169, 89685255143424, 218294163330634, 195004791803182, 10675590397504, 49712368000929, 84384076344488, 111279737302288, 8074903834588, 35224571397558, 47098327090584, 255671287252882, 235331015297173, 42976215032985, 150231617765910, 186902682311966, 279990131404878, 226233991559198, 272803422258354, 18954193173291, 135996015154914, 199153172144913, 276835497581753, 268752790498333, 9469184707564, 192515278579460, 252661851746206, 19682548346777, 90350089972387, 97168383372713, 7201432689380, 103414092787426, 143369396217955, 211957934976731, 61562502423673, 195004186063598, 77391729914584, 104160299261926, 95466285544586, 182003185628147, 193288932813850, 67141850195934, 276676743654187, 276970190135096, 174292281850433, 198547114186298, 147140236073260, 126849499453934, 160244360306324, 29769106753906, 75282515687906, 33748842849620, 91190703532963, 221149943432468, 127204319472165, 245004426217893, 17502600229265, 165964360476662, 54721625467842, 129006759114548, 265087338291440, 201985346828788, 193301336121362, 276068552368995, 158913297405451, 224353276423554, 45398056977597, 36899662629107, 115701523459660, 104691403928352, 37415185821565, 410353654598344, 137793705286031, 252486821984524, 439986571970973, 522504846758083, 140442073055713, 37019574340353, 41008597264093, 8009021351016, 110513791914742, 545724590709175, 491983206105334, 516126204452594, 84006552525808, 134717401653322, 456657679352592, 180805845899961, 162454978882553, 207249629217408, 329468978385085, 473937764401701, 541299855780053, 116359364001499, 308034039606563, 550100565428688, 483898583355171, 60759099029692, 151523471574604, 58258260716427, 132856640537629, 177649575256694, 83923810146343, 535010884844890, 139016726729122, 165807968869501, 336562953871795, 39454914876964, 57794231190945, 388132758921547, 435528963797253, 120732973486200, 556835005811796, 498153234527823, 544478113453650, 322462494371181, 372861957845640, 480132440751550, 418626147182385, 17188383821351, 334944041699414, 508447577252350, 413042629575915, 400576040227445, 160218079323526, 553401775846290, 402093248397156, 208920827398035, 394954552132259, 100344499837581, 33182039102569, 156273684437155, 85425035916511, 536081636429247, 404379412282687, 31322307072199, 122162260342714, 305435929253139, 325607323745936, 549950455530273, 353816944288573, 40473073106362, 350172293244466, 507105496990699, 344688368799006, 198498878132739, 4445861046069, 477734280751112, 206611270258621, 147641515634069, 216406289581526, 231100734955116, 136645076676242, 290043846036427, 491478811156403, 69138691322158, 147046267982241, 279793951920712, 391145400851236, 411010577607869, 367940554377597, 441152879704028, 195616985515181, 514907547654111, 240339194377247, 486063586713773, 560840184040359, 61743308467210, 242636092382901, 484321393052011, 297925412259444, 510983559918618, 431300598789822, 166679500479629, 211711045076079, 102014416326820, 343480193371151, 351042772890364, 544959845731, 150715001661670, 349715658012371, 385206881268500, 99538044506651, 97371967867250, 430292473815284, 141188472313269, 418421319542151, 217584598016051, 236269285035700, 304818895084601, 410155317384726, 257100886002416, 188038572503228, 477911954954779, 41197698932289],
    1024: [277610578474042, 46176525009819, 276925330241740, 82225758822448, 243363659572963, 63400112087197, 95743787879872, 246457746092627, 119294132184812, 70569223776714, 257687916014104, 139222048563014, 28015583277739, 42234204330407, 18409905372716, 83668477089874, 255594472115464, 57007858620872, 155555018544911, 109391030878002, 190413096883639, 56744590973109, 204087428547014, 78579367169760, 281015439913189, 8015714419640, 54366837400074, 157754625220951, 264158257984665, 234470436643282, 74000256319727, 201152830403781, 103831509244445, 34962203934902, 14111204120456, 114156856371130, 224365136945293, 179380850686697, 272155877210450, 251278318171534, 53302556717669, 62581319333907, 122243551710331, 144577661204451, 110935482224486, 49080452107918, 251468604104302, 3471726606598, 107994580878103, 157711857526673, 191466458089946, 217389507334773, 129585634425094, 228952116119976, 185538218364250, 188624414546198, 70778960835748, 175074278556190, 187629324072114, 81126219416492, 51401302017013, 128446773054503, 203041331986905, 34621908991467, 71018166598442, 276695173817014, 4921122257358, 87022745151760, 185351923083980, 131311870791492, 61057662064270, 231130571194105, 112607460743302, 52834720871290, 27439871252070, 17110695973159, 167274777966259, 202182198422744, 190969341791969, 56150453831087, 44335441288036, 61542607295398, 271911360693337, 195745934216846, 117973433895799, 119361062659115, 224208986110909, 119780210630704, 134171883972890, 42538788405187, 168394997643254, 259574531278074, 131818039921335, 105564779181010, 21715691972681, 53420881129808, 237636012597517, 134270482868882, 106734638900456, 194829609331481, 141779231179317, 117396178298510, 214831900416862, 213297417340685, 186880439907712, 91332924859567, 98903208018395, 117077583258505, 180459067414324, 218804973553638, 257472296762052, 220273498636684, 277072851209384, 52526039727553, 81130598782833, 6370162267012, 62304817723592, 55878459991228, 146995253053940, 271215560594933, 57755121965672, 206930784058593, 55698254111469, 241089364466931, 118336069102390, 124939886080281, 200901350666260, 72999054445462, 201615899291063, 256518695350507, 242015528968319, 9891531572899, 266856893095274, 263161065295366, 213990973802801, 228395567341000, 125216118084670, 25052499583067, 48188010620173, 176834178631853, 223923281665903, 183041436041654, 248698218588768, 108685465286176, 43999704281633, 225016984619163, 161737715084881, 24846454600545, 147955599435295, 143665195288738, 209722421832360, 116507002291300, 208607170230066, 821253552017, 46113877773906, 252366134457913, 102636503110440, 38831946633782, 238052210627475, 89992503838676, 5478007173211, 266603670676828, 129035336906558, 232853375602042, 216234212013000, 135645590604360, 79531940281744, 27606454554939, 37145433376487, 56619336601922, 22511928996334, 70043022913130, 160222278056391, 56067587284080, 230355448484285, 107062945426918, 205192308341381, 72964719660632, 5466420327643, 121272658926130, 139396078522650, 240366661916364, 257196336177769, 52631264399241, 24941163039086, 99325233132279, 151588277943973, 263895754768895, 266711043638039, 120455292102909, 35346920367520, 95072995268484, 139808402302679, 99275465713471, 68695788075255, 145910278027181, 44213443148981, 212379441496689, 165252782683447, 96582938556377, 134999759709663, 93554370626437, 95223189057789, 56603537256236, 112989746116280, 119545016651180, 33289192949932, 180736120535098, 216315251807010, 126217318180217, 99406866144484, 24675498780837, 49819149956129, 59306522221558, 231812570458763, 124115054719332, 217508288779533, 274447444530879, 105141900390331, 61592188450562, 164556908343591, 169197695186077, 24110095885867, 148692555010217, 41725103313553, 166387916128730, 149092887305858, 94804806526453, 149163248492417, 94646719514619, 51269965758607, 18669519584702, 272626533931382, 3362914652512, 147942102424846, 194698229084638, 79468455742630, 265407796107065, 60994437307697, 36491694015434, 36556775779731, 97917065561319, 93944711543983, 31186503375071, 191890166469551, 60904554688459, 117160127698791, 112591592251505, 128152761775157, 93367813095250, 145120908991019, 58321067642188, 245607315841568, 133704779988445, 267795406143172, 198187739112481, 58160160850619, 135732779756482, 196969576867717, 507955751050686, 387925135941550, 131470722156098, 456472748840375, 211179811960148, 355229167765557, 542225730088377, 436180700421614, 554179558902199, 195767465660578, 162993751542713, 197032639110287, 43287028741835, 74526493791314, 173302584406071, 31109780655969, 500776711949952, 85420677723533, 308989671800123, 30718006895611, 368814380493268, 410864263940708, 437244115875727, 138410218285130, 272860139524695, 182850870543048, 281058429778005, 200768447986413, 27101975257412, 337467763742083, 244161616845654, 208760712706931, 278595096541042, 4230434254037, 71145649487511, 279769569259736, 406736998058216, 227299478237190, 421365523513460, 20420446078592, 81761549160819, 441633943430701, 131821232950944, 148658801416356, 346061098004061, 515009179136249, 50725389274165, 502112792522126, 133783172223880, 382166829818849, 435412810208845, 117586779036556, 365215974638455, 163345393281406, 324832162292717, 491871344292332, 56423978085281, 369453207923352, 428507136292843, 45614586470469, 477705428867485, 268448630619875, 479894424131543, 381686762930133, 559340293005520, 78739240097516, 448913519191859, 516984649066153, 542454966255919, 467386705985250, 91317074324166, 1234931691945, 145691945610739, 288166968698328, 43393984333116, 213800941766356, 115749498403243, 462138567227392, 2890075011527, 531241608757505, 277062459742935, 2844573491017, 167352356470087, 490218285906593, 23329711139822, 277579872891072, 489885443580519, 72999787466856, 19170471941182, 152683092417700, 555231572134736, 29606421761364, 401158627127970, 466619307121800, 477518518269232, 227340565693899, 130889476325701, 152505881899678, 182614103925947, 240179219552343, 420763071529521, 358010815285327, 500117971914864, 113594711060117, 64124565298521, 47850208271471, 155765161966714, 266542165491279, 413251656894714, 350010408291237, 267484349464113, 310935231288916, 439777296869431, 357243509440772, 119807548433630, 381739503492153, 512637056895862, 525071952258773, 67632987620633, 383500942199406, 149487705963334, 543357846092537, 98468108330027, 395480590422048, 199945690564862, 423199189432906, 389257362034299, 34338602309386, 457282177543711, 290071186397430, 147477534432014, 300790776846102, 57741533606539, 443372914857882, 444215508818892, 466057654332504, 53366973471932, 457984823531784, 532129494152811, 35899474670912, 167815003877091, 333759171884093, 24127015960771, 187459229859499, 190069601793601, 196837168414909, 53198163626385, 261992234460068, 51967575290765, 67696913035856, 46856268127911, 286509182297601, 344112324230854, 399445996306826, 32882526168971, 382804624438460, 461610157778554, 232854211012205, 489673693895064, 431114144595308, 533850739903671, 5398991407559, 183359842003524, 66217599319228, 325966231216715, 17408643043976, 15585925898808, 406849851088223, 399400153651663, 26310962146300, 25647485675619, 246544455183487, 271557140233231, 215530762556473, 32209895229418, 288198540767359, 347239983756614, 534846055902249, 502951755121891, 322732849482495, 398968515715794, 494951784839383, 22127493879308, 143164914339166, 7601804663203, 513966138191974, 231354321652813, 468332012720550, 258216310934727, 557251822944281, 82774565308822, 551427532046657, 67033361057275, 390148826120227, 314376687335323, 170946327454149, 271130370183843, 313710971669602, 404197490383783, 552308572838762, 204804650987094, 528549597984247, 76560016765670, 100825368693173, 234314934656326, 541058050782226, 9037151432596, 105110321661077, 433235351491338, 380403664157549, 443083986774524, 211767988051975, 294882496728535, 419385570990417, 158818843656067, 166195854081529, 514901406705991, 271668961546767, 462422093668291, 470098800730081, 12656255767568, 55616682008132, 236595039339609, 127800967248499, 318679037672203, 426383507625445, 255058444284178, 379672023087632, 384544983203357, 505607947153000, 320354213848896, 80651178832735, 97798512606589, 484822843255411, 258380032851544, 336208511602430, 229765438724493, 277699680982381, 486899847212291, 145185678315742, 270935941325794, 235065062201460, 560183904089704, 188396916764928, 471436357137203, 397251163094861, 75108608044028, 101427407444788, 392652028373828, 393141983625276, 224613685231130, 125546042237235, 472962451185219],
}