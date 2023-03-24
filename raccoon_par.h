//  raccoon_par.h

//  === Raccoon signature scheme -- parameters.

#ifndef _RACCOON_PAR_H_
#define _RACCOON_PAR_H_

//  select default parameter set
#ifndef RACC_BENCH
#define RACCOON_128_32
#endif

//  parameter sets

#if defined( RACCOON_128_2 )

#define RACC_SEC    16
#define RACC_Q      549824583172097
#define RACC_LPT    12
#define RACC_LPW    43
#define RACC_N      512
#define RACC_K      8
#define RACC_ELL    3
#define RACC_W      19
#define RACC_D      2
#define RACC_B22    1500
#define RACC_BOO    1
#define RACC_CTT    1535
#define RACC_CTW    1091155339404

#elif defined( RACCOON_128_4 )

#define RACC_SEC    16
#define RACC_Q      549824583172097
#define RACC_LPT    12
#define RACC_LPW    43
#define RACC_N      512
#define RACC_K      8
#define RACC_ELL    3
#define RACC_W      19
#define RACC_D      4
#define RACC_B22    2500
#define RACC_BOO    3
#define RACC_CTT    1790
#define RACC_CTW    1636733009107

#elif defined( RACCOON_128_8 )

#define RACC_SEC    16
#define RACC_Q      549824583172097
#define RACC_LPT    11
#define RACC_LPW    43
#define RACC_N      512
#define RACC_K      8
#define RACC_ELL    3
#define RACC_W      19
#define RACC_D      8
#define RACC_B22    4096
#define RACC_BOO    4
#define RACC_CTT    959
#define RACC_CTW    1909521843958

#elif defined( RACCOON_128_16 )

#define RACC_SEC    16
#define RACC_Q      549824583172097
#define RACC_LPT    11
#define RACC_LPW    43
#define RACC_N      512
#define RACC_K      8
#define RACC_ELL    3
#define RACC_W      19
#define RACC_D      16
#define RACC_B22    8192
#define RACC_BOO    6
#define RACC_CTT    991
#define RACC_CTW    2045916261384

#elif defined( RACCOON_128_32 )

#define RACC_SEC    16
#define RACC_Q      549824583172097
#define RACC_LPT    10
#define RACC_LPW    43
#define RACC_N      512
#define RACC_K      8
#define RACC_ELL    3
#define RACC_W      19
#define RACC_D      32
#define RACC_B22    16384
#define RACC_BOO    8
#define RACC_CTT    502
#define RACC_CTW    2114113470096

#elif defined( RACCOON_192_32 )

#define RACC_SEC    24
#define RACC_Q      549824583172097
#define RACC_LPT    6
#define RACC_LPW    40
#define RACC_N      512
#define RACC_K      11
#define RACC_ELL    5
#define RACC_W      31
#define RACC_D      32
#define RACC_B22    32768
#define RACC_BOO    8
#define RACC_CTT    30
#define RACC_CTW    499130175376

#elif defined( RACCOON_256_32 )

#define RACC_SEC    32
#define RACC_Q      549824583172097
#define RACC_LPT    7
#define RACC_LPW    42
#define RACC_N      512
#define RACC_K      14
#define RACC_ELL    6
#define RACC_W      44
#define RACC_D      32
#define RACC_B22    21000
#define RACC_BOO    8
#define RACC_CTT    62
#define RACC_CTW    2096644979110

#else

//  no parameters defined
#error  "No known parameter defined."

#endif

//  shared / derived parameters
#define RACC_LGQ    49
#define RACC_LGN    9
#define RACC_QMSK   ((1LL << RACC_LGQ) - 1)
#define RACC_LGW    (RACC_LGQ - RACC_LPW)
#define RACC_QT     (RACC_Q >> RACC_LPT)
#define RACC_QW     (RACC_Q >> RACC_LPW)

//  _RACCOON_PAR_H_
#endif
