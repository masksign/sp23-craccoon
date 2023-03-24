#!/bin/bash

rm -f bench.txt

for dut in \
	RACCOON_128_2	\
	RACCOON_128_4	\
	RACCOON_128_8	\
	RACCOON_128_16	\
	RACCOON_128_32	\
	RACCOON_192_32	\
	RACCOON_256_32
do
	make clean
	make RACCF="-D"$dut" -DRACC_BENCH=10.0"
	./xtest >> bench.txt
done
