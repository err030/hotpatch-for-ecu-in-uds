#include "hp_helper.h"

HOTPATCH_FUNCTION_START_NAKED(stabilizerTask, 0xDA, replacement, 0x0) {
    __asm__ volatile(
		".short 0xE00F\n"
	);
}

// function entry 0x801da8c
// patch address 0x801db5e
// return address 0x801db7a

// function entry: 200133e0
// patch address: 200134ba
// return address: 200134dc

/*
200134b6:	f5a8 63fa 	sub.w	r3, r8, #2000	@ 0x7d0
200134ba:	17db      	asrs	r3, r3, #31
200134bc:	ee07 3a90 	vmov	s15, r3
200134c0:	ed94 7a03 	vldr	s14, [r4, #12]
200134c4:	eef8 7ae7 	vcvt.f32.s32	s15, s15
200134c8:	eef7 6a00 	vmov.f32	s13, #112	@ 0x3f800000  1.0
200134cc:	ee67 7a87 	vmul.f32	s15, s15, s14
200134d0:	ed9f 7abf 	vldr	s14, [pc, #764]	@ 200137d0 <stabilizerTask+0x3f0>
200134d4:	edc4 7a03 	vstr	s15, [r4, #12]
200134d8:	edd4 7a0a 	vldr	s15, [r4, #40]	@ 0x28
200134dc:	ee67 7a88 	vmul.f32	s15, s15, s16
200134e0:	a905      	add	r1, sp, #20
*/