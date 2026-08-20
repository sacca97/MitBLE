NVCCFLAGS += -ccbin /usr/bin/g++-15

bruteforcer:
	nvcc -O3 --use_fast_math -arch=sm_120 -Xptxas=-O3 -Xcompiler=-O3 -o aes_bruteforcer_ble_asm aes_bruteforcer_ble_asm.cu