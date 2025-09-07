cmake_minimum_required(VERSION 3.28)    # server la versione 3.28 di CMake
project(DES LANGUAGES C CXX CUDA)       # nome del progetto: DES # linguaggi utilizzati: C, C++, CUDA
find_package(CUDAToolkit REQUIRED)      # ricerca del toolkit CUDA
include_directories(C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.5/include)
set(CMAKE_CUDA_STANDARD 17)             # imposta lo standard a C++ 17

add_executable(DES    # crea un eseguibile chiamato DES compilando
        main.cu       # main del programma
        utils.h       # funzioni di supporto
        d_DES.cu      # codice CUDA
        d_DES.cuh
        DES.cpp       # implementazione CPU
        DES.h
)

set_target_properties(DES PROPERTIES
        CUDA_SEPARABLE_COMPILATION OFF)    # viene tutto compilato in un unico passaggio

# il compilatore CUDA stampa informazioni dettagliate sull'uso di risorse GPU
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v")

