cmake_minimum_required(VERSION 3.28)
project(DES LANGUAGES C CXX CUDA)
find_package(CUDAToolkit REQUIRED)
set(CMAKE_CUDA_ARCHITECTURES "75")
include_directories(C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.5/include)
set(CMAKE_CUDA_STANDARD 17)

add_executable(DES    # crea un eseguibile chiamato DES compilando
        main.cu             # main del programma
        utility.h           # funzioni di supporto
        DES_parallel.cu     # codice CUDA
        DES_parallel.cuh
        DES.cpp             # implementazione CPU
        DES.h
)

# Viene tutto compilato in un unico passaggio
set_target_properties(DES PROPERTIES
        CUDA_SEPARABLE_COMPILATION OFF)

# Il compilatore CUDA stampa informazioni dettagliate sull'uso di risorse GPU
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v")

