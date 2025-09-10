#include <iostream>     // per input/output
#include <string>
#include <random>
#include <filesystem>   // per controllare l'esistenza del file
#include <fstream>      // per leggere e scrivere il file
#include <cstdint>      // per i tipi a 64 bit
#include <chrono>       // per misurare i tempi
#include <sstream>      // per creare stringhe formattate
#include <numeric>      // per funzioni matematiche
#include "utility.h"      // per funzioni di utilità
#include "DES.h"        // per DES lato CPU
#include "DES_parallel.cuh"    // per DES lato CUDA
#include <cuda_runtime.h>
using namespace constants;
using namespace std;
using namespace chrono;

int main() {
    // Verifica problemi CUDA
    int deviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);
    fprintf(stdout, "cudaGetDeviceCount -> %d, err=%d (%s)\n",
            deviceCount, (int)err,
            (cudaGetErrorString(err) ? cudaGetErrorString(err) : "NULL"));

    if (deviceCount > 0) {
        cudaDeviceProp prop;
        if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess) {
            fprintf(stdout, "Device 0: %s  computeCapability=%d.%d  totalGlobalMem=%zuMB\n",
                    prop.name, prop.major, prop.minor, (size_t)(prop.totalGlobalMem / (1024*1024)));
        } else {
            fprintf(stderr, "cudaGetDeviceProperties failed\n");
        }
    } else {
        fprintf(stderr, "No CUDA devices found or initialization failed.\n");
    }


    // Dizionario delle password
        string passwordPath = R"(C:\Users\AleDo\CLionProjects\ParallelComputing_DES\password.txt)";

    // Genera un timestamp per avere un nome univoco dei file dei risultati
        auto time = std::time(nullptr);
        auto localTime = *std::localtime(&time);
        std::ostringstream ss;
        ss << std::put_time(&localTime, "%Y%m%d-%H%M%S");
        auto str = ss.str();
        string resultsPath = R"(C:\Users\AleDo\CLionProjects\ParallelComputing_DES\Results\results-)" + ss.str() + ".txt";

    // Parametri dell'esperimento
        bool overwrite = false;                         // se true rigenera il dizionario anche se esiste
        bool saveResults = true;                        // salva su file i risultati
        int pwdNum = 1000;                            // grandezza del dizionario
        int pwdLength = 8;                              // lunghezza delle password
        int numCrack = 1000;                            // numero di password da craccare
        int numTests = 10;                              // ripetizioni dell'esperimento
        vector<int> blockSizes = {32, 64, 128, 256};    // block size CUDA da testare
        uint64_t key = toUint64_T("a2kvt8rz");     // chiave DES fissa per cifrare e tentare il brute force

    // Se esiste già il dizionario
    if (filesystem::exists(passwordPath) && !overwrite) {

        // Crea un vettore (pwdList) con tutte le password del file
            ifstream passwordsFile(passwordPath);   // apro il file delle password
            string pwd;                             // pwd: una password
            int pwdCount = 0;                       // pwdCount: contatore delle password
            auto *pwdList = new uint64_t [pwdNum];  // pwdList: è una lista che conterrà tutte le password del file

            while (getline(passwordsFile, pwd) && pwdCount < pwdNum) {   // legge il file riga per riga
                pwdList[pwdCount] = toUint64_T(pwd);                           // converte ogni password in uint64_t e la aggiunge alla lista
                pwdCount++;
            }
            passwordsFile.close();

        // Generazione set di test
            random_device rd;           // a seed source for the random number engine
            mt19937 gen(rd());      // mersenne_twister_engine seeded with rd()
            uniform_int_distribution<> distrib(0, pwdNum-1);
            vector<uint64_t*> tests;    // lista degli hash (password cifrate)
            // La procedura è ripetuta numTests (10) volte, quindi avrò 10 test ciascuno con 1000 pwd cifrate
            for(int idTest = 0; idTest < numTests; idTest++){
                auto test = new uint64_t[numCrack];     // è un array che contiene numCrack password da craccare
                // Dal file sceglie a caso, secondo una distribuzione uniforme, 1000 pwd dal dizionario (pwdList) e si cifrano (desEncrypt)
                for (int i = 0; i < numCrack; i++){
                    test[i] = desEncrypt(key, pwdList[distrib(gen)]);
                }
                tests.push_back(test);
            }


        cout << "------------------ Experiments parameters ------------------";
        cout << "\nNumber of password in the dictionary: " << pwdNum;
        cout << "\nPasswords lengths (bit): " << pwdLength;
        cout << "\nNumber of passwords to crack: " << numCrack;
        cout << "\nNumber of tests: " << numTests;
        cout << "\nBlock sizes to test: " << toString<int>(blockSizes);


        cout << "\n------------------ Sequential Experiment ------------------\n";
            vector<double> sequentialTimes = {};

            // Per ogni test in tests, mi prendo le password cifrate e le metto in pwdToCrack
            for (auto &pwdToCrack: tests) {
                cout << "Test started " << endl;
                auto start = system_clock::now();

                // per ogni password da decifrare in pwdToCrack (in totale sono numCrack)
                for (int i = 0; i < numCrack; i++){
                    // scorri tutto il dizionario fino a quando non trovi un match
                    for (int j = 0; j < pwdNum; j++){
                        // le cifra e le confronta la versione cifrata, se coincidono gli hash ho fatto
                        if (pwdToCrack[i] == desEncrypt(key, pwdList[j]))
                            break;
                    }
                }

                auto end = system_clock::now();
                auto seqElapsed = duration_cast<milliseconds>(end - start);
                sequentialTimes.push_back((double)seqElapsed.count());
                printf("Passwords cracked (%f ms)\n", sequentialTimes.back());
            }
            double sequentialAvg = accumulate(sequentialTimes.begin(), sequentialTimes.end(), 0.0) / (double)sequentialTimes.size();
            printf("\nAverage time per experiment (ms): %4.2f\n", sequentialAvg);


        cout << "\n------------------ Parallel Experiment ------------------\n";
            vector<double> parallelAvg = {};
            vector<double> speedUps = {};

            for (auto &blockSize: blockSizes) {
                printf("------------- Block size: %d -------------\n", blockSize);
                vector<double> parallelTimes = {};

                for (auto &pwdToCrack: tests) {
                    cout << "Test started" << endl;
                    bool *found;
                    auto start = system_clock::now();

                    found = parallelCrack(pwdList, pwdNum, pwdToCrack, numCrack, key, blockSize);

                    auto end = system_clock::now();
                    auto parallelElapsed = duration_cast<milliseconds>(end - start);
                    parallelTimes.push_back((double)parallelElapsed.count());
                    printf("Passwords cracked (%f ms)\n", parallelTimes.back());

                    for(int i = 0; i < numCrack; i++){
                        if (!found[i])
                            printf("Error occurred");
                    }

                    free(found);
                }
                parallelAvg.push_back(accumulate(parallelTimes.begin(), parallelTimes.end(), 0.0) / (double)parallelTimes.size());
                speedUps.push_back(sequentialAvg / parallelAvg.back());
                printf("\nAverage time per block size = %d: %4.2f \n", blockSize, parallelAvg.back());
                printf("Speedup: %4.2fx\n\n", speedUps.back());

            }
            cout << "\nAverage time per experiments (ms): " << toString<double>(parallelAvg);
            cout << "\nSpeedups: " << toString<double>(speedUps) << "\n";


        if (saveResults){
            ofstream resultsFile(resultsPath);  // crea e/o apre il file dei risultati
            resultsFile << "------------------ Experiments parameters ------------------";
            resultsFile << "\nSearch space: " << pwdNum;
            resultsFile << "\nPasswords lengths: " << pwdLength;
            resultsFile << "\nNumber of passwords to crack: " << numCrack;
            resultsFile << "\nNumber of tests for each experiment: " << numTests;
            resultsFile << "\n------------------ Sequential Experiment ------------------";
            resultsFile << "\nAverage time per experiment (ms): " << sequentialAvg;
            resultsFile << "\n------------------ Parallel Experiment ------------------";
            resultsFile << "\nBlock sizes tested: " << toString(blockSizes);
            resultsFile << "\nAverage time per experiments (ms): " << toString(parallelAvg);
            resultsFile << "\nSpeedups: " << toString(speedUps);
        }
        //free(pwdList);
    } else {
        // Altrimenti genera il dizionario
        vector<string> passwords = passwordsGeneration(pwdNum, pwdLength);
        ofstream passwordsFile(passwordPath);

        for(const auto& password : passwords){
            passwordsFile << password << "\n";
        }
        passwordsFile.close();
        cout << "New password file created" << endl;
    }


    return 0;
}
