#include <iostream>     // per input/output
#include <string>
#include <random>
#include <filesystem>   // per controllare l'esistenza del file
#include <fstream>      // per leggere e scrivere il file
#include <cstdint>      // per i tipi a 64 bit
#include <chrono>       // per misurare i tempi
#include <sstream>      // per creare stringhe formattate
#include <numeric>      // per funzioni matematiche
#include <cuda_runtime.h>
#include "utility.h"           // per funzioni di utilità
#include "DES.h"               // per DES lato CPU
#include "DES_parallel.cuh"    // per DES lato CUDA

using namespace constants;
using namespace std;
using namespace chrono;

int main() {
    string passwordPath = R"(C:\Users\AleDo\CLionProjects\ParallelComputing_DES\password.txt)";

    auto time = std::time(nullptr);
    auto localTime = *std::localtime(&time);
    std::ostringstream date;
    date << std::put_time(&localTime, "%Y%m%d-%H%M%S");
    string resultsPath = R"(C:\Users\AleDo\CLionProjects\ParallelComputing_DES\Results\results-)" + date.str() + ".txt";

    bool overwrite = false;                         // se true rigenera il dizionario anche se esiste
    int pwdNum = 1000;                              // grandezza del dizionario
    int pwdLength = 8;                              // lunghezza delle password
    int numCrack = 1000;                            // numero di password da decifrare
    int numTests = 10;                              // ripetizioni dell'esperimento
    vector<int> blockSizes = {32, 64, 128, 256};    // block size CUDA da testare
    uint64_t key = toUint64_T("a2kvt8rz");     // chiave DES fissa per cifrare

    if (filesystem::exists(passwordPath) && !overwrite) {
        ifstream passwordsFile(passwordPath);
        string pwd;
        int pwdCount = 0;
        auto *pwdList = new uint64_t [pwdNum];      // pwdList: è una lista che conterrà tutte le password del file

        while (getline(passwordsFile, pwd) && pwdCount < pwdNum) {   // legge il file riga per riga
            pwdList[pwdCount] = toUint64_T(pwd);                           // converte ogni password in uint64_t e la aggiunge alla lista
            pwdCount++;
        }
        passwordsFile.close();

        // Generazione set di test: numTest test con numCrack password scelte secondo una distribuzione uniforme
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> distrib(0, pwdNum-1);
        vector<uint64_t*> tests;
        for(int idTest = 0; idTest < numTests; idTest++){
            auto test = new uint64_t[numCrack];
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
        cout << "\nBlock sizes to test: " << toString<int>(blockSizes) << endl;


        cout << "\n------------------ Sequential Experiment ------------------\n";
            vector<double> sequentialTimes = {};

            for (auto &pwdToCrack: tests) {
                cout << "Test started " << endl;
                auto start = system_clock::now();

                for (int i = 0; i < numCrack; i++){
                    for (int j = 0; j < pwdNum; j++){
                        if (pwdToCrack[i] == desEncrypt(key, pwdList[j]))
                            break;
                    }
                }

                auto end = system_clock::now();
                auto sequentialElapsed = duration_cast<milliseconds>(end - start);
                sequentialTimes.push_back((double)sequentialElapsed.count());
                printf("Passwords cracked (%f ms)\n", sequentialTimes.back());
            }

            double sequentialAvg = accumulate(sequentialTimes.begin(), sequentialTimes.end(), 0.0) / (double)sequentialTimes.size();
            printf("\nAverage time per test (ms): %4.2f\n", sequentialAvg);


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


        ofstream resultsFile(resultsPath);
        resultsFile << "------------------ Experiments parameters ------------------";
        resultsFile << "\nNumber of password in the dictionary: " << pwdNum;
        resultsFile << "\nPasswords lengths (bit): " << pwdLength;
        resultsFile << "\nNumber of passwords to crack: " << numCrack;
        resultsFile << "\nNumber of tests: " << numTests;
        resultsFile << "\n------------------ Sequential Experiment ------------------";
        resultsFile << "\nAverage time per experiment (ms): " << sequentialAvg;
        resultsFile << "\n------------------- Parallel Experiment -------------------";
        resultsFile << "\nBlock sizes tested: " << toString(blockSizes);
        resultsFile << "\nAverage time per experiments (ms): " << toString(parallelAvg);
        resultsFile << "\nSpeedups: " << toString(speedUps);

    } else {
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
