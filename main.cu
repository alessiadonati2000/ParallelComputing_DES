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
using namespace constants;
using namespace std;
using namespace chrono;

int main() {
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
    int numPassword = 100;                          // grandezza del dizionario (1M password)
    int length = 8;                                 // lunghezza delle password
    vector<int> blockSizes = {32, 64, 128, 256};    // block size CUDA da testare
    int nCrack = 1000;                              // numero di password da craccare
    int nTests = 10;                                // ripetizioni dell'esperimento
    uint64_t key = toUint64_T("a2kvt8rz");     // chiave DES fissa per cifrare e tentare il brute force

    // Se esiste già il dizionario
    if (filesystem::exists(passwordPath) && !overwrite) {

        // Crea un vettore (pwdList) con tutte le parole del file specificato
        ifstream passwordsFile(passwordPath);
        string pwd;
        int pwdCount = 0;
        auto *pwdList = new uint64_t [numPassword];
        while (getline(passwordsFile, pwd) && pwdCount < numPassword) {   // legge il file riga per riga
            pwdList[pwdCount] = toUint64_T(pwd);                  // converte ogni parola in uint64_t
            pwdCount++;
        }
        passwordsFile.close();

        // Generazione set di test
        random_device rd;           // a seed source for the random number engine
        mt19937 gen(rd());      // mersenne_twister_engine seeded with rd()
        uniform_int_distribution<> distrib(0, numPassword);

        vector<uint64_t*> tests;    // lista degli hash (password da craccare)
        // sceglie a caso, secondo una distribuzione uniforme, una password dal dizionario
        // la cifra con DES, ottendo così gli hash da craccare
        for(int idTest = 0; idTest < nTests; idTest++){    // per ogni test fino a nTests
            auto test = new uint64_t[nCrack];
            for (int i = 0; i < nCrack; i++){
                test[i] = desEncrypt(key, pwdList[distrib(gen)]);
            }
            tests.push_back(test);
        }


        cout << "------------------ Experiments parameters ------------------";
        cout << "\nSearch space: " << numPassword;
        cout << "\nPasswords lengths: " << length;
        cout << "\nNumber of passwords to crack: " << nCrack;
        cout << "\nBlock sizes to test: " << toString<int>(blockSizes);
        cout << "\nNumber of tests for each experiment: " << nTests;


        cout << "\n------------------ Sequential Experiment ------------------\n";
        vector<double> sTimes = {};
        for (auto &pwdToCrack: tests) {    // per ogni password da craccare
            cout << "Test started " << endl;
            auto start = system_clock::now();

            for (int i = 0; i < nCrack; i++){
                for (int j = 0; j < numPassword; j++){    // prova tutte le N password del dizionario
                    if (pwdToCrack[i] == desEncrypt(key, pwdList[j]))   // le cifra e le confronta
                        break;
                }
            }

            auto end = system_clock::now();
            auto seqElapsed = duration_cast<milliseconds>(end - start);
            sTimes.push_back((double)seqElapsed.count());
            printf("Passwords cracked ( %f ms)\n", sTimes.back());
        }
        double sAvg = accumulate(sTimes.begin(), sTimes.end(), 0.0) / (double)sTimes.size();
        printf("Average time per experiment (ms): %4.2f\n", sAvg);


        cout << "\n------------------ Parallel Experiment ------------------\n";
        vector<double> pAvg = {};
        vector<double> speedUps = {};
        for (auto &blockSize: blockSizes) {      // per ciascun valore di blockSize (32, 64, 126, 256)
            printf("Block size: %d\n", blockSize);
            vector<double> pTimes = {};

            for (auto &test: tests) {       // per ogni password da craccare
                cout << "Test started" << endl;
                bool *found;
                auto start = system_clock::now();

                found = parallelCrack(pwdList, numPassword, test, nCrack, key, blockSize);

                auto end = system_clock::now();
                auto parElapsed = duration_cast<milliseconds>(end - start);
                pTimes.push_back((double)parElapsed.count());
                printf("Passwords cracked ( %f ms)\n", pTimes.back());

                for(int i = 0; i < nCrack; i++){
                    if (!found[i])
                        printf("Error occurred");
                }

                free(found);
            }
            pAvg.push_back(accumulate(pTimes.begin(), pTimes.end(), 0.0) / (double)pTimes.size());
            speedUps.push_back(sAvg / pAvg.back());
            printf("\nAverage time per block size = %d: %4.2f \n", blockSize, pAvg.back());
            printf("\nSpeedup: %4.2fx\n", speedUps.back());

        }
        cout << "\nAverage time per experiments (ms): " << toString<double>(pAvg);
        cout << "\nSpeedups: " << toString<double>(speedUps);


        if (saveResults){
            ofstream resultsFile(resultsPath);  // crea e/o apre il file dei risultati
            resultsFile << "------------------ Experiments parameters ------------------";
            resultsFile << "\nSearch space: " << numPassword;
            resultsFile << "\nPasswords lengths: " << length;
            resultsFile << "\nNumber of passwords to crack: " << nCrack;
            resultsFile << "\nNumber of tests for each experiment: " << nTests;
            resultsFile << "\n------------------ Sequential Experiment ------------------";
            resultsFile << "\nAverage time per experiment (ms): " << sAvg;
            resultsFile << "\n------------------ Parallel Experiment ------------------";
            resultsFile << "\nBlock sizes tested: " << toString(blockSizes);
            resultsFile << "\nAverage time per experiments (ms): " << toString(pAvg);
            resultsFile << "\nSpeedups: " << toString(speedUps);
        }
        free(pwdList);
    } else {
        // Altrimenti genera il dizionario
        vector<string> passwords = passwordsGeneration(numPassword, length);
        ofstream passwordsFile(passwordPath);

        for(const auto& password : passwords){
            passwordsFile << password << "\n";
        }
        passwordsFile.close();
        cout << "New password file created" << endl;
    }


    return 0;
}
