#include <iostream>     // per input/output
#include <string>
#include <random>
#include <filesystem>   // per controllare l'esistenza del file
#include <fstream>      // per leggere e scrivere il file
#include <cstdint>      // per i tipi a 64 bit
#include <chrono>       // per misurare i tempi
#include <sstream>      // per creare stringhe formattate
#include <numeric>      // per funzioni matematiche
#include <iomanip>      // PER FORMATTARE L'OUTPUT IN FILE
#include <cuda_runtime.h>

#include "utility.h"           // per funzioni di utilità
#include "DES.h"               // per DES lato CPU
#include "DES_parallel.cuh"    // per DES lato CUDA

int main() {
    string passwordPath = R"(C:\Users\AleDo\CLionProjects\ParallelComputing_DES\password.txt)";

    auto time = std::time(nullptr);
    auto localTime = *std::localtime(&time);
    std::ostringstream date;
    date << std::put_time(&localTime, "%Y%m%d-%H%M%S");
    string resultsPath = R"(C:\Users\AleDo\CLionProjects\ParallelComputing_DES\Results\results-)" + date.str() + "RELEASE.txt";

    bool overwrite = false;                         // se true rigenera il dizionario anche se esiste
    int pwdNum = 1000000;                           // grandezza del dizionario
    int pwdLength = 8;                              // lunghezza delle password
    int numCrack = 1000;                             // numero di password da decifrare
    int numTests = 10;                              // ripetizioni dell'esperimento
    vector<int> blockSizes = {32, 64, 128, 256};    // block size CUDA da testare
    uint64_t key = toUint64_T("a2kvt8rz");    // chiave DES fissa per cifrare

    if (filesystem::exists(passwordPath) && !overwrite) {
        // Creo una lista delle password estraendole dal file
        ifstream passwordsFile(passwordPath);
        string pwd;
        int pwdCount = 0;
        auto *pwdList = new uint64_t [pwdNum];      // pwdList: è una lista che conterrà tutte le password del file
        while (getline(passwordsFile, pwd) && pwdCount < pwdNum) {   // legge il file riga per riga
            pwdList[pwdCount] = toUint64_T(pwd);                           // converte ogni password in uint64_t e la aggiunge alla lista
            pwdCount++;
        }
        passwordsFile.close();

        // Generazione set di test: creo numTest test con numCrack password scelte secondo una distribuzione uniforme
        // queste numCrack password vengono criptate
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> distrib(0, pwdNum); // TODO: avevo messo pwdNum - 1
        vector<uint64_t*> tests;
        for(int idTest = 0; idTest < numTests; idTest++){
            auto test = new uint64_t[numCrack];
            for (int i = 0; i < numCrack; i++){
                test[i] = desEncrypt(key, pwdList[distrib(gen)]);
            }
            tests.push_back(test);
        }

        cout << "\n========================================================" << endl;
        cout << "           PARAMETRI DELL'ESPERIMENTO" << endl;
        cout << "========================================================" << endl;
        printf("Numero password nel dizionario: %d\n", pwdNum);
        printf("Lunghezza password (caratteri): %d\n", pwdLength);
        printf("Password da decifrare per test: %d\n", numCrack);
        printf("Numero di test da eseguire:     %d\n", numTests);
        cout << "Block size CUDA da testare:     " << toString<int>(blockSizes) << endl;


        cout << "\n========================================================" << endl;
        cout << "           ESPERIMENTO SEQUENZIALE (CPU)" << endl;
        cout << "========================================================" << endl;
            vector<double> sequentialTimes = {};
            int i = 0;
            // Per ciascun test contenuto in tests
            for (auto &pwdToCrack: tests) {
                printf("Avvio test sequenziale %d/%d...\n", i + 1, (int)tests.size());
                i++;
                auto start = chrono::system_clock::now();

                // Ogni password del test (criptata) viene confrontata con le password del dizionario una ad una (che vengono qui criptate al volo)
                // Se coincidono ho trovato la password
                for (int i = 0; i < numCrack; i++){
                    for (int j = 0; j < pwdNum; j++){
                        if (pwdToCrack[i] == desEncrypt(key, pwdList[j])) {
                            break;
                        }
                    }
                }

                auto end = chrono::system_clock::now();
                auto sequentialElapsed = chrono::duration_cast<chrono::milliseconds>(end - start);
                sequentialTimes.push_back((double)sequentialElapsed.count());
                printf("Test %d/%d completato: %4.2f ms\n", i + 1, (int)tests.size(), sequentialTimes.back());
            }

            double sequentialAvg = accumulate(sequentialTimes.begin(), sequentialTimes.end(), 0.0) / (double)sequentialTimes.size();
            printf("\nTempo MEDIO sequenziale: %4.2f ms\n", sequentialAvg);


        cout << "\n========================================================" << endl;
        cout << "           ESPERIMENTO PARALLELO (CUDA)" << endl;
        cout << "========================================================" << endl;
            vector<double> parallelAvg = {};
            vector<double> speedUps = {};

            for (auto &blockSize: blockSizes) {
                printf("\n------------- Test con Block Size: %d -------------\n", blockSize);
                vector<double> parallelTimes = {};
                int i = 0;

                for (auto &pwdToCrack: tests)  {
                    printf("Avvio test parallelo %d/%d (Block size: %d)...\n", i + 1, (int)tests.size(), blockSize);
                    i++;
                    bool *found;
                    auto start = chrono::system_clock::now();

                    found = parallelCrack(pwdList, pwdNum, pwdToCrack, numCrack, key, blockSize);

                    auto end = chrono::system_clock::now();
                    auto parallelElapsed = chrono::duration_cast<chrono::milliseconds>(end - start);
                    parallelTimes.push_back((double)parallelElapsed.count());
                    printf("Test %d/%d completato: %4.2f ms\n", i + 1, (int)tests.size(), parallelTimes.back());

                    for(int i = 0; i < numCrack; i++){
                        if (!found[i])
                            printf("Error occurred");
                    }

                    free(found);
                }

                parallelAvg.push_back(accumulate(parallelTimes.begin(), parallelTimes.end(), 0.0) / (double)parallelTimes.size());
                speedUps.push_back(sequentialAvg / parallelAvg.back());
                printf("\nTempo MEDIO (Block size %d): %4.2f ms\n", blockSize, parallelAvg.back());
                printf("Speedup vs Sequenziale: %4.2fx\n", speedUps.back());
            }

        // ---------- SINTESI RISULTATI (CONSOLE) ----------
        cout << "\n\n========================================================" << endl;
        cout << "                 SINTESI DEI RISULTATI" << endl;
        cout << "========================================================" << endl;
        printf("Parametri: %d password, %d da decifrare, %d test\n", pwdNum, numCrack, numTests);
        cout << "--------------------------------------------------------" << endl;

        // Intestazioni tabella
        printf("%-20s | %-18s | %-10s\n", "Metodo", "Tempo Medio (ms)", "Speedup");
        printf("---------------------+--------------------+-----------\n");

        // Riga Sequenziale
        printf("%-20s | %-18.2f | %-10.2fx\n", "Sequenziale (CPU)", sequentialAvg, 1.0);

        // Righe Parallele
        for (size_t i = 0; i < blockSizes.size(); ++i) {
            string methodName = "Parallelo (BS: " + to_string(blockSizes[i]) + ")";
            printf("%-20s | %-18.2f | %-10.2fx\n", methodName.c_str(), parallelAvg[i], speedUps[i]);
        }
        cout << "========================================================" << endl;


        // ---------- SCRITTURA FILE DI RISULTATI ----------
        ofstream resultsFile(resultsPath);
        resultsFile << "========================================================" << endl;
        resultsFile << "           PARAMETRI DELL'ESPERIMENTO" << endl;
        resultsFile << "========================================================" << endl;
        resultsFile << "Numero password nel dizionario: " << pwdNum << "\n";
        resultsFile << "Lunghezza password (caratteri): " << pwdLength << "\n";
        resultsFile << "Password da decifrare per test: " << numCrack << "\n";
        resultsFile << "Numero di test da eseguire: " << numTests << "\n";
        resultsFile << "Block size CUDA testati: " << toString<int>(blockSizes) << "\n";
        resultsFile << "--------------------------------------------------------\n";

        resultsFile << "\n========================================================" << endl;
        resultsFile << "                 SINTESI DEI RISULTATI" << endl;
        resultsFile << "========================================================" << endl;

        // Uso di stringstream e iomanip per formattare la tabella nel file
        std::stringstream ss;
        ss << std::left; // Allinea a sinistra

        // Intestazioni
        ss << std::setw(20) << "Metodo" << " | ";
        ss << std::setw(20) << "Tempo Medio (ms)" << " | ";
        ss << std::setw(12) << "Speedup" << "\n";

        ss << std::setw(20) << "--------------------" << " | ";
        ss << std::setw(20) << "--------------------" << " | ";
        ss << std::setw(12) << "------------" << "\n";

        // Riga Sequenziale
        ss << std::setw(20) << "Sequenziale (CPU)" << " | ";
        ss << std::setw(20) << std::fixed << std::setprecision(2) << sequentialAvg << " | ";
        ss << std::setw(10) << std::fixed << std::setprecision(2) << 1.0 << "x\n";

        // Righe Parallele
        for (size_t i = 0; i < blockSizes.size(); ++i) {
            string methodName = "Parallelo (BS: " + to_string(blockSizes[i]) + ")";
            ss << std::setw(20) << methodName << " | ";
            ss << std::setw(20) << std::fixed << std::setprecision(2) << parallelAvg[i] << " | ";
            ss << std::setw(10) << std::fixed << std::setprecision(2) << speedUps[i] << "x\n";
        }
        ss << "========================================================\n";

        resultsFile << ss.str();
        resultsFile.close();

        cout << "\nRisultati salvati in: " << resultsPath << endl;

        free(pwdList);
        // TODO: questo lo ho aggiunto io
        /*for(auto test : tests) {
            delete[] test;
        }
        tests.clear();*/

    } else {
        vector<string> passwords = passwordsGeneration(pwdNum, pwdLength);
        ofstream passwordsFile(passwordPath);

        for(const auto& password : passwords){
            passwordsFile << password << "\n";
        }
        passwordsFile.close();
        cout << "Nuovo file password creato in: " << passwordPath << endl;
        cout << "Riesegui il programma per avviare gli esperimenti." << endl;
    }

    return 0;
}