//C internal library 
#include <iostream>
using std::endl;
using std::cout;
using std::cin;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;
#include "assert.h"

//Cryptopp Librari
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#endif

#include <chrono>
#include <locale>
#include <string>
using std::string;
#include <cstdlib>
using std::exit;
#include "assert.h"

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

using namespace std;
using namespace CryptoPP;

#include "mypackages/AES_Cipher.h"
#include "mypackages/convert.h"
#include "mypackages/userio.h"

const string INPUT_FILE_NAME[8] = {"test1.txt", "test2.txt", "test3.txt", "test4.txt", "test5.txt", "test6.txt", "test7.txt", "test8.txt"};

int main(){
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
    #endif
  
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    
    string mode;
    int modeSelection;
    int inputSelection;

    int keySize = AES::DEFAULT_KEYLENGTH, ivSize = AES::BLOCKSIZE;

    // Select mode
    cout << ">>> Select AES mode:" << endl
          << "1. ECB" << endl
          << "2. CBC" << endl
          << "3. OFB" << endl
          << "4. CFB" << endl
          << "5. CTR" << endl
          << "6. XTS" << endl
          << "7. CCM" << endl
          << "8. GCM" << endl
          << "Please enter your number (1/2/3/4/5/6/7/8):" << endl
          << "> ";

    cin >> modeSelection;
    cin.ignore();

    // Set mode, keySize and ivSize
    switch (modeSelection) {
        case 1: 
            mode = "ECB";
            ivSize = 0;
            break;
        case 2: 
            mode = "CBC";
            break;
        case 3: 
            mode = "OFB";
            break;
        case 4: 
            mode = "CFB";
            break;
        case 5: 
            mode = "CTR";
            break;
        case 6: 
            mode = "XTS";
            keySize = 32;
            break;
        case 7: 
            mode = "CCM";
            ivSize = 12;
            break;
        case 8: 
            mode = "GCM";
            break;
        default:
            cout << "Invalid input!" << endl;
            exit(0);
            break;
    }

    AES_Cipher aes(mode);
    CryptoPP::byte *key = nullptr;
    CryptoPP::byte *iv = nullptr;

    while (true){
        int userChoice;
        cout << "What would you like to do?" << endl
             << "1. Generate KEY/IV" << endl
             << "2. Encrypt" << endl
             << "3. Decrypt" << endl
             << "4. Quit" << endl
             << "> ";
        cin >> userChoice;
        cin.ignore();
        switch (userChoice){
            case 1:{
                // Generate KEY
                cout << ">>> How would you like to generate KEY?" << endl
                    << "1. Random" << endl
                    << "2. Input from screen" << endl
                    << "3. Input from file" << endl
                    << "Please enter your number (1/2/3)?" << endl << "> ";
                cin >> inputSelection;
                cin.ignore();
                key = generateBlock(keySize, inputSelection, "KEY");
                aes.setKey(key, keySize);

                if (mode != "ECB"){
                    // Generate iv
                    cout << ">>> How would you like to generate IV?" << endl
                        << "1. Random" << endl
                        << "2. Input from screen" << endl
                        << "3. Input from file" << endl
                        << "Please enter your number (1/2/3)?" << endl << "> ";
                    cin >> inputSelection;
                    cin.ignore();
                    iv = generateBlock(ivSize, inputSelection, "IV");
                    aes.setIV(iv, ivSize);
                }
                break;
            }
            case 2:{
                if (key == nullptr){
                    cout << "Please generate key before!" << endl;
                    break;
                }

                string path;
                #ifdef __WIN32
                path = ".\\input\\";
                #elif __linux__
                path = "./input/";
                #endif
                vector<double> averageTimeEncrypt;
                for (int index = 0; index < 8; index++){
                    string ciphertext, plaintext, filepath, encoded;
                    filepath = path + INPUT_FILE_NAME[index];
                    FileSource(filepath.data(), true, new StringSink(plaintext));
                    auto start = chrono::high_resolution_clock::now();
            
                    for (int i = 0; i < 1000; ++i) {
                        ciphertext = aes.encrypt(plaintext);
                    }

                    auto end = chrono::high_resolution_clock::now();
                    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
                    averageTimeEncrypt.push_back(static_cast<double>(duration) / 1000.0);

                    encoded = base64encode(ciphertext);
                    string outpath;
                    #ifdef __WIN32
                    outpath = ".\\enc\\" + INPUT_FILE_NAME[index];
                    #elif __linux__
                    outpath = "./enc/" + INPUT_FILE_NAME[index];
                    #endif
                    StringSource(encoded, true, new FileSink(outpath.data()));
                }
                cout << "ENCRYPT:\t";
                for (double avg : averageTimeEncrypt){
                    cout << avg << '\t';
                }
                cout << endl;
                break;
            }
            case 3:{
                if (key == nullptr){
                    cout << "Please generate key before!" << endl;
                    break;
                }
                string path;
                #ifdef __WIN32
                path = ".\\enc\\";
                #elif __linux__
                path = "./enc/";
                #endif
                vector<double> averageTimeDecrypt;
                for (int index = 0; index < 8; index++){
                    string ciphertext, plaintext, filepath, decoded;
                    filepath = path + INPUT_FILE_NAME[index];
                    FileSource(filepath.data(), true, new StringSink(ciphertext));
                    decoded = base64decode(ciphertext);
                    auto start = chrono::high_resolution_clock::now();
            
                    for (int i = 0; i < 1000; ++i) {
                        plaintext = aes.decrypt(decoded);
                    }

                    auto end = chrono::high_resolution_clock::now();
                    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
                    averageTimeDecrypt.push_back(static_cast<double>(duration) / 1000.0);

                    string outpath;
                    #ifdef __WIN32
                    outpath = ".\\dec\\" + INPUT_FILE_NAME[index];
                    #elif __linux__
                    outpath = "./dec/" + INPUT_FILE_NAME[index];
                    #endif
                    StringSource(plaintext, true, new FileSink(outpath.data()));
                }
                cout << "DECRYPT:\t";
                for (double avg : averageTimeDecrypt){
                    cout << avg << '\t';
                }
                cout << endl;
                break;
            }
            case 4:{
                return cout << "Bye!" << endl, 0;
                break;
            }
            default:{
                cout << "Invalid input!" << endl;
                exit(0);
                break;
            }
        }
    }
    return 0;
}