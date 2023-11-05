#pragma once

#ifndef IO_USER_SELECTION_H
#define IO_USER_SELECTION_H
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
#include "fstream"


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

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

/* Set utf8 support for windows*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string <--> utf8*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;
using namespace CryptoPP;

#include "convert.h"

void getData(string &data, string nameOfData){
    int userSelection;
    cout << ">>> How would you like to get the " << nameOfData << "?" << endl 
        << "1. From screen" << endl
        << "2. From file" << endl
        << "Please enter your number (1/2):" << endl << "> ";
    
    cin >> userSelection;
    cin.ignore();
    switch(userSelection){
        case 1:{
            cout << ">>> Enter your " << nameOfData << ":" << endl << "> ";
            getline(cin, data);
            break;
        }
        case 2:{
            string filename;
            cout << ">>> Enter the file name of the " << nameOfData << ":" << endl << "> ";
            getline(cin, filename);
            FileSource(filename.data(), true, new StringSink(data));
            break;
        }
        default:
            cout << "Invalid input!" << endl;
            exit(0);
            break;
    }
}

void printData(string data, string nameOfData = "DATA"){
    int userSelection;
    cout << ">>> How would you like to display the " << nameOfData << "?" << endl 
        << "1. Display in screen" << endl
        << "2. Save to file" << endl
        << "Please enter your number (1/2):" << endl 
        << "> ";
    cin >> userSelection;
    cin.ignore();
    switch (userSelection){
        case 1:{
            cout << "Your " << nameOfData << ": " << data << endl;   
            break;
        }
        case 2: {
            string filename;
            cout << ">>> Enter the file name:" << endl
                 << "> ";
            getline(cin, filename);
            StringSource(data, true, new FileSink(filename.data(), data.size()));
            break;
        }
        default:
            cout << "Invalid input\n";
            exit(0);
            break;
    }
}

string decodeInput(string data, string nameOfData){
    int performanceSelection;
    cout << ">>> Select encoding performance of the " << nameOfData << "?" << endl
            << "1. Bytes" << endl
            << "2. Hex" << endl
            << "3. Base64" << endl
            << "Please enter your number (1/2/3)?" << endl
            << "> ";
    cin >> performanceSelection;
    string decoded;
    decoded.clear();
    switch(performanceSelection){
        case 1:{
            decoded = data;
            break;
        }
        case 2:{
            decoded = hexdecode(data);
            break;
        }
        case 3:{
            decoded = base64decode(data);
            break;
        }
        default:
            cout << "Invalid input" << endl;
            exit(0);
            break;
    }
    return decoded;
}

string encodeOutput(string data, string nameOfData){
    int performanceSelection;
    cout << ">>> Select encoding performance of the " << nameOfData << "?" << endl
            << "1. Bytes" << endl
            << "2. Hex" << endl
            << "3. Base64" << endl
            << "Please enter your number (1/2/3)?" << endl
            << "> ";
    cin >> performanceSelection;
    cin.ignore();
    string encoded;
    encoded.clear();
    switch (performanceSelection){
        case 1:{
            encoded = data;
            break;
        }
        case 2:{
            encoded = hexencode(data);
            break;
        }
        case 3:{
            encoded = base64encode(data);
            break;
        }
        default:
            cout << "Invalid input!" << endl;
            exit(0);
            break;
    }
    return encoded;
}

string encodeOutput(CryptoPP::byte *data, int dataSize, string nameOfData){
    string strdata; 
    StringSource(data, dataSize, true, new StringSink(strdata));
    return encodeOutput(strdata, nameOfData);
}

CryptoPP::byte *generateBlock(unsigned int blockSize, string nameOfBlock){
    int userSelection;
    cout << ">>> How would you like to generate " << nameOfBlock << "?" << endl
        << "1. Random" << endl
        << "2. Input from screen" << endl
        << "3. Input from file" << endl
        << "Please enter your number (1/2/3)?" << endl << "> ";
    cin >> userSelection;
    cin.ignore();
    CryptoPP::byte *block = new CryptoPP::byte[blockSize];
    switch (userSelection){
        case 1: {
            // Random block and iv
            AutoSeededRandomPool prng;
            prng.GenerateBlock(block, blockSize);
            break;
        }
        case 2:{
            // Load block (hex) from screen
            string data;
            cout << "Please enter your " << nameOfBlock << " (hex - " << blockSize << "):"
                 << endl << "> ";
            getline(cin, data);
            StringSource(hexdecode(data).data(), true, new ArraySink(block, blockSize));
            break;
        }   
        case 3:{
            // Select performance of block/IV
            string fileblock, data, decoded;
            cout << "Please enter the path of your file which contains " << nameOfBlock << ":" << endl << "> ";
            getline(cin, fileblock);
            FileSource(fileblock.data(), true, new StringSink(data));
            decoded = decodeInput(data, nameOfBlock);
            // Decode block
            StringSource(decoded.data(), true, new ArraySink(block, blockSize));
            break;
        }  
        default:
            cout << "Invalid input!" << endl;
            exit(0);
            break;
    }

    cout << ">>> Would you like to save " << nameOfBlock << "?" << endl
         << "1. Yes" << endl
         << "2. No" << endl
         << "> ";
    cin >> userSelection;
    cin.ignore();    
    switch (userSelection)
    {
    case 1:
        printData(encodeOutput(block, blockSize, nameOfBlock), nameOfBlock);
        break;
    case 2:
        cout << nameOfBlock << " : " << hexencode(block, blockSize) << endl;
        break;
    default:
        break;
    }
    return block;
}

int selectMode(){
    // const string MODE[8] = {"ECB", "CBC", "OFB", "CFB", "CTR", "XTS", "CCM", "GCM"};
    // Select mode
    int modeSelection;
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
    return modeSelection;
}

int selectEncryptOrDecrypt(){
    cout << ">>> The code supports:" << endl
        << "1. Encrypt" << endl
        << "2. Decrypt" << endl
        << "Would you like to Encrypt or Decrypt?" << endl << "> ";
    int aescipher;
    cin >> aescipher;
    cin.ignore();
    return aescipher;
}

#endif