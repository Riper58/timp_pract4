#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/gost.h>
#include <cryptopp/base64.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include "cryptopp/modes.h"
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
using namespace CryptoPP;

class AlgorithmGost
{
private:
    string filePath_in;
    string filePath_out;
    string filePath_Iv;
    string psw;
    string salt = "solurahelszxytrgvbcvbsewqe";
public:
    AlgorithmGost() = delete;
    AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass);
    AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass, const string & iv);
    void encodeGost (AlgorithmGost enc);
    void decodeGost (AlgorithmGost dec);
};
