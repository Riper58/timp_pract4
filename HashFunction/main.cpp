#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int main ()
{
    CryptoPP::SHA1 hash;
    string one_str, file_text;
    cout <<"Имя: " << hash.AlgorithmName() << endl;
    cout << "Размер хэша: " << hash.DigestSize() << endl;
    cout << "Размер блока: " << hash.BlockSize() << endl;
    fstream file;
    string path = "/home/riper/Загрузки/log.txt";
    file.open(path);
    if(!file.is_open()) {
        cout << "Файл не открыт" << endl;
        return 1;
    }
    while(true) {
        getline(file,one_str);
        if (file.fail())
            break;
        file_text += one_str;
    }
    cout << "Содержимое файла: " << file_text << endl;
    vector<byte> digest (hash.DigestSize());
    hash.Update(reinterpret_cast<const byte*>(file_text.data()),file_text.size());
    hash.Final(digest.data());
    cout << "Хэш: " << endl;
    CryptoPP::StringSource(digest.data(),digest.size(),true, new  CryptoPP::HexEncoder(new  CryptoPP::FileSink(cout)));
    cout << endl;
    return 0;
}
