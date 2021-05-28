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

    CryptoPP::SHA384 hash; // создание хэш-объекта

    cout <<"Name: " << hash.AlgorithmName() << endl; // Имя алгоритма
    cout << "Diget size:" << hash.DigestSize() << endl; //размер хэша
    cout << "Block size:" << hash.BlockSize() << endl; // размер внутреннего Блока
    fstream file;
    string path = "/home/riper/hash.txt"; // Путь до файла
    string str_message, file_contents;
    file.open(path);
    if(!file.is_open()) {
        cout << "Ошибка: файл не открыт" << endl;
        return 1;
    }
    while(true) {
        getline(file,str_message);
        if (file.fail()) //сразу после чтения поток проверяется на наличие
            break;
        file_contents += str_message;
    }
    cout << "File_contents: " << file_contents << endl; // содержимое файла

    vector<byte> digest (hash.DigestSize());

    hash.Update(reinterpret_cast<const byte*>(file_contents.data()),file_contents.size()); // формируем хэш
    hash.Final(digest.data()); // получаем хэш

    cout << "Digest HEX format: ";
    CryptoPP::StringSource(digest.data(),digest.size(),true, new  CryptoPP::HexEncoder(new  CryptoPP::FileSink(cout))); // выводим хэш в формате "hex"
    cout << endl;
    return 0;
}
