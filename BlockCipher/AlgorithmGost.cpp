#include "AlgorithmGost.h"
AlgorithmGost::AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = pass;
}

AlgorithmGost::AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass, const string & iv)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = pass;
    this->filePath_Iv = iv;
}

void AlgorithmGost::encodeGost (AlgorithmGost enc)
{
    //Генерируем ключ
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)enc.psw.data(), enc.psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Генерируем вектор инициализации(IV)
    AutoSeededRandomPool prng;
    byte iv[GOST::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    //Записываем  вектор инициализации(IV) в файл (он понадобится при расшифровании)
    ofstream v_IV(string(enc.filePath_out + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, GOST::BLOCKSIZE);
    v_IV.close();

    cout << "Файл \"IV\" c вектором инициализации успешно создан.\nПуть: " << enc.filePath_out << ".iv" << endl;

    //Шифрование. Результат в файл
    CBC_Mode<GOST>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filePath_in.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.filePath_out.c_str())));
    cout << "Шифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << enc.filePath_out << endl;

    //Шифрование. Результат в виде строки Base64
    string base64, resultbase64;
    FileSource fs_base64(enc.filePath_in.c_str(), true, new StreamTransformationFilter(encr, new StringSink(base64)));
    StringSource ss_base64(base64, true, new Base64Encoder ( new StringSink(resultbase64)));
    cout << "Зашифрованный текст в формате Base64: " << resultbase64 << endl;
}

void AlgorithmGost::decodeGost (AlgorithmGost dec)
{
    //Генерируем ключ (нужно использовать такой же пароль)
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)dec.psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Записываем вектор инициализации(IV) из файла, который формируется при шифровании
    byte iv[GOST::BLOCKSIZE];
    ifstream v_IV(dec.filePath_Iv.c_str(), ios::in | ios::binary);
    //Проверки файла с вектором инициализации(IV) на ошибки
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), GOST::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw string ("Ошибка: Файл \"IV\" (с вектором инициализации) не открыт");
        v_IV.close();
    } else {
        throw string ("Ошибка: Файл \"IV\" (с вектором инициализации) некорректный");
        v_IV.close();
    }
    //Расшифрование
    CBC_Mode<GOST>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filePath_in.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.filePath_out.c_str())));
    cout << "Расшифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << dec.filePath_out << endl;
}
