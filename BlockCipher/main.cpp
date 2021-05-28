#include "AlgorithmAES.h"
#include "AlgorithmGost.h"

int main ()
{
    bool isTrue = true;
    string mode;
    string f_in, f_out,f_iv,password;
    cout << "Добро пожаловать в программу." << endl;
    cout << "Справки о режимах работы программы:" << endl;
    cout << " EncodeGOST - шифрование с использованием алгоритма \"GOST\"" << endl;
    cout << " EncodeAES - шифрование с использованием алгоритма \"AES\"" << endl;
    cout << " DecodeGOST - расшифрование с использованием алгоритма \"GOST\"" << endl;
    cout << " DecodeAES - расшифрование с использованием алгоритма \"AES\"" << endl;
    do {
        cout << "Выбирете режим работы: ";
        cin >> mode;
        if (mode == "EncodeGOST") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmGost enc(f_in,f_out,password);
                enc.encodeGost(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "EncodeAES") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES enc(f_in,f_out,password);
                enc.encodeAES(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "DecodeGOST") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmGost dec(f_in,f_out,password,f_iv);
                dec.decodeGost(dec);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "DecodeAES") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES dec(f_in,f_out, password, f_iv );
                dec.decodeAES(dec);
            } catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "exit") {
            cout << "Программа завершила работу." << endl;
            isTrue = false;
            break;
        }
    } while (isTrue != false);

    return 0;
}
