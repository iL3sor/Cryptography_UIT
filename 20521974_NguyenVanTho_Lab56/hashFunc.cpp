#include <sstream>
#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include <codecvt>
using std::codecvt_utf8;
#include <locale>
using std::wstring_convert;
// set mode
#include <locale>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

// External library
#include <cryptopp/files.h>
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

// random number
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

// string method
#include <cryptopp/filters.h>
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

using namespace CryptoPP;

// Hex encode and decode
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/shake.h>
#include <cryptopp/sha3.h>
#include <cryptopp/sha.h>

std::wstring s2ws(const std::string &str)
{
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
/* convert wstring to string */
std::string ws2s(const std::wstring &str)
{
    std::wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

std::wstring in2ws(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // pumb t to oss
    std::string encoded(oss.str()); // to string
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring
}
/*
//////////////////////////////////////////////////////////////////////////
*/
int main()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    std::wcout << " **** HASH Function***" << std::endl;
    int plaintext = 0;
    std::wcout << "Plaintext source:  1. screen   2.File  ";
    std::wcin >> plaintext;
    string plaininput = "";
    wstring wplaininput;
    switch (plaintext)
    {
    case 1:
    {
        std::wcout << "Your plaintext is ... ";
        fflush(stdin);
        getline(std::wcin, wplaininput);
        plaininput = ws2s(wplaininput);
        break;
    }
    case 2:
    {
        std::wcout << "File name for plaintext is ... ";
        fflush(stdin);
        getline(std::wcin, wplaininput);
        string filename = ws2s(wplaininput);
        FileSource file(filename.c_str(), true, new StringSink(plaininput));
        break;
    }
    default:
    {
        std::wcout << "choose the appropriate source" << std::endl;
        break;
    }
    }


    string message = plaininput;
    int hashfunction = 0;
    std::wcout << "Choose Hash Function: 1. SHA224, 2. SHA256, 3. SHA384, 4. SHA512, 5. SHA3-224, 6. SHA3-256, 7. SHA3-384, 8. SHA3-512, 9. SHAKE128, 10.SHAKE256 " << std::endl;
    wcin >> hashfunction;
    switch (hashfunction)
    {
    case 1:
    {
        CryptoPP::SHA224 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 2:
    {
        CryptoPP::SHA256 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 3:
    {
        CryptoPP::SHA384 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 4:
    {
        CryptoPP::SHA512 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 5:
    {
        CryptoPP::SHA3_224 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 6:
    {
        CryptoPP::SHA3_256 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 7:
    {
        CryptoPP::SHA3_384 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 8:
    {
        CryptoPP::SHA3_512 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << hash.DigestSize()<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(hash.DigestSize());
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 9:
    {
        std::wcout<<"input Digest size (byte): ";
        int digestsize;
        std::wcin>>digestsize;
        CryptoPP::SHAKE128 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << digestsize<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(digestsize);
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    case 10:
    {
        std::wcout<<"input Digest size (byte): ";
        int digestsize;
        std::wcin>>digestsize;
        CryptoPP::SHAKE256 hash;
        std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
        std::wcout << "Digest size: " << digestsize<< std::endl;
        std::wcout << "Block size: " << hash.BlockSize() << std::endl;
        
        std::string digest;
        hash.Restart();
        hash.Update((const byte*)message.data(), message.size()); //setup input
        digest.resize(digestsize);
        hash.TruncatedFinal((byte*)&digest[0], digest.size());

        std::wcout<<"Message: "<<s2ws(message)<<std::endl;
        std::string encode;
        StringSource( digest, true, new HexEncoder(new StringSink(encode)));
        std::wcout<<"Digest: "<<s2ws(encode)<<std::endl;

        std::string hdigest=encode+"H";
        CryptoPP::Integer idigest(hdigest.data());
        CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
        // std::wcout << "Prime number p for Z_p: "<< in2ws(p) << std::endl;
        std::wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << std::endl; // idigest mod p
        break;
    }
    default:
        break;
    }
    return 0; //end
}
