#include "cryptopp/cryptlib.h"
#include "cryptopp/x509cert.h"
#include "cryptopp/secblock.h"
#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include "cryptopp/files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/pem.h"

#include <sstream>
#include <iostream>
#include <string>
using std::string;

// External library
#include <cryptopp/files.h>
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

// random number
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using namespace CryptoPP;

#include <cryptopp/asn.h>
#include <cryptopp/oids.h> //
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

int main(int argc, char *argv[])
{
    std::string pemCertificate;

    using namespace CryptoPP;
    std::cout << "Certificate file name: ";
    string filename;
    getline(std::cin, filename);

    X509Certificate cert;
    if (filename.substr(filename.length() - 4) == ".pem")
    {
        FileSource file(filename.c_str(), true, new StringSink(pemCertificate));
        StringSource ss(pemCertificate, true);
        PEM_Load(ss, cert);
    }
    else if (filename.substr(filename.length() - 4) == ".der" || filename.substr(filename.length() - 4) == ".cer" || filename.substr(filename.length() - 4) == ".crt")
    {
        string s = "openssl x509 -inform der -in " + filename + " -out certificate.pem";
        int n = s.length();
        char char_array[n + 1];
        strcpy(char_array, s.c_str());
        system(char_array);
        FileSource file("certificate.pem", true, new StringSink(pemCertificate));
        StringSource ss(pemCertificate, true);
        PEM_Load(ss, cert);
    }

    const SecByteBlock &signature = cert.GetCertificateSignature();
    const SecByteBlock &toBeSigned = cert.GetToBeSigned();
    const X509PublicKey &publicKey = cert.GetSubjectPublicKey();
    if (cert.GetCertificateSignatureAlgorithm() == id_sha256WithRSAEncryption )
    {
        RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_sha384WithRSAEncryption )
    {
        RSASS<PKCS1v15, SHA384>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_sha512WithRSAEncryption )
    {
        RSASS<PKCS1v15, SHA512>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_sha1WithRSASignature  )
    {
        RSASS<PKCS1v15, SHA1>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_ecdsaWithSHA256  )
    {
        ECDSA<ECP, SHA256>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_ecdsaWithSHA384 )
    {
        ECDSA<ECP, SHA384>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_ecdsaWithSHA512 )
    {
        ECDSA<ECP, SHA512>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }
    else if (cert.GetCertificateSignatureAlgorithm() == id_ecdsaWithSHA1 )
    {
        ECDSA<ECP, SHA1>::Verifier verifier(publicKey);
        bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

        if (result)
            std::cout << "Verified certificate" << std::endl;
        else
            std::cout << "Failed to verify certificate" << std::endl;
    }   

    std::cout << "Signature: " << std::endl;
    StringSource(signature, signature.size(), true, new HexEncoder(new FileSink(std::cout)));

    std::cout << "\nTo Be Signed: " << std::endl;
    StringSource(toBeSigned, toBeSigned.size(), true, new HexEncoder(new FileSink(std::cout)));
    std::cout<<"\n";
    std::cout<<"===================================="<<std::endl;

    cert.Print(std::cout);

    std::cout<<"\n";
    std::cout<<"===================================="<<std::endl;
    std::cout<<"Public key"<<std::endl;
    std::string pk, out;
    StringSink pubKey(pk);
    publicKey.DEREncode(pubKey);
    CryptoPP::StringSource ss(pk, true,
     new CryptoPP::HexEncoder(new CryptoPP::StringSink(out)
    ));
    std::cout << out <<std::endl;
}
// https://www.leaderssl.com/tools/ssl_converter