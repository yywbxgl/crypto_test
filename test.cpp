#include <iostream>
#include <sys/time.h>
#include <cassert>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>


//MD5为弱加密算法，不安全，使用需要开启宏定义
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

using namespace CryptoPP;
using namespace std;

// 测试循环执行次数
# define TEST_COUNT 1000*1000

int float_test(void)
{
	float temp = 0.123456798901234567;
	double temp2 = 0.12345678;

	cout << temp << endl;
	cout << temp2 << endl;

	return 0;
}

// SHA1 哈希算法 测试
int SHA1_test(void)
{
	SHA1 hash;
	HexEncoder encoder(new FileSink(std::cout));
	std::string msg = "Yoda said, Do or do not. There is no try.";
	std::string digest;
	digest.resize(hash.DigestSize());

	std::cout << "--------------------------" << std::endl ;
    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;

	timeval starttime,endtime;
	gettimeofday(&starttime,0);

	for (int i=0; i< TEST_COUNT; ++i)
	{
		hash.Update((const byte*)msg.data(), msg.size());
		hash.Final((byte*)&digest[0]);
	}

	gettimeofday(&endtime,0);
	double timeuse  = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
	// 显示毫秒数
	timeuse /=1000;

	std::cout << "Message: " << msg << std::endl;
	// 二进制内容转为字符串输出，按16进制打印
	std::cout << "Digest: ";
	StringSource(digest, true, new Redirector(encoder));
	std::cout << std::endl;
	std::cout << "time_cost: " << timeuse << std::endl;

	return 0;
}

// SHA256 哈希算法 测试
int SHA256_test(void)
{
	SHA256 hash;
	HexEncoder encoder(new FileSink(std::cout));
	std::string msg = "Yoda said, Do or do not. There is no try.";
	std::string digest;
	digest.resize(hash.DigestSize());

	std::cout << "--------------------------" << std::endl ;
	std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;

	timeval starttime,endtime;
	gettimeofday(&starttime,0);

	for (int i=0; i< TEST_COUNT; ++i)
	{
		hash.Update((const byte*)msg.data(), msg.size());
		hash.Final((byte*)&digest[0]);
	}

	gettimeofday(&endtime,0);
	double timeuse  = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
	// 显示毫秒数
	timeuse /=1000;

	std::cout << "Message: " << msg << std::endl;
	std::cout << "Digest: ";
	StringSource(digest, true, new Redirector(encoder));
	std::cout << std::endl;
	std::cout << "time_cost: " << timeuse << std::endl;

	return 0;
}

//MD5 哈希算法 测试 
int MD5_test(void)
{
	Weak::MD5 hash;
	HexEncoder encoder(new FileSink(std::cout));
	std::string msg = "Yoda said, Do or do not. There is no try.";
	std::string digest;
	digest.resize(hash.DigestSize());

	std::cout << "--------------------------" << std::endl ;
	std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;

	timeval starttime,endtime;
	gettimeofday(&starttime,0);

	for (int i=0; i< TEST_COUNT; ++i)
	{
		hash.Update((const byte*)msg.data(), msg.size());
		hash.Final((byte*)&digest[0]);
	}

	gettimeofday(&endtime,0);
	double timeuse  = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
	// 显示毫秒数
	timeuse /=1000;

	std::cout << "Message: " << msg << std::endl;
	std::cout << "Digest: ";
	StringSource(digest, true, new Redirector(encoder));
	std::cout << std::endl;
	std::cout << "time_cost: " << timeuse << std::endl;

	return 0;
}


// AES 对称加密算法 CFB模式 测试
int AES_test(void)
{
	std::cout << "--------------------------" << std::endl ;
	cout << "Name: AES-CFB" << endl;
	cout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
	cout << "key length (min): " << AES::MIN_KEYLENGTH << endl;
	cout << "key length (max): " << AES::MAX_KEYLENGTH << endl;
	cout << "block size: " << AES::BLOCKSIZE << endl;

	AutoSeededRandomPool rnd;

	// Generate a random key
	SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
	rnd.GenerateBlock( key, key.size() );

	// Generate a random IV
	SecByteBlock iv(AES::BLOCKSIZE);
	rnd.GenerateBlock(iv, iv.size());

	byte plainText[] = "Hello! How are you.";
	size_t messageLen = std::strlen((char*)plainText) + 1;
	std::cout << "Message: " << plainText << std::endl;

	//////////////////////////////////////////////////////////////////////////
	// Encrypt

	CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
	cfbEncryption.ProcessData(plainText, plainText, messageLen);
	std::cout << "Encryped: " << plainText << std::endl;

	//////////////////////////////////////////////////////////////////////////
	// Decrypt

	CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
	cfbDecryption.ProcessData(plainText, plainText, messageLen);
	std::cout << "Decryped: " << plainText << std::endl;

	timeval starttime,endtime;
	gettimeofday(&starttime,0);

	for (int i=0; i< TEST_COUNT; ++i)
	{
		cfbEncryption.ProcessData(plainText, plainText, messageLen);
		cfbDecryption.ProcessData(plainText, plainText, messageLen);
	}

	gettimeofday(&endtime,0);
	double timeuse  = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
	// 显示毫秒数
	timeuse /=1000;

	std::cout << "time_cost: " << timeuse << std::endl;

	return 0;
}


//RSA 非对称加解密算法  测试
int RSA_test(void)
{

	std::cout << "-------------------------------" << std::endl;
	cout << "Name: RSA" << endl;

	timeval starttime,endtime;
	gettimeofday(&starttime,0);

	////////////////////////////////////////////////
	// Generate keys
	AutoSeededRandomPool rng;

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);

	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);

	string plain="RSA Encryption", cipher, recovered;
	std::cout << "Message: " << plain << std::endl;

	////////////////////////////////////////////////
	// Encryption
	RSAES_OAEP_SHA_Encryptor e(publicKey);

	StringSource ss1(plain, true,
		new PK_EncryptorFilter(rng, e,
			new StringSink(cipher)
	) // PK_EncryptorFilter
	); // StringSource

	////////////////////////////////////////////////
	// Decryption
	RSAES_OAEP_SHA_Decryptor d(privateKey);

	StringSource ss2(cipher, true,
		new PK_DecryptorFilter(rng, d,
			new StringSink(recovered)
	) // PK_DecryptorFilter
	); // StringSource

	gettimeofday(&endtime,0);
	double timeuse  = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
	// 显示毫秒数
	timeuse /=1000;

	std::cout << "time_cost: " << timeuse << std::endl;
		
	return 0;
}

int main(int argc, char **argv)
{
	// float_test();
	MD5_test();
	SHA1_test();
	SHA256_test();
	AES_test();
	// RSA_test();

	return 0;
}
