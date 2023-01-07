#!/bin/sh

##Should be run from the root folder

#git clone --depth 1 https://github.com/bitcoin-core/secp256k1
##règle une erreur à la compilation en C++ (correct en C)
#sed -i 's|const unsigned char \*p1 = s1, \*p2 = s2;|const unsigned char \*p1 = (const unsigned char \*)s1, \*p2 = (const unsigned char \*)s2;|' ./secp256k1/src/util.h
##règle une incompatibilité avec libff: tous deux utilisent la macro STR(x)
#sed -i 's|#define STR(x) STR_(x)|//#define STR(x) STR_(x)|' ./secp256k1/src/util.h
#sed -i 's|#define DEBUG_CONFIG_DEF(x) DEBUG_CONFIG_MSG(#x "=" STR(x))|#define DEBUG_CONFIG_DEF(x) DEBUG_CONFIG_MSG(#x "=" STR_(x))|' ./secp256k1/src/util.h
#git clone --depth 1 --branch cmake --single-branch https://github.com/chfast/secp256k1.git ./tmp
#cp ./tmp/CMakeLists.txt ./secp256k1/
#cp ./tmp/src/CMakeLists.txt ./secp256k1/src/
#sed -i 's|secp256k1.c|secp256k1.c precompute_ecmult_gen.c precompute_ecmult.c precomputed_ecmult_gen.c precomputed_ecmult.c|' ./secp256k1/src/CMakeLists.txt
#rm -rf ./tmp
#cp ./CMakeLists_secp256k1.txt ./secp256k1/CMakeLists.txt
#cp ./secp256k1_sha256.h ./secp256k1/include/
#cd secp256k1
#./autogen.sh
#./configure --disable-shared --disable-tests --disable-coverage --disable-openssl-tests --disable-exhaustive-tests --disable-jni --with-bignum=no --with-field=64bit --with-scalar=64bit --#with-asm=no
#cd ..

#git clone --depth 1 --branch CRYPTOPP_8_7_0 https://github.com/abdes/cryptopp-cmake.git

git clone --depth 1 --branch v1.0.0 https://github.com/chfast/ethash.git
#règle une erreur à une déclaration de Hunter (interdit dans projet fils)
sed -i 's|include(HunterGate)|#include(HunterGate)|' ./ethash/CMakeLists.txt
sed -i 's|include(cmake/Hunter/init.cmake)|#include(cmake/Hunter/init.cmake)|' ./ethash/CMakeLists.txt
rm -rf ./ethash/cmake/cable
git clone --depth 1 --branch v0.5.0 https://github.com/ethereum/cable.git ./ethash/cmake/cable
./ethash/cmake/cable/cable.cmake install CableBuildType

#git clone --depth 1 --branch v0.2.1 https://github.com/scipr-lab/libff.git
#cd libff
#git submodule init && git submodule update
#cd ..

#git clone --depth 1 --branch v1.22 https://github.com/technion/libscrypt.git
#git clone --depth 1 --branch v1.21-p1 https://github.com/hunter-packages/libscrypt.git ./tmp
#cp ./tmp/libscryptConfig.cmake.in ./libscrypt
#cp ./tmp/CMakeLists.txt ./libscrypt
#rm -rf ./tmp

#git clone --depth 1 --branch 1.9.5 https://github.com/open-source-parsers/jsoncpp.git

#git clone --recurse-submodules --depth 1 --branch 1.23 https://github.com/google/leveldb.git

#git clone --depth 1 --branch v7.7.3 https://github.com/facebook/rocksdb.git
#switches off tests to avoid already declared names conflicts
#sed -i 's|CMAKE_DEPENDENT_OPTION(WITH_TESTS "build with tests" ON|CMAKE_DEPENDENT_OPTION(WITH_TESTS "build with tests" OFF|' ./rocksdb/CMakeLists.txt
#sed -i 's|option(WITH_BENCHMARK_TOOLS "build with benchmarks" ON)|option(WITH_BENCHMARK_TOOLS "build with benchmarks" OFF)|' ./rocksdb/CMakeLists.txt
#sed -i 's|option(WITH_CORE_TOOLS "build with ldb and sst_dump" ON)|option(WITH_CORE_TOOLS "build with ldb and sst_dump" OFF)|' ./rocksdb/CMakeLists.txt
#sed -i 's|option(WITH_TOOLS "build with tools" ON)|option(WITH_TOOLS "build with tools" OFF)|' ./rocksdb/CMakeLists.txt
