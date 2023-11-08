/********************************************************************
 *
 *
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 */
#include "utilstrencodings.h"
#include "uint256.h"
#include "mmr.h"

/**
 * Helper functions
 * **/

std::string string_to_hex(const std::string& input)
{
    static const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

std::string bytes_to_hex(const std::vector<unsigned char> &in)
{
    std::vector<unsigned char>::const_iterator from = in.cbegin();
    std::vector<unsigned char>::const_iterator to = in.cend();
    std::ostringstream oss;
    for (; from != to; ++from)
       oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*from);
    return oss.str();
}

std::vector<unsigned char> uint64_to_vec(uint64_t input){

    std::vector<unsigned char> bytes;
    while (input) {
        bytes.push_back(input & 0xFF);
        input >>= 8;
    }
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}
/**
 * Returns the number of in order matching nibbles between the 2 arrays
 **/
int matchingNibbleLength(std::vector<unsigned char> nibble1,std::vector<unsigned char> nibble2){
    int i;
    for(i = 0;nibble1[i] == nibble2[i] && nibble1.size() > i;i++){}
    return i;
}

std::vector<unsigned char> toNibbles(std::vector<unsigned char> data){
    //convert the unsigned char to a hex string the hex string back to a vector of unsigned char
    std::string tempString = bytes_to_hex(data);
    std::vector<unsigned char> output(tempString.begin(),tempString.end());
    return output;
}

std::vector<unsigned char> toNibbles(std::string data){
    //convert the unsigned char to a hex string the hex string back to a vector of unsigned char
    //string tempString = bytes_to_hex(data);
    //check if its an even length if not add a 0 on the front
    if(data.length()%2 != 0){
        data = "0" + data;
    }
    std::vector<unsigned char> output(data.begin(),data.end());
    return output;
}

TrieNode::nodeType TrieNode::setType(){
    if(raw.size() == 17) return BRANCH;
    else if(raw.size() == 2){
        std::vector<unsigned char> nodeKey = toNibbles(raw[0]);
        //is the key a terminator
        if(nodeKey[0] > 1) return LEAF;
        return EXTENSION;
    }
    return BRANCH;
}
void TrieNode::setKey(){
    if(type != BRANCH && raw[0].size() > 0){
        std::vector<unsigned char> inProgressKey = toNibbles(raw[0]);
        int adjustment = 0;
        if (int(inProgressKey[0]) % 2) {
            adjustment = 1;
        } else {
            adjustment = 2;
        }
        key = std::vector<unsigned char>(inProgressKey.begin() + adjustment,inProgressKey.end());
    }
}
void TrieNode::setValue(){
    if(type != BRANCH){
        value = raw[1];
    }
}



std::vector<unsigned char> RLP::encodeLength(int length,int offset){
    std::vector<unsigned char> output;
    if(length < 56){
        output.push_back(length+offset);
    } else {
        std::vector<unsigned char> lengthBytes;
        while (length > 0) {
            lengthBytes.insert(lengthBytes.begin(), static_cast<unsigned char>(length & 0xFF));
            length >>= 8;
        }

        // The first byte indicates the start of the data payload.
        output.push_back(static_cast<unsigned char>(offset + 55 + lengthBytes.size()));

        // Append the binary length bytes.
        output.insert(output.end(), lengthBytes.begin(), lengthBytes.end());
    }
    return output;
}


std::vector<unsigned char> RLP::encode(std::vector<unsigned char> input){
    std::vector<unsigned char> output;
    if(input.size() == 1 && input[0] < 128 ) return input;
    else {
        output = encodeLength(input.size(),128);
        output.insert(output.end(),input.begin(),input.end());
        return output;
        }
    }

std::vector<unsigned char> RLP::encode(std::vector<std::vector<unsigned char>> input){
    std::vector<unsigned char> encoded;
    std::vector<unsigned char> inProgress;
    for(int i = 0; i < input.size(); i++){
        inProgress = encode(input[i]);
        encoded.insert(encoded.end(),inProgress.begin(),inProgress.end());
    }
    std::vector<unsigned char> output = encodeLength(encoded.size(),192);
    output.insert(output.end(),encoded.begin(),encoded.end());
    return output;
}



RLP::rlpDecoded RLP::decode(std::vector<unsigned char> inputBytes){

    std::vector<unsigned char> inProgress;
    std::vector<std::vector <unsigned char>>  decoded;
    unsigned char firstByte = inputBytes[0];
    rlpDecoded output;
    unsigned int length = 0;

    std::vector<unsigned char> innerRemainder;

    if(firstByte <= 0x7f) {
        // the data is a string if the range of the first byte(i.e. prefix) is [0x00, 0x7f],
        //and the string is the first byte itself exactly;
        inProgress.push_back(firstByte);
        output.data.push_back(inProgress);
        inputBytes.erase(inputBytes.begin());
        output.remainder = inputBytes;

    } else if (firstByte <= 0xb7) {
        //the data is a string if the range of the first byte is [0x80, 0xb7], and the string whose
        //length is equal to the first byte minus 0x80 follows the first byte;
        length = (int)(firstByte - 0x7f);
        if (firstByte == 0x80) {
            inProgress = std::vector<unsigned char>();
        } else {
            //teh byte std::vector removing the first byte
            inProgress = std::vector<unsigned char>(inputBytes.begin()+1,inputBytes.begin() + length);
            //input.slice(1, length);
            //for (auto const& c : inProgress)
            //    std::cout << c << ' ';
        }
        if (length == 2 && inProgress[0] < 0x80) {
            throw std::invalid_argument("invalid rlp encoding: byte must be less 0x80");
        }
        output.data.push_back(inProgress);
        output.remainder = std::vector<unsigned char>(inputBytes.begin()+length,inputBytes.end());
        return output;
    } else if(firstByte <= 0xbf){
        //the data is a string if the range of the first byte is [0xb8, 0xbf], and the length of the string
        //whose length in bytes is equal to the first byte minus 0xb7 follows the first byte, and the string
        //follows the length of the string;
        int dataLength = (int)(firstByte - 0xb6);
        //calculate the length from the string and convert the hexbytes to an int
        std::string lengthString = string_to_hex(std::string(inputBytes.begin()+1,inputBytes.begin() + dataLength));
        //boost::algorithm::hex(inputBytes.begin()+1,inputBytes.begin() + dataLength, back_inserter(lengthString));
        length = std::stoi(lengthString, nullptr, 16);
        // inProgress = std::std::vector<unsigned char>(inputBytes.begin() + length,inputBytes.begin() + length + dataLength );
        std::vector<unsigned char>inProgress(inputBytes.begin() + dataLength,inputBytes.begin() + length + dataLength);
        if(inProgress.size() < length){
            throw std::invalid_argument("invalid RLP");
        }
        output.data.push_back(inProgress);
        output.remainder = std::vector<unsigned char>(inputBytes.begin() + dataLength + length,inputBytes.end());
        return output;
    } else if(firstByte <= 0xf7){
        length = (int)(firstByte - 0xbf);
        std::vector<unsigned char> innerRemainder;
        innerRemainder = std::vector<unsigned char>(inputBytes.begin() + 1,inputBytes.begin() + length);
        //need to recurse
        rlpDecoded innerRLP;
        while(innerRemainder.size()){
            innerRLP = decode(innerRemainder);
            //loop through the returned data array and push back each element
            for(std::size_t i=0; i<innerRLP.data.size(); ++i)  {
                decoded.push_back(innerRLP.data[i]);
            }
            innerRemainder = innerRLP.remainder;
        }
        output.data = decoded;
        output.remainder = std::vector<unsigned char>(inputBytes.begin()+length,inputBytes.end());
        return output;
    } else {
        int dataLength = (int)(firstByte - 0xf6);
        std::string testBytes(inputBytes.begin(),inputBytes.end()); //not used
        std::string lengthString(inputBytes.begin()+1,inputBytes.begin() + dataLength);
        lengthString = string_to_hex(lengthString);
        //boost::algorithm::hex(inputBytes.begin()+1,inputBytes.begin() + dataLength, back_inserter(lengthString));

        length = std::stoul(lengthString, nullptr, 16);
        int totalLength = dataLength + length;
        if(totalLength > inputBytes.size()) {
            throw std::invalid_argument("invalid rlp: total length is larger than the data");
        }
        innerRemainder = std::vector<unsigned char>(inputBytes.begin() + dataLength,inputBytes.begin() + totalLength);

        if(innerRemainder.size() == 0){
            throw std::invalid_argument("invalid rlp: List has an invalid length");
        }
        while(innerRemainder.size()){
            rlpDecoded innerRLP = decode(innerRemainder);
            //loop through the returned data array and push back each element
            for(std::size_t i=0; i<innerRLP.data.size(); ++i)  {
                decoded.push_back(innerRLP.data[i]);
            }
            innerRemainder = innerRLP.remainder;
        }
        output.data = decoded;
        output.remainder = std::vector<unsigned char>(inputBytes.begin()+length,inputBytes.end());
        return output;
    }

    return output;

}

RLP::rlpDecoded RLP::decode(std::string inputString){
    std::vector<unsigned char> inputBytes = ParseHex(inputString);
    return decode(inputBytes);
}



template<>
std::vector<unsigned char> CETHPATRICIABranch::verifyProof(uint256& rootHash,std::vector<unsigned char> key,std::vector<std::vector<unsigned char>>& proof){

    uint256 wantedHash = rootHash;
    RLP rlp;

    key = toNibbles(key);
    //loop through each element in the proof
    for(std::size_t i=0; i< proof.size(); ++i)  {

        //check to see if the hash of the node matches the expected hash
        CKeccack256Writer writer;
        writer.write((const char *)proof[i].data(), proof[i].size());

        if(writer.GetHash() != wantedHash){
            std::string error("Bad proof node: i=");
            error += std::to_string(i);
            throw std::invalid_argument(error);
        }
        //create a trie node
        TrieNode node(rlp.decode(proof[i]).data);
        std::vector<unsigned char> child;
        if(node.type == node.BRANCH) {
            if(key.size() == 0) {
                if(i != proof.size() -1){
                    throw std::invalid_argument(std::string("Additional nodes at end of proof (branch)"));
                }
                return node.value;
            }

            int keyIndex = HexDigit(key[0]);

            child = node.raw[keyIndex];
            //remove the first nibble of the key as we move up the std::vector
            key = std::vector<unsigned char>(key.begin()+1,key.end());

            if(child.size() == 2){
                //MIGHT NOT NEED TO DECODE THIS HERE
                //RLP::rlpDecoded decodedEmbeddedNode = rlp.decode(child).data;
                TrieNode embeddedNode(rlp.decode(child).data);

                if(i != proof.size() -1){
                    throw std::invalid_argument(std::string("Additional nodes at end of proof (embeddedNode)"));
                }

                if(matchingNibbleLength(node.key,key)!= node.key.size()){
                    throw std::invalid_argument(std::string("Key length does not match with the proof one (embeddedNode)"));
                }

                //check that the embedded node key matches the relevant portion of the node key

                key = std::vector<unsigned char>(key.begin() + embeddedNode.key.size(),key.end());
                if(key.size() !=0){
                    throw std::invalid_argument(std::string("Key does not match with the proof one (embeddedNode)"));
                }

                return embeddedNode.value;
            } else {
                uint256 tmp_child;
                memcpy(&tmp_child,&child.at(0),child.size());
                wantedHash = tmp_child;
            }
        } else if(node.type == node.EXTENSION || node.type == node.LEAF){
            if(matchingNibbleLength(node.key,key) != node.key.size()){
                throw std::invalid_argument(std::string("Key does not match with the proof one (embeddedNode)"));
            }
            child = node.value;
            key = std::vector<unsigned char>(key.begin() + node.key.size(),key.end());

            if (key.size() == 0 || child.size() == 17 && key.size() == 1) {
                // The value is in an embedded branch. Extract it.
                if (child.size() == 17) {
                    //child = child[key[0]][1];
                    //key = std::vector<unsigned char>(key.begin() + 1,key.end());
                }
                if (i != proof.size() - 1) {
                    throw std::invalid_argument(std::string("Additional nodes at end of proof (extention|leaf)"));
                }
                return child;
            } else {
                uint256 tmp_child;
                memcpy(&tmp_child,&child.at(0),child.size());
                wantedHash = tmp_child;
            }

        } else {
                throw std::invalid_argument(std::string("Invalid node type"));
        }

    }
    return {0};
}


template<>
std::vector<unsigned char> CPATRICIABranch<CHashWriter>::verifyAccountProof()
{
    CKeccack256Writer key_hasher;
    key_hasher.write((const char *)(&address), address.size());
    uint256 key_hash = key_hasher.GetHash();

    std::vector<unsigned char> address_hash(key_hash.begin(),key_hash.end());
    //create key from account address
    try{
        CKeccack256Writer stateroot_hasher;
        stateroot_hasher.write((const char *)proofdata.proof_branch[0].data(), proofdata.proof_branch[0].size());

        //As we dont have the state root from the Notaries, spoof the state root to pass for first RLP loop check
        stateRoot =  stateroot_hasher.GetHash();
        return verifyProof(stateRoot,address_hash,proofdata.proof_branch);
    }catch(const std::invalid_argument& e){

        memset(&stateRoot,0,stateRoot.size());
        std::cerr << "exception: " << e.what() << std::endl;
        throw std::invalid_argument(std::string("verifyAccountProof"));
    }

}

template<>
uint256 CPATRICIABranch<CHashWriter>::verifyStorageProof(uint256 ccExporthash){

    //Check the storage value hash, which is the hash of the crosschain export transaction
    //matches the the RLP decoded information from the bridge keeper

    std::vector<unsigned char> ccExporthash_vec(ccExporthash.begin(),ccExporthash.end());
    RLP rlp;
    try{
        CKeccack256Writer key_hasher;
        key_hasher.write((const char *)(&storageProofKey), storageProofKey.size());

        uint256 key_hash = key_hasher.GetHash();
        std::vector<unsigned char> storageProofKey_vec(key_hash.begin(),key_hash.end());
        std::vector<unsigned char> storageValue = verifyProof(storageHash,storageProofKey_vec,storageProof.proof_branch);
        RLP::rlpDecoded decodedValue = rlp.decode(bytes_to_hex(storageValue));

        while(decodedValue.data[0].size() < 32)
        {
            decodedValue.data[0].insert(decodedValue.data[0].begin(), 0x00); //proofs can be truncated on the left.
        }

        if(ccExporthash_vec != decodedValue.data[0])
        {
            throw std::invalid_argument(std::string("RLP Storage Value does not match"));
        }

    }catch(const std::invalid_argument& e){
        LogPrintf(" %s\n", e.what());
        memset(&stateRoot,0,stateRoot.size());
        return stateRoot;
    }

    //Storage value has now been cheked that it RLP decodes and matches the storageHash.

    //Next check that the Account proof RLP decodes and the account value matches the storage encoded

    std::vector<unsigned char> accountValue;
    try{
        accountValue = verifyAccountProof();
    }
    catch(const std::invalid_argument& e){

        LogPrintf("Account Proof Failed : %s\n", e.what());
        memset(&stateRoot,0,stateRoot.size());
        return stateRoot;
    }

    //rlp encode the nonce , account balance , storageRootHash and codeHash
    std::vector<unsigned char> encodedAccount;
    std::vector<unsigned char> storage(storageHash.begin(),storageHash.end());
    try
    {
        std::vector<std::vector<unsigned char>> toEncode;
        toEncode.push_back(uint64_to_vec(nonce));
        toEncode.push_back(GetBalanceAsBEVector());
        toEncode.push_back(storage);
        std::vector<unsigned char> codeHash_vec(codeHash.begin(),codeHash.end());
        toEncode.push_back(codeHash_vec);
        encodedAccount = rlp.encode(toEncode);
    }
    catch(const std::invalid_argument& e)
    {
        LogPrintf("RLP Encode failed : %s\n", e.what());
        memset(&stateRoot,0,stateRoot.size());
        return stateRoot;
    }
    //confim that the encoded account details match those stored in the proof
    while(accountValue.size() < 32)
    {
        accountValue.insert(accountValue.begin(), 0x00); //proofs can be truncated on the left.
    }

    if(encodedAccount != accountValue){
        memset(&stateRoot,0,stateRoot.size());
        LogPrintf("ETH Encoded Account Does not match proof : ");
        memset(&stateRoot,0,stateRoot.size());
        return stateRoot;
    }
    else {
        LogPrint("crosschain", "%s: PATRICIA Tree proof Account Matches\n", __func__);
    }
    //run the storage proof

    return stateRoot;
}
