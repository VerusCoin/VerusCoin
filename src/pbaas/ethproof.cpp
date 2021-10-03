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

std::string int_to_hex(int input){
    std::stringstream sstream;
    if(input < 10) sstream << std::hex << 0;
    sstream << std::hex << input;
    std::string result = sstream.str();
    return result;
}

std::string uint64_to_hex(uint64_t input){
    if(input < 10){
        std::stringstream sstream;
        if(input < 10) sstream << std::hex << 0;
        sstream << std::hex << input;
        std::string result = sstream.str();
        return result;
    }
    char buffer[64] = {0};
    sprintf(buffer,"%lx",input);
    return std::string(buffer);
}

//converts uint to vector and trims off leading 00 bytes
std::vector<unsigned char> uint64_to_vec(uint64_t input){

    std::vector<unsigned char> temp(8);
    for (int i = 0; i < 8; i++)
         temp[7 - i] = (input >> (i * 8));
    
    for (int i=0; i<8; i++){
        if(temp[i] == 0)
            temp.erase(temp.begin());
        else 
            break;    
    }

    return temp;
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
        std::string hexLength = int_to_hex(length);
        int dataLength = hexLength.size() / 2;
        std::string firstByte = int_to_hex((offset + 55 + dataLength));
        std::string outputString = firstByte + hexLength;
        output = ParseHex(outputString);
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
std::vector<unsigned char> CPATRICIABranch<CHashWriter>::verifyAccountProof(){
    
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

        if(ccExporthash_vec != decodedValue.data[0])
        {
            throw std::invalid_argument(std::string("RLP Storage Value does no match"));
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
    try{
        std::vector<std::vector<unsigned char>> toEncode;
        toEncode.push_back(ParseHex(uint64_to_hex(nonce)));
        toEncode.push_back(uint64_to_vec(balance));
        toEncode.push_back(storage);
        std::vector<unsigned char> codeHash_vec(codeHash.begin(),codeHash.end());
        toEncode.push_back(codeHash_vec);
        encodedAccount = rlp.encode(toEncode);

    }catch(const std::invalid_argument& e){
        LogPrintf("RLP Encode failed : %s\n", e.what());
        memset(&stateRoot,0,stateRoot.size());
        return stateRoot;
    }
    //confim that the encoded account details match those stored in the proof

    if(encodedAccount != accountValue){
        memset(&stateRoot,0,stateRoot.size());
        LogPrintf("ETH Encoded Account Does not match proof : ");
        memset(&stateRoot,0,stateRoot.size());
        return stateRoot;
    }
    else {
        
        LogPrintf("PATRICIA Tree proof Account Matches\n");
    
    }
    //run the storage proof

    return stateRoot;
}


template<>
bool CETHPATRICIABranch::Init(){

    accountProof = proofdata.proof_branch;
   // address.insert(address.end(),address2.begin(),address2.end());  
    //balance is ok
   // codeHash.insert(codeHash.end(),codeHash2.begin(),codeHash2.end()); 
    //nonce is ok
    //storagehash ok
    //storageProofKey ok
    //storageProof = storageProof2.proof_branch;
    //storageProofValue.insert(storageProofValue.end(),storageProofValue2.begin(),storageProofValue2.end()); 
   // stateRoot = parse_string_to_256("deb248945b09f9c67b14d8aba5d9309dd89dd84609edd21cc98ada77e1eb5de8");
    return true;
}


template<>
bool CETHPATRICIABranch::testProof(){

    stateRoot = uint256S("a9d1bce0a863561e3adcb06e2478cd7c9c1eefb654d708918d704e7221739bcf");
    accountProof = {ParseHex("f90211a0a055908c5697a4895882ae9800c0f379add8873bf952054aaeb418d7b024d8a8a04a034848d6802a596cfb574aadb76ca5cf47e0093a437c39f7e7eb9802cb2c72a07d8afae9b0c23c7adb8d93a71ea996aa0101613398656c327b8cb4ebb95a71e9a000d5618bdc5c6db1852b65b3e65fc6b0af9fdfb043e7496715071616c770f056a0d6d149ff82c779cfb4c5f4c753746284b850e08b0dda6c5673c9e711a360b7cda0d0e415276852238cacad7537723ecdde5f683424a244f3759cecbc5128ce0164a05032b2eae8f3aaf675e9b8bd7fd46a14a312bece2145b01a60942ddd3dbc477ca014a700e1250040c5a2a3052c9bfe06c87645a674332ada60b2622df9389d59cda0d440c345583edb55c17a034ffadfac55adc53d32516b4bb49773854ddb83594ca0a99dc9480471e146a8a0801139d37ca87495ade4fe69d5bf9334edad55f507dca043b962eabbc9bb898d2de979dd4d87d38467f9036046346f54874dc0d398d552a0570f7099623cc91db4cc49bb0dd16455ff9cb9da4cf614fd5b52fa9a2bf4ca77a08d0a4b8b996f4775c5312371abb4c8b9ca4d21b122e8b3ab9623e23386d21050a0aa1cb5a227bafcbe6b4c5a54c50fc34d795a3b22a73f93930c8c8ab86a2ebf91a0cabbc80624b9eebcd8dd62cc07a398b411f8fcac19793e3c0b950d6fe8cd1c67a09fa188fabc6bf1a488b0b7c6a0642afa0108f7140e1a8c0f4735b19df9248af580"),
    ParseHex("f90211a0bb629f5ad92f94cb179ffd00d7f2a9d78916e1c6b5b43326ac08d018e910e3e8a029e5528f849a85c34f0bb206d01375461f957f6385166630a545a3629f0fd0f5a05b028e251502ae64f9b99b00a6c5327e1788797358a15c2dae4862045c274472a0d9d4bfac17fedf12b85a0f54aa25d59ccec188d168b3737dd44a413320abeb2ea0090bcbb72ff32a8784522b90cdd8aa21798fef03b2e750dc384afbdee1a64f63a07b2c5a9c03dbde577dfe1bee65cc58f0144d116040cad7410955bdeab4ffcc22a0fae7319a7dfa285bec71ae70a1133ea0a4122ec99ad7462795dbbd340f00c45aa0fdd16925fa8fd24dc2dbd05ab67134909858573f39b9b3c2d615835980b92964a06af1eb03359e87ac0c84c70a46f76d48df6a2c0566cfb1bb23cff40b9aadbde2a079398312d544d4c372fa75c0e8aa780475cd6719ac061e7d22467e802d105baea07f2932d1c1d0261ada307493ebdd3bd08c34c4b1c969f0b710f772fbc67359b3a092ad0ec7ffdb598c63b5f9bb1f9e573d411b1c2e4ac65dba2783ef1ee0285e4ba098ea86b87aa22c6f2cdf60b63ea03f58dc95f5f5ca75850a70bac442cfefc9baa0679fb9bf83d3bde5d63a7781deacc516a1753867a96c02ceca8757214cca3bc1a058d015e4ddb493f78019877416bc3a3b3790d74c3297308d3c8b010462af9e45a01e561bc67cd896d27df7782a5a37eae742fc52baf7aa3c248fd41e7ef378f22280"),
    ParseHex("f90211a005fbff79c0ed24626ba54aab65ecc7872af5f15ee613cc7342118c7997fdfbfba0b39a5e3e2bb4c82858363aa3cb263623ca2768b93864aaaff1220a0ef0e64e3fa0d44bbf96b09e9aebd72b2cc9cf53d27407d8a92b6bd8f146ba46b33fe9655479a04006016b7c471390cb567d349a6c7f9bf0cc6123ffa102dc49319e35e5011641a084d80e738f1ae5fdd48783bc52dcb53a2ded73f41e414419f939800c73146497a08276ace2ef74ea7b1936294244df23a5742fec219b81769eec9c10d56cb52099a01155fe360f77ded94ecf91a8e9143985fdf9e326ed71fd951ed5703c6bda76f7a0dad61bee21d20aa2495a86410a0c9e0fed2886049ee6d015b49a3bef58d99f3fa01d83fa07a62b4262984b671fbe5253debddb55b99a911a4b0413c11315b2befba086ff9d7588dd725e4a63d3b73e9913a066b3443bed02d28735b8417a8a237dfca0d04b6a923ace3728f3c9312f925f5f8c064a77d9872f69123a43e3055b1b5d9fa0c53e6a2f805ae3a03979dd84669e98b22b2408b6693a6c54bb7fdc9160e02c27a0994be7324a6cc1c04a34461e3e3c1b26af03be47f17e9ce26a6c0db95d3cb279a00763a86e6428b798d5ba596d68de27d0276dc05ebe22ddd77c8d51b77bfee003a09efe91778a838600985f34ba1e76594f689b79f7528d48b9931a8b15cbf33e15a00c0f5e78460b9706cbfccf98ff27fe2546d291be35276ee2ee2c2e52b23de41b80"),
    ParseHex("f90211a0619856cdc66ee5bba442c1bec27fbf8ca40579d0269c05540f1766c3cfb36557a01ac5fe60e27c479c77c74bd8c18b713b8da3bd7edec3839f8f2b0c83d86ec8efa00b6afce15cfa16fc4e4bf62d7c0ee458ecf85c7a6338a4a9221864a77c01845ca042ee2fcaf6774b4c1d8af24fcca53fb9ae877404de5f132f9adee61e93248e01a07f7b0de43fff94cd6b84d63fad119acb50dd02d21999b8242443aeaccc0b34b9a069404df1de4ecae899ff3418f25b8814ebf84ed9ac741436ab5c091bea45b98aa027358b5f4983500636857f9e37567efe0326057ca609d59d95926b3995671891a0c9b7ffa8313a3f81b9f1ba0039704547a5ae99d18a10fdf6cf867d8fe51e4010a01526f549ef8377273333aba4120e84395d29b17df337d594c29044b0b8e80bfca009b41c3684958cfcc7228a3169793a2533f8e65ede6e58184a89aa82230cabaaa0f1a2ba8b17ddf12ae5ff327106ed3880722a069ce30dc2b37723154bda870756a0745a585319fcd95bf36bffc5fb215759911e06a90672d3824d80d2ab3704f34fa0d6de6ca44f2009991cf6ddc97a475792325cb207286fcfcda9f2916d86d9c6cba0d0ffe00892aed7ab66c9e8a43f8ecea24875eaec1df2972f8d539d5ba366b628a0821ccc522a7eef621105c04b8d7f00deb471a6f10d6ef4b307ada74fd2313c47a04e76b8d045c2246e38c0a887a7924d2a996f2be21b383bef11285e2d02cfd2c680"),
    ParseHex("f90211a07f7e57467c137eef9eec755e615ca46acc82709c979015fd7ce410d872d8fddea00d61233e504bbfa750c77a5ef860b546d11553b2a5b8a72f07e2fd7c521c55c1a0bc54f00dc455ff0819335735fff2d293fc3150d45cd0a38a88cc06ecfe2bebcca045f82460bb00566d6de0abbf380d4c2a5aaa0bf9dbf7e6f551edf6c2eee5ca25a0a7243b4cee4a4d6e21f14ead2ffc4f72e247f98072f1e59bac787a64f4dd3ad9a0da15d7b3cac0879b99991d1b9586a29731d1c38a4a589683735cdf5c82d037b4a07b379d93f2055f6e264cc0018705af9f06937148a3d7763edb7a1018075e5206a059322c82e0e7b34c97877c7cea676c06ae8b05a4b0653035585667d208c2346ea0fe292f280f515ba7c99993b4282c93144c9048ab19f4e6d29437e0439d1ef44ba0fc97ab70f5bd6e77caaf0d33eac47a216d2b4a57d5f73c02606dbb4b48551c1fa0c89506ad0a1caf4822eb01524dde2eb64b6f7e9235608c8e89f0a82c48c410c1a038399b3a9face347932e0fb9694a8edbb2ea5e740437496e67c1fce0f1249d68a05761a7d51aea787b0c5c0325babbbeccbac876b2ad02b6114f381b580910d1a6a04b7325a9ba2101cb9708640eb28291c5eaf8b05a6dadb6d21c852a346844ce28a03d0996af61541cee2ea0724d13d22df3374838687942a2905b8233b910e857a1a0b65fa957a5867abcb67fd703bcdf508d0ef16d09f81bc925521336faf7cd3bae80"),
    ParseHex("f8b180a0ee6bf2dd2b13f84fa92c8269d9f6dd3f3be7cbf9fddc7a796cd2f04dcb4746c78080a0231153bd27856696da26c964394fc73bbcdca2de619e088cc2fd203a8af0afa5808080a0195b3beca9d7bb26f4f1b67f7a17e34d38976b2aa023be1814a49ff7eb057a96a0eb0a189ce8f01fc310f8b045aabf9b42f191e4cf9ad4c9306826befefb91f45d808080a0b6a36bd717660ec0410a9cd2dbc7a468119268ad923e7fbc1fcf41b9bc72d762808080"),
    ParseHex("f86f9e20feda63703b859c5fc1532f295f0dab86866128afb4de81221e2eaba2fab84ef84c01884e6d18756ab00000a05c81bf03ee49db55e3322bcda7eb3e48512b42d20d51940abea4c4d4bf3fcfeda0f7e52f2aa71e4aef0374d93451708c24910b5e76ddeacff99d36251308128046"),
    };

   // address = (parse_string("1148744c707a6bff512d4C6499A071dF2ff43538"));
    balance = (5651200000000000000);
    //codeHash. = (parse_string("f7e52f2aa71e4aef0374d93451708c24910b5e76ddeacff99d36251308128046"));
    nonce = (1);
    storageHash = uint256S("5c81bf03ee49db55e3322bcda7eb3e48512b42d20d51940abea4c4d4bf3fcfed");

    uint256 storageKey = uint256S("0175b7a638427703f0dbe7bb9bbf987a2551717b34e79f33b5b1008d1fa01db9");    
    CKeccack256Writer key_hasher;
    key_hasher.write((const char *)&(storageKey),32);
    storageProofKey = key_hasher.GetHash();

   
    storageProof.proof_branch = {ParseHex("f901f1a0d8c4bc9542d28cc89ab88376db1b3a8662a780f1262fabb3da6956b44d0c477da0da81124dc501d5f9797dd2e747d2fe1885030363ddfee9c4b730ce443ae24e49a0b4972109573bf020498db034062ec506ac6f6d10f0934aea9fb0b4fdeb381b0380a04270283e90196274dff75b3631c6aab3a6f5beddd151d85965327f67e05a49aca0eb84a8dc69d06e526f911809900fc95d981f649632312a3c2ae778c2035cced4a08685623d415f31319e682c151c8f8288b152f264505c09b6a67b8e8b5bed6388a0a8ae632e982f7c6d919162ffa4f811769984e947cbb825e6a078ff24d881354ea027c21bea8eca9fa4d23649066e96b95657f3e8afcae0ee317fd433c0b909b1c5a00ade8131eccc3261cb1aca31c32e671e9df48082441033ed7eed46668698c89ea03c724484802200a13499a56cb9be44cbf1dafa5a128e13a0e6ee2b9c33cb3bc3a03a7412cc33b2839ad31b13de6755241c3e7c7918e25eab6f0ddb0d80148b61cba093ebed7f95eca0be8cc56994e7821fb2efe73f22dde3d54227ae93ff8367fdd0a07e34a95ca57a03f779a2f637624b36c36cee08033253f04e78234e0a6156ca21a083b4a89f27b296f92aeb9f235f50dc27fd87a08d7cf72c594d6a801ed8ae2de3a056095c22618c9a9c681646b0ebb4c9d5ebb5c1563f375b8c57c94c5476a6229080"),
        ParseHex("f89180a0391d85655163014c62f450686bbc20fe1098652fa7075f1136b0355fead9b7e7a05f4260f6a3fbe107fe9ccab85fbf2fae0e74c4da14282058ac81d7bed27bc624a0614118aae67cbc60551acf4ce98b919e971d322383e773185c719c85b13f6075808080808080808080a0bcaa1b3471f7a81fd7813f6c7b64dc1053120c9b15bac6d1ec07631006ed4c3c808080"),
        ParseHex("f843a020ac7d4e10f072d9f46be3db644ef1be450423557f8fa8d52ccc7cf0d7e8c319a1a0731530f68a3d73eb14e83696ba04cb85f3b268f14e8b7232613e6804dcd05255")};
   // std::vector<unsigned char> storageProofValue_vec = (parse_string("731530f68a3d73eb14e83696ba04cb85f3b268f14e8b7232613e6804dcd05255"));
    
   // verifyStorageProof();
    
    return true;
    
}
