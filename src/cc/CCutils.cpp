/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "CCinclude.h"

/*
 CCutils has low level functions that are universally useful for all contracts.
 */


CC *MakeCCcond1of2(uint8_t evalcode,CPubKey pk1,CPubKey pk2)
{
    std::vector<CC*> pks;
    pks.push_back(CCNewSecp256k1(pk1));
    pks.push_back(CCNewSecp256k1(pk2));
    CC *condCC = CCNewEval(E_MARSHAL(ss << evalcode));
    CC *Sig = CCNewThreshold(1, pks);
    return CCNewThreshold(2, {condCC, Sig});
}

CC *MakeCCcond1(uint8_t evalcode, CPubKey pk)
{
    std::vector<CC*> pks;
    pks.push_back(CCNewSecp256k1(pk));
    CC *condCC = CCNewEval(E_MARSHAL(ss << evalcode));
    CC *Sig = CCNewThreshold(1, pks);
    return CCNewThreshold(2, {condCC, Sig});
}

CC *MakeCCcondAny(uint8_t evalcode, std::vector<CTxDestination> dests)
{
    std::vector<CC*> pks;
    for (auto dest : dests)
    {
        CPubKey pk = boost::apply_visitor<GetPubKeyForPubKey>(GetPubKeyForPubKey(), dest);
        if (pk.IsValid())
        {
            pks.push_back(CCNewSecp256k1(pk));
        }
        else
        {
            pks.push_back(CCNewHashedSecp256k1(CKeyID(GetDestinationID(dest))));
        }
    }

    CC *condCC = CCNewEval(E_MARSHAL(ss << evalcode));
    CC *Sig = CCNewThreshold(1, pks);
    return CCNewThreshold(2, {condCC, Sig});
}

CTxOut MakeCC1of2vout(uint8_t evalcode,CAmount nValue,CPubKey pk1,CPubKey pk2)
{
    CTxOut vout;
    CC *payoutCond = MakeCCcond1of2(evalcode,pk1,pk2);
    vout = CTxOut(nValue,CCPubKey(payoutCond));
    cc_free(payoutCond);
    return(vout);
}

std::vector<unsigned char> GetFulfillmentVector(CScript const& scriptSig)
{
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> ffbin;
    if (scriptSig.GetOp(pc, opcode, ffbin))
        return ffbin;
    return std::vector<unsigned char>();
}

CC* GetCryptoCondition(CScript const& scriptSig)
{
    auto pc = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> ffbin;
    if (scriptSig.GetOp(pc, opcode, ffbin))
        return cc_readFulfillmentBinary((uint8_t*)ffbin.data(), ffbin.size()-1);
    return nullptr;
}

// FIXME Alright - used by StakeGuard
CPubKey pubkey2pk(std::vector<uint8_t> pubkey)
{
    CPubKey pk; int32_t i,n; uint8_t *dest,*pubkey33;
    n = pubkey.size();
    dest = (uint8_t *)pk.begin();
    pubkey33 = (uint8_t *)pubkey.data();
    for (i=0; i<n; i++)
        dest[i] = pubkey33[i];
    return(pk);
}

bool Getscriptaddress(char *destaddr,const CScript &scriptPubKey)
{
    CTxDestination address; 
    txnouttype whichType;
    std::vector<std::vector<unsigned char>> vvch = std::vector<std::vector<unsigned char>>();
    if (Solver(scriptPubKey, whichType, vvch) && vvch[0].size() == 20)
    {
        address = CKeyID(uint160(vvch[0]));
        strcpy(destaddr,(char *)CBitcoinAddress(address).ToString().c_str());
        return(true);
    }
    fprintf(stderr,"Solver for scriptPubKey failed\n%s\n", scriptPubKey.ToString().c_str());
    return(false);
}

// FIXME Alright used by StakeGuard
bool GetCCParams(Eval* eval, const CTransaction &tx, uint32_t nIn,
                 CTransaction &txOut, std::vector<std::vector<unsigned char>> &preConditions, std::vector<std::vector<unsigned char>> &params)
{
    uint256 blockHash;

    if (myGetTransaction(tx.vin[nIn].prevout.hash, txOut, blockHash) && txOut.vout.size() > tx.vin[nIn].prevout.n)
    {
        // must ensure that the block is valid and that this is a valid
        CBlockIndex index;
        if (eval->GetBlock(blockHash, index))
        {
            // read preconditions
            CScript subScript = CScript();
            preConditions.clear();
            if (txOut.vout[tx.vin[nIn].prevout.n].scriptPubKey.IsPayToCryptoCondition(&subScript, preConditions))
            {
                // read any available parameters in the output transaction
                params.clear();
                if (tx.vout.size() > 0 && tx.vout[tx.vout.size() - 1].scriptPubKey.IsOpReturn())
                {
                    if (tx.vout[tx.vout.size() - 1].scriptPubKey.GetOpretData(params) && params.size() == 1)
                    {
                        CScript scr = CScript(params[0].begin(), params[0].end());

                        // printf("Script decoding inner:\n%s\nouter:\n%s\n", scr.ToString().c_str(), tx.vout[tx.vout.size() - 1].scriptPubKey.ToString().c_str());

                        if (!scr.GetPushedData(scr.begin(), params))
                        {
                            return false;
                        }
                        else return true;
                    }
                    else return false;
                }
                else return true;
            }
        }
    }
    return false;
}

// FIXME Alright used by StakeGuard
CPubKey GetUnspendable(struct CCcontract_info *cp,uint8_t *unspendablepriv)
{
    if ( unspendablepriv != 0 )
        memcpy(unspendablepriv,cp->CCpriv,32);
    return(pubkey2pk(ParseHex(cp->CChexstr)));
}

// FIXME Alright used within Eval::Dispatch
bool ProcessCC(struct CCcontract_info *cp, Eval* eval, std::vector<uint8_t> paramsNull,const CTransaction &ctx, unsigned int nIn, bool fulfilled)
{
    CTransaction createTx; uint256 assetid,assetid2,hashBlock; uint8_t funcid; int32_t height,i,n,from_mempool = 0; int64_t amount; std::vector<uint8_t> origpubkey;
    height = KOMODO_CONNECTING;
    if ( KOMODO_CONNECTING < 0 ) // always comes back with > 0 for final confirmation
        return(true);
    if ( ASSETCHAINS_CC == 0 || (height & ~(1<<30)) < KOMODO_CCACTIVATE )
        return eval->Invalid("CC are disabled or not active yet");
    if ( (KOMODO_CONNECTING & (1<<30)) != 0 )
    {
        from_mempool = 1;
        height &= ((1<<30) - 1);
    }
    //fprintf(stderr,"KOMODO_CONNECTING.%d mempool.%d vs CCactive.%d\n",height,from_mempool,KOMODO_CCACTIVATE);
    // there is a chance CC tx is valid in mempool, but invalid when in block, so we cant filter duplicate requests. if any of the vins are spent, for example
    //txid = ctx.GetHash();
    //if ( txid == cp->prevtxid )
    //    return(true);
    //fprintf(stderr,"process CC %02x\n",cp->evalcode);
    cp->evalcode2 = cp->evalcode3 = 0;
    cp->unspendableaddr2[0] = cp->unspendableaddr3[0] = 0;
    if ( paramsNull.size() != 0 ) // Don't expect params
        return eval->Invalid("Cannot have params");
    //else if ( ctx.vout.size() == 0 )      // spend can go to z-addresses
    //    return eval->Invalid("no-vouts");
    else if ( (*cp->validate)(cp, eval, ctx, nIn, fulfilled) != 0 )
    {
        //fprintf(stderr,"done CC %02x\n",cp->evalcode);
        //cp->prevtxid = txid;
        return(true);
    }
    //fprintf(stderr,"invalid CC %02x\n",cp->evalcode);
    return(false);
}

