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

#ifndef H_KOMODOCCDATA_H
#define H_KOMODOCCDATA_H

struct komodo_ccdata *CC_data;
int32_t CC_firstheight;

uint256 BuildMerkleTree(bool* fMutated, const std::vector<uint256> leaves, std::vector<uint256> &vMerkleTree);

uint256 komodo_calcMoM(int32_t height,int32_t MoMdepth)
{
    static uint256 zero; CBlockIndex *pindex; int32_t i; std::vector<uint256> tree, leaves;
    bool fMutated;
    MoMdepth &= 0xffff;  // In case it includes the ccid
    if ( MoMdepth >= height )
        return(zero);
    for (i=0; i<MoMdepth; i++)
    {
        if ( (pindex= komodo_chainactive(height - i)) != 0 )
            leaves.push_back(pindex->hashMerkleRoot);
        else
            return(zero);
    }
    return BuildMerkleTree(&fMutated, leaves, tree);
}

struct komodo_ccdata_entry *komodo_allMoMs(int32_t *nump,uint256 *MoMoMp,int32_t kmdstarti,int32_t kmdendi)
{
    struct komodo_ccdata_entry *allMoMs=0; struct komodo_ccdata *ccdata,*tmpptr; int32_t i,num,max;
    bool fMutated; std::vector<uint256> tree, leaves;
    num = max = 0;
    {
        LOCK(smartTransactionCS);
        DL_FOREACH_SAFE(CC_data,ccdata,tmpptr)
        {
            if ( ccdata->MoMdata.height <= kmdendi && ccdata->MoMdata.height >= kmdstarti )
            {
                if ( num >= max )
                {
                    max += 100;
                    allMoMs = (struct komodo_ccdata_entry *)realloc(allMoMs,max * sizeof(*allMoMs));
                }
                allMoMs[num].MoM = ccdata->MoMdata.MoM;
                allMoMs[num].notarized_height = ccdata->MoMdata.notarized_height;
                allMoMs[num].kmdheight = ccdata->MoMdata.height;
                allMoMs[num].txi = ccdata->MoMdata.txi;
                strcpy(allMoMs[num].symbol,ccdata->symbol);
                num++;
            }
            if ( ccdata->MoMdata.height < kmdstarti )
                break;
        }
    }
    if ( (*nump= num) > 0 )
    {
        for (i=0; i<num; i++)
            leaves.push_back(allMoMs[i].MoM);
        *MoMoMp = BuildMerkleTree(&fMutated, leaves, tree);
    }
    else
    {
        free(allMoMs);
        allMoMs = 0;
    }
    return(allMoMs);
}

int32_t komodo_addpair(struct komodo_ccdataMoMoM *mdata,int32_t notarized_height,int32_t offset,int32_t maxpairs)
{
    if ( maxpairs >= 0) {
        if ( mdata->numpairs >= maxpairs )
        {
            maxpairs += 100;
            mdata->pairs = (struct komodo_ccdatapair *)realloc(mdata->pairs,sizeof(*mdata->pairs)*maxpairs);
            //fprintf(stderr,"pairs reallocated to %p num.%d\n",mdata->pairs,mdata->numpairs);
        }
    } else {
        fprintf(stderr,"komodo_addpair.maxpairs %d must be >= 0\n",(int32_t)maxpairs);
        return(-1);
    }
    mdata->pairs[mdata->numpairs].notarized_height = notarized_height;
    mdata->pairs[mdata->numpairs].MoMoMoffset = offset;
    mdata->numpairs++;
    return(maxpairs);
}

#endif
