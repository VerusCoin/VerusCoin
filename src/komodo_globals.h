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

#include "sync.h"
#include "komodo_structs.h"

void komodo_prefetch(FILE *fp);
uint32_t komodo_heightstamp(int32_t height);
void komodo_stateupdate(int32_t height,uint8_t notarypubs[][33],uint8_t numnotaries,uint8_t notaryid,uint256 txhash,uint64_t voutmask,uint8_t numvouts,uint32_t *pvals,uint8_t numpvals,int32_t kheight,uint32_t ktime,uint64_t opretvalue,uint8_t *opretbuf,uint16_t opretlen,uint16_t vout,uint256 MoM,int32_t MoMdepth);
void komodo_init(int32_t height);
int32_t komodo_MoMdata(int32_t *notarized_htp,uint256 *MoMp,uint256 *kmdtxidp,int32_t nHeight,uint256 *MoMoMp,int32_t *MoMoMoffsetp,int32_t *MoMoMdepthp,int32_t *kmdstartip,int32_t *kmdendip);
int32_t komodo_notarizeddata(int32_t nHeight,uint256 *notarized_hashp,uint256 *notarized_desttxidp);
char *komodo_issuemethod(char *userpass,char *method,char *params,uint16_t port);
void komodo_init(int32_t height);
int32_t komodo_chosennotary(int32_t *notaryidp,int32_t height,uint8_t *pubkey33,uint32_t timestamp);
int32_t komodo_isrealtime(int32_t *kmdheightp);
uint64_t komodo_paxtotal();
int32_t komodo_longestchain();
uint64_t komodo_maxallowed(int32_t baseid);
int32_t komodo_bannedset(int32_t *indallvoutsp,uint256 *array,int32_t max);

pthread_mutex_t komodo_mutex;

#define KOMODO_ELECTION_GAP 2000    //((ASSETCHAINS_SYMBOL[0] == 0) ? 2000 : 100)
#define KOMODO_ASSETCHAIN_MAXLEN 65

struct pax_transaction *PAX;
int32_t NUM_PRICES; uint32_t *PVALS;
struct knotaries_entry *Pubkeys;

struct komodo_state KOMODO_STATES[34];

int32_t KOMODO_MININGTHREADS = 0,IS_KOMODO_NOTARY,USE_EXTERNAL_PUBKEY,KOMODO_CHOSEN_ONE,KOMODO_ON_DEMAND,KOMODO_EXTERNAL_NOTARIES,KOMODO_PASSPORT_INITDONE,KOMODO_PAX,KOMODO_EXCHANGEWALLET,KOMODO_REWIND,KOMODO_CONNECTING = -1;
int32_t KOMODO_INSYNC,KOMODO_LASTMINED,prevKOMODO_LASTMINED,KOMODO_CCACTIVATE,JUMBLR_PAUSE = 1;
std::string NOTARY_PUBKEY,ASSETCHAINS_NOTARIES,ASSETCHAINS_OVERRIDE_PUBKEY,DONATION_PUBKEY;
uint8_t NOTARY_PUBKEY33[33],ASSETCHAINS_OVERRIDE_PUBKEY33[33],ASSETCHAINS_PUBLIC,ASSETCHAINS_PRIVATE;
bool VERUS_MINTBLOCKS;

char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN], ASSETCHAINS_USERPASS[4096];

bool PBAAS_TESTMODE;
std::string PBAAS_HOST;
int32_t PBAAS_PORT;
std::string PBAAS_USERPASS;
std::string ASSETCHAINS_RPCHOST, ASSETCHAINS_RPCCREDENTIALS;

uint160 ASSETCHAINS_CHAINID;
uint160 VERUS_CHAINID;
std::string VERUS_CHAINNAME = "VRSC";

const uint32_t PBAAS_PREMAINNET_ACTIVATION = 1679072400; // already activated, so harden with immutable value
const uint32_t PBAAS_TESTFORK_TIME = 1683561600;
const uint32_t PBAAS_LARGE_ETH_PROOF_ACTIVATION = 2757830;

bool PARAMS_LOADED = false;
uint16_t ASSETCHAINS_P2PPORT, ASSETCHAINS_RPCPORT;
uint32_t ASSETCHAIN_INIT,ASSETCHAINS_CC,KOMODO_STOPAT;
uint32_t ASSETCHAINS_MAGIC = 2387029918;
int64_t ASSETCHAINS_GENESISTXVAL = 5000000000;

int64_t MAX_MONEY = 200000000 * 100000000LL;
int64_t MAX_SUPPLY = 50000000000LL * 100000000LL;

// consensus variables for coinbase timelock control and timelock transaction support
// time locks are specified enough to enable their use initially to lock specific coinbase transactions for emission control
// to be verifiable, timelocks require additional data that enables them to be validated and their ownership and
// release time determined from the blockchain. to do this, every time locked output according to this
// spec will use an op_return with CLTV at front and anything after |OP_RETURN|PUSH of rest|OPRETTYPE_TIMELOCK|script|
#define _ASSETCHAINS_TIMELOCKOFF 0xffffffffffffffff
uint64_t ASSETCHAINS_TIMELOCKGTE = _ASSETCHAINS_TIMELOCKOFF, ASSETCHAINS_TIMEUNLOCKFROM = 0, ASSETCHAINS_TIMEUNLOCKTO = 0;

uint32_t ASSETCHAINS_LASTERA = 1;
uint64_t ASSETCHAINS_ENDSUBSIDY[ASSETCHAINS_MAX_ERAS],ASSETCHAINS_REWARD[ASSETCHAINS_MAX_ERAS],ASSETCHAINS_HALVING[ASSETCHAINS_MAX_ERAS],ASSETCHAINS_DECAY[ASSETCHAINS_MAX_ERAS];
uint64_t ASSETCHAINS_ERAOPTIONS[ASSETCHAINS_MAX_ERAS];

#define _ASSETCHAINS_EQUIHASH 0
uint32_t ASSETCHAINS_NUMALGOS = 2;
uint32_t ASSETCHAINS_EQUIHASH = _ASSETCHAINS_EQUIHASH;
uint32_t ASSETCHAINS_VERUSHASH = 1;
const char *ASSETCHAINS_ALGORITHMS[] = {"equihash", "verushash"};
uint64_t ASSETCHAINS_NONCEMASK[] = {0xffff,0xfffffff};
uint32_t ASSETCHAINS_NONCESHIFT[] = {32,16};
uint32_t ASSETCHAINS_HASHESPERROUND[] = {1,0x10000};
uint32_t ASSETCHAINS_ALGO = _ASSETCHAINS_EQUIHASH;
uint32_t ASSETCHAINS_STARTING_DIFF = 0;

// Verus proof of stake controls
int32_t ASSETCHAINS_LWMAPOS = 0;        // percentage of blocks should be PoS
int32_t VERUS_BLOCK_POSUNITS = 1024;    // one block is 1000 units
int32_t VERUS_MIN_STAKEAGE = 150;       // 2x this should also be a cap on the POS averaging window, or startup could be too easy
int32_t VERUS_CONSECUTIVE_POS_THRESHOLD = 7; // this gives us 9 in a row
int32_t VERUS_PBAAS_CONSECUTIVE_POS_THRESHOLD = 3; // reduce to max 5 in a row
int32_t VERUS_NOPOS_THRESHHOLD = 150;   // if we have no POS blocks in this many blocks, reset difficulty
int32_t VERUS_PBAAS_NOPOS_THRESHHOLD = 150; // extend for PBaaS to enable more variability in staking supply
int32_t PBAAS_STARTBLOCK = 0;           // the parent blockchain must be notarized at this value in block 1 for it to be accepted
int32_t PBAAS_ENDBLOCK = 0;             // end of life block for the PBaaS blockchain

int32_t ASSETCHAINS_SAPLING;
int32_t ASSETCHAINS_OVERWINTER;

uint64_t KOMODO_INTERESTSUM,KOMODO_WALLETBALANCE;
uint64_t ASSETCHAINS_COMMISSION, ASSETCHAINS_STAKED;
int64_t ASSETCHAINS_ISSUANCE, ASSETCHAINS_SUPPLY = 10;

uint32_t KOMODO_INITDONE;
char KMDUSERPASS[8192],BTCUSERPASS[8192]; uint16_t KMD_PORT = 7771,BITCOIND_RPCPORT = 7771;
uint64_t PENDING_KOMODO_TX;
extern int32_t KOMODO_LOADINGBLOCKS;
unsigned int MAX_BLOCK_SIGOPS = 20000;

struct komodo_kv *KOMODO_KV;
pthread_mutex_t KOMODO_KV_mutex;
CCriticalSection smartTransactionCS;

#define MAX_CURRENCIES 32
char CURRENCIES[][8] = { "USD", "EUR", "JPY", "GBP", "AUD", "CAD", "CHF", "NZD", // major currencies
    "CNY", "RUB", "MXN", "BRL", "INR", "HKD", "TRY", "ZAR", "PLN", "NOK", "SEK", "DKK", "CZK", "HUF", "ILS", "KRW", "MYR", "PHP", "RON", "SGD", "THB", "BGN", "IDR", "HRK",
    "KMD" };

int32_t komodo_baseid(char *origbase)
{
    int32_t i; char base[64];
    for (i=0; origbase[i]!=0&&i<sizeof(base); i++)
        base[i] = toupper((int32_t)(origbase[i] & 0xff));
    base[i] = 0;
    for (i=0; i<=MAX_CURRENCIES; i++)
        if ( strcmp(CURRENCIES[i],base) == 0 )
            return(i);
    //printf("illegal base.(%s) %s\n",origbase,base);
    return(-1);
}

#ifndef SATOSHIDEN
#define SATOSHIDEN ((uint64_t)100000000L)
#endif
int64_t komodo_current_supply(uint32_t nHeight)
{
    uint64_t cur_money;
    // figure out max_money by adding up supply to a maximum of 10,000,000 blocks
    cur_money = (ASSETCHAINS_SUPPLY + ASSETCHAINS_ISSUANCE + 1) + (ASSETCHAINS_MAGIC & 0xffffff) + ASSETCHAINS_GENESISTXVAL;
    if ( ASSETCHAINS_LASTERA == 0 && ASSETCHAINS_REWARD[0] == 0 )
    {
        cur_money += (nHeight * 10000) / SATOSHIDEN;
    }
    else
    {
        for ( int j = 0; j <= ASSETCHAINS_LASTERA; j++ )
        {
            // if any condition means we have no more rewards, break
            if (j != 0 && (nHeight <= ASSETCHAINS_ENDSUBSIDY[j - 1] || (ASSETCHAINS_ENDSUBSIDY[j - 1] == 0 &&
                (ASSETCHAINS_REWARD[j] == 0 && (j == ASSETCHAINS_LASTERA || ASSETCHAINS_DECAY[j] != SATOSHIDEN)))))
                break;

            // add rewards from this era, up to nHeight
            int64_t reward = ASSETCHAINS_REWARD[j];
            if ( reward > 0 )
            {
                uint64_t lastEnd = j == 0 ? 0 : ASSETCHAINS_ENDSUBSIDY[j - 1];
                uint64_t curEnd = ASSETCHAINS_ENDSUBSIDY[j] == 0 ? nHeight : nHeight > ASSETCHAINS_ENDSUBSIDY[j] ? ASSETCHAINS_ENDSUBSIDY[j] : nHeight;
                uint64_t period = ASSETCHAINS_HALVING[j];
                if (period == 0)
                {
                    period = curEnd - lastEnd;
                }
                uint32_t nSteps = (curEnd - lastEnd) / period;
                uint32_t modulo = (curEnd - lastEnd) % period;
                uint64_t decay = ASSETCHAINS_DECAY[j];

                // if exactly SATOSHIDEN, linear decay to zero or to next era, same as:
                // (next_era_reward + (starting reward - next_era_reward) / 2) * num_blocks
                if ( decay == SATOSHIDEN )
                {
                    int64_t lowestSubsidy, subsidyDifference, stepDifference, stepTriangle;
                    int64_t denominator, modulo;
                    int32_t sign = 1;

                    if ( j == ASSETCHAINS_LASTERA )
                    {
                        subsidyDifference = reward;
                        lowestSubsidy = 0;
                    }
                    else
                    {
                        // Ex: -ac_eras=3 -ac_reward=0,384,24 -ac_end=1440,260640,0 -ac_halving=1,1440,2103840 -ac_decay 100000000,97750000,0
                        subsidyDifference = reward - ASSETCHAINS_REWARD[j + 1];
                        if (subsidyDifference < 0)
                        {
                            sign = -1;
                            subsidyDifference *= sign;
                            lowestSubsidy = reward;
                        }
                        else
                        {
                            lowestSubsidy = ASSETCHAINS_REWARD[j + 1];
                        }
                    }

                    // if we have not finished the current era, we need to caluclate a total as if we are at the end, with the current
                    // subsidy. we will calculate the total of a linear era as follows. Each item represents an area calculation:
                    // a) the rectangle from 0 to the lowest reward in the era * the number of blocks
                    // b) the rectangle of the remainder of blocks from the lowest point of the era to the highest point of the era if any remainder
                    // c) the minor triangle from the start of transition from the lowest point to the start of transition to the highest point
                    // d) one halving triangle (half area of one full step)
                    //
                    // we also need:
                    // e) number of steps = (n - erastart) / halving interval
                    //
                    // the total supply from era start up to height is:
                    // a + b + c + (d * e)

                    // calculate amount in one step's triangular protrusion over minor triangle's hypotenuse
                    denominator = nSteps * period;

                    // difference of one step vs. total
                    stepDifference = (period * subsidyDifference) / denominator;

                    // area == coin holding of one step triangle, protruding from minor triangle's hypotenuse
                    stepTriangle = (period * stepDifference) >> 1;

                    // sign is negative if slope is positive (start is less than end)
                    if (sign < 0)
                    {
                        // use steps minus one for our calculations, and add the potentially partial rectangle
                        // at the end
                        cur_money += stepTriangle * (nSteps - 1);
                        cur_money += stepTriangle * (nSteps - 1) * (nSteps - 1);

                        // difference times number of steps is height of rectangle above lowest subsidy
                        cur_money += modulo * stepDifference * nSteps;
                    }
                    else
                    {
                        // if negative slope, the minor triangle is the full number of steps, as the highest
                        // level step is full. lowest subsidy is just the lowest so far
                        lowestSubsidy = reward - (stepDifference * nSteps);

                        // add the step triangles, one per step
                        cur_money += stepTriangle * nSteps;

                        // add the minor triangle
                        cur_money += stepTriangle * nSteps * nSteps;
                    }

                    // add more for the base rectangle if lowest subsidy is not 0
                    cur_money += lowestSubsidy * (curEnd - lastEnd);
                }
                else
                {
                    for ( int k = lastEnd; k < curEnd; k += period )
                    {
                        cur_money += period * reward;

                        // if zero, we do straight halving
                        reward = decay ? (reward * decay) / SATOSHIDEN : reward >> 1;
                    }
                    cur_money += modulo * reward;
                }
            }
        }
    }
    return((int64_t)(cur_money + (cur_money * ASSETCHAINS_COMMISSION) / SATOSHIDEN));
}

