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

#ifndef H_KOMODO_H
#define H_KOMODO_H
#include "komodo_defs.h"

#ifdef _WIN32
#define printf(...)
#endif

// Todo:
// verify: reorgs

#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <ctype.h>
#include "uthash.h"
#include "utlist.h"

#include "komodo_structs.h"
#include "komodo_globals.h"
#include "komodo_utils.h"
#include "komodo_curve25519.h"

#include "komodo_cJSON.c"
#include "komodo_bitcoind.h"
#include "komodo_interest.h"
#include "komodo_notary.h"

#include "komodo_kv.h"
#include "komodo_jumblr.h"
#include "komodo_ccdata.h"

#endif
