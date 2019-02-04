/* Copyright 2017 Cedric Mesnil <cslashm@gmail.com>, Ledger SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os.h"
#include "cx.h"
#include "monero_types.h"
#include "monero_api.h"
#include "monero_vars.h"

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    void ecdhEncode(ecdhTuple & unmasked, const key & sharedSec, bool v2) {
        //encode
        if (v2)
        {
          unmasked.mask = zero();
          xor8(unmasked.amount, ecdhHash(sharedSec));
        }
        else
        {
          key sharedSec1 = hash_to_scalar(sharedSec);
          key sharedSec2 = hash_to_scalar(sharedSec1);
          sc_add(unmasked.mask.bytes, unmasked.mask.bytes, sharedSec1.bytes);
          sc_add(unmasked.amount.bytes, unmasked.amount.bytes, sharedSec2.bytes);
        }
    }
*/
int monero_apdu_blind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout,32);
    monero_io_fetch(k,32);
    monero_io_fetch(v,32);

    monero_io_discard(1);

    if ((G_monero_vstate.options&0x03)==2) {
        os_memset(k,0,32);
        monero_ecdhHash(AKout, AKout);
        for (int i = 0; i<8; i++){
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        //blind mask
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_addm(k,k,AKout);
        //blind value
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_addm(v,v,AKout);
    }
    //ret all
    monero_io_insert(v,32);
    monero_io_insert(k,32);

    return SW_OK;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
/*
    void ecdhDecode(ecdhTuple & masked, const key & sharedSec, bool v2) {
        //decode
        if (v2)
        {
          masked.mask = genCommitmentMask(sharedSec);
          xor8(masked.amount, ecdhHash(sharedSec));
        }
        else
        {
          key sharedSec1 = hash_to_scalar(sharedSec);
          key sharedSec2 = hash_to_scalar(sharedSec1);
          sc_sub(masked.mask.bytes, masked.mask.bytes, sharedSec1.bytes);
          sc_sub(masked.amount.bytes, masked.amount.bytes, sharedSec2.bytes);
        }
    }
*/
int monero_unblind(unsigned char *v, unsigned char *k, unsigned char *AKout, unsigned int short_amount) {
    if (short_amount==2) {
        monero_genCommitmentMask(k,AKout);
        monero_ecdhHash(AKout, AKout);
        for (int i = 0; i<8; i++) {
            v[i] = v[i] ^ AKout[i];
        }
    } else {
        //unblind mask
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_subm(k,k,AKout);
        //unblind value
        monero_hash_to_scalar(AKout, AKout, 32);
        monero_subm(v,v,AKout);
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* ---                                                                 --- */
/* ----------------------------------------------------------------------- */
int monero_apdu_unblind() {
    unsigned char v[32];
    unsigned char k[32];
    unsigned char AKout[32];

    monero_io_fetch_decrypt(AKout,32);
    monero_io_fetch(k,32);
    monero_io_fetch(v,32);

    monero_io_discard(1);

    monero_unblind(v, k, AKout, G_monero_vstate.options&0x03);

    //ret all
    monero_io_insert(v,32);
    monero_io_insert(k,32);

    return SW_OK;
}

