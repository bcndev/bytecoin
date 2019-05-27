/*******************************************************************************
*   Bytecoin Wallet for Ledger Nano S
*   (c) 2018 - 2019 The Bytecoin developers
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#ifndef BYTECOIN_API_H
#define BYTECOIN_API_H

#define BYTECOIN_CLA 0x00

#define INS_NONE  0x00
#define INS_RESET 0x02

#define BYTECOIN_MAX_OUTPUT_INDEXES 16
#define BYTECOIN_MAX_BUFFER_SIZE    128
#define BYTECOIN_MAX_SCAN_OUTPUTS   7

// INS must be even and cannot start with 9 or 6
#define INS_GET_WALLET_KEYS           0x30
#define INS_SCAN_OUTPUTS              0x32
#define INS_GENERATE_KEYIMAGE         0x34
#define INS_GENERATE_OUTPUT_SEED      0x36
#define INS_EXPORT_VIEW_ONLY          0x38

#define INS_SIG_START                 0x3a
#define INS_SIG_ADD_INPUT_START       0x3c
#define INS_SIG_ADD_INPUT_INDEXES     0x3e
#define INS_SIG_ADD_INPUT_FINISH      0x42
#define INS_SIG_ADD_OUPUT             0x44
#define INS_SIG_ADD_EXTRA             0x46
#define INS_SIG_STEP_A                0x48
#define INS_SIG_STEP_A_MORE_DATA      0x4a
#define INS_SIG_GET_C0                0x4c
#define INS_SIG_STEP_B                0x4e
#define INS_SIG_PROOF_START           0x50
#define INS_GET_APP_INFO              0x52

#define INS_GET_RESPONSE              0xc0


#define SW_SECURITY_STATUS_NOT_SATISFIED  0x6982
#define SW_CLA_NOT_SUPPORTED              0x6E00
#define SW_INS_NOT_SUPPORTED              0x6D00

#define SW_NO_ERROR                       0x9000
#define SW_BYTES_REMAINING_00             0x6100
#define SW_CONDITIONS_NOT_SATISFIED       0x6985
#define SW_COMMAND_NOT_ALLOWED            0x6986
#define SW_WRONG_LENGTH                   0x6700
#define SW_WRONG_DATA                     0x6A80
#define SW_NOT_ENOUGH_MEMORY              0x6A84
#define SW_COMMAND_CHAINING_NOT_SUPPORTED 0x6884

#define SW_SOMETHING_WRONG                0x6F42

#endif // BYTECOIN_API_H
