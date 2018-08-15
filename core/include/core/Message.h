/**
 *  @file
 *  @copyright defined in ultrain-core-for-open-source/LICENSE.txt
 */
#pragma once

namespace ultrainio {

    enum ConsensusPhase {
        kPhaseInit = 0,
        kPhaseBA0,
        kPhaseBA1,
        kPhaseBAX
    };

    struct SyncRequestMessage {
        uint32_t startBlockNum;
        uint32_t endBlockNum;
    };

    struct ReqLastBlockNumMsg {
        uint32_t seqNum;    
    };

    struct RspLastBlockNumMsg {
        uint32_t seqNum;
        uint32_t blockNum;
        std::string blockHash;
        std::string prevBlockHash;
    };

    struct ProposeMsg {
        Block block;
    };

    struct EchoMsg {
        BlockHeader blockHeader;
        ConsensusPhase phase;
        uint32_t    baxCount;
        std::string pk;
        std::string proof;
        std::string signature;
    };
}
