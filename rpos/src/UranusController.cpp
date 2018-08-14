#include <rpos/UranusController.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <boost/asio.hpp>

#include <core/Chain.h>
#include <rpos/MessageManager.h>
#include <rpos/Node.h>
#include <log/Log.h>

using namespace boost::asio;
using namespace std;

namespace {

    bool EmptyBlock(const ultrainio::BlockHeader &block) {
        if (!block.proposerPk.empty() || !block.proposerProof.empty())
            return false;
        return true;
    }
}

namespace ultrainio {

    std::string UranusController::signature(const EchoMsg &echo) {
        ultrainio::sha256 echoSHA256 = ultrainio::sha256::hash(echo);
        uint8_t signature[VRF_PROOF_LEN];
        Vrf::prove(signature, (const uint8_t *) (echoSHA256.data()), echoSHA256.data_size(),
                            UranusNode::URANUS_PRIVATE_KEY);
        return std::string((char *) (signature), VRF_PROOF_LEN);
    }

    EchoMsg UranusController::constructMsg(const Block &block) {
        EchoMsg echo;
        echo.blockHeader = block;
        echo.phase = UranusNode::getInstance()->getPhase();
        echo.baxCount = UranusNode::getInstance()->getBaxCount();
        echo.pk = std::string((char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);
        echo.proof = std::string(
                (char *) MessageManager::getInstance()->getVoterProof(block.block_num(), echo.phase, echo.baxCount),
                VRF_PROOF_LEN);
        echo.signature = signature(echo);
        return echo;
    }

    EchoMsg UranusController::constructMsg(const ProposeMsg &propose) {
        EchoMsg echo;
        echo.blockHeader = propose.block;
        echo.phase = UranusNode::getInstance()->getPhase();
        echo.baxCount = UranusNode::getInstance()->getBaxCount();
        echo.pk = std::string((char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);
        echo.proof = std::string(
                (char *) MessageManager::getInstance()->getVoterProof(propose.block.block_num(), echo.phase,
                                                                      echo.baxCount), VRF_PROOF_LEN);
        echo.signature = signature(echo);
        return echo;
    }

    EchoMsg UranusController::constructMsg(const EchoMsg &echo) {
        EchoMsg myEcho = echo;
        myEcho.pk = std::string((char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);
        myEcho.proof = std::string(
                (char *) MessageManager::getInstance()->getVoterProof(echo.blockHeader.block_num(), echo.phase,
                                                                      echo.baxCount), VRF_PROOF_LEN);
        myEcho.signature = signature(echo);
        return myEcho;
    }

    UranusController::UranusController() : m_ba0Block(), m_proposerMsgMap(), m_echoMsgMap(),
                                           m_cacheProposeMsgMap(), m_cacheEchoMsgMap(),
                                           m_echoMsgAllPhase() {
        m_syncTaskPeriod = {std::chrono::seconds{1}};
        m_syncTaskTimer.reset(new boost::asio::steady_timer(app().get_io_service()));
        m_fast_timestamp = ultrainio::time_point::now();
    }

    void UranusController::reset() {
        BlockRecord ba0_block;

        m_ba0Block = ba0_block;
        m_proposerMsgMap.clear();
        m_echoMsgMap.clear();
        clearMsgCache(m_cacheProposeMsgMap, getLastBlocknum());
        clearMsgCache(m_cacheEchoMsgMap, getLastBlocknum());
        clearMsgCache(m_echoMsgAllPhase, getLastBlocknum());
    }

    void UranusController::resetEcho() {
        m_echoMsgMap.clear();
    }

    bool UranusController::insert(const EchoMsg &echo) {
        echo_message_info echo_info;
        echo_info.echo = echo;
        echo_info.pk_pool.push_back(echo.pk);
        echo_info.hasSend = true;
        VoterSystem voter;
        int stakes = UranusNode::getInstance()->getStakes(echo.pk);
        echo_info.totalVoter += voter.vote((uint8_t *) echo.proof.data(), stakes, VoterSystem::VOTER_RATIO);
        m_echoMsgMap.insert(make_pair(echo.blockHeader.id(), echo_info));
        return true;
    }

    bool UranusController::insert(const ProposeMsg &propose) {
        m_proposerMsgMap.insert(make_pair(propose.block.id(), propose));
        return true;
    }

    bool UranusController::isLaterMsg(const EchoMsg &echo) {
        uint32_t currentBlockNum = UranusNode::getInstance()->getBlockNum();
        ConsensusPhase current_phase = UranusNode::getInstance()->getPhase();
        uint32_t current_bax_count = UranusNode::getInstance()->getBaxCount();

        if (echo.blockHeader.block_num() > currentBlockNum) {
            return true;
        }

        if (echo.blockHeader.block_num() == currentBlockNum) {
            if (echo.phase > current_phase) {
                return true;
            } else if ((echo.phase == current_phase) && (current_bax_count > echo.baxCount)) {
                return true;
            }
        }

        return false;
    }

    bool UranusController::isLaterMsg(const ProposeMsg &propose) {
        uint32_t currentBlockNum = UranusNode::getInstance()->getBlockNum();
        ConsensusPhase current_phase = UranusNode::getInstance()->getPhase();

        if (propose.block.block_num() > currentBlockNum) {
            return true;
        }

        if ((propose.block.block_num() == currentBlockNum)
            // Default genesis block is #1, so the first block
            // nodes are working on is #2.
            && (currentBlockNum == 2)
            && (current_phase == kPhaseInit)) {
            return true;
        }

        return false;
    }

    bool UranusController::isLaterMsgAndCache(const EchoMsg &echo, bool &duplicate) {
        duplicate = false;
        if (isLaterMsg(echo)) {
            msgkey key;
            key.blockNum = echo.blockHeader.block_num();
            key.phase = echo.phase + echo.baxCount;

            auto itor = m_cacheEchoMsgMap.find(key);
            if (itor == m_cacheEchoMsgMap.end()) {
                if (m_cacheEchoMsgMap.size() >= m_maxCachedKeys) {
                    //NOTE: itor will be invalid after the operation below.
                    clearOldCachedEchoMsg();
                }
                std::vector<EchoMsg> echo_vector;
                echo_vector.push_back(echo);
                m_cacheEchoMsgMap.insert(make_pair(key, echo_vector));
            } else {
                auto id = echo.blockHeader.id();
                std::vector<EchoMsg> &ev = itor->second;
                for (size_t i = 0; i < ev.size(); i++) {
                    if (ev[i].pk == echo.pk && ev[i].blockHeader.id() == id) {
                        duplicate = true;
                        return true;
                    }
                }
                ev.push_back(echo);
            }
            return true;
        }
        return false;
    }

    bool UranusController::isLaterMsgAndCache(const ProposeMsg &propose, bool &duplicate) {
        duplicate = false;
        if (isLaterMsg(propose)) {
            msgkey key;
            key.blockNum = propose.block.block_num();
            key.phase = kPhaseBA0;

            auto itor = m_cacheProposeMsgMap.find(key);
            if (itor == m_cacheProposeMsgMap.end()) {
                if (m_cacheProposeMsgMap.size() >= m_maxCachedKeys) {
                    //NOTE: itor will be invalid after the operation below.
                    clearOldCachedProposeMsg();
                }
                std::vector<ProposeMsg> propose_vector;
                propose_vector.push_back(propose);
                m_cacheProposeMsgMap.insert(make_pair(key, propose_vector));
            } else {
                auto id = propose.block.id();
                std::vector<ProposeMsg> &pv = itor->second;
                for (size_t i = 0; i < pv.size(); i++) {
                    if (pv[i].block.proposerPk == propose.block.proposerPk && pv[i].block.id() == id) {
                        duplicate = true;
                        return true;
                    }
                }
                pv.push_back(propose);
            }
            return true;
        }
        return false;
    }

    bool UranusController::isBeforeMsg(const EchoMsg &echo) {
        std::string this_pk = std::string((const char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);

        if (this_pk == echo.pk) {
            return false;
        }
        if (echo.blockHeader.block_num() != UranusNode::getInstance()->getBlockNum()) {
            return false;
        }
        if ((UranusNode::getInstance()->getPhase() == kPhaseBAX) && (echo.phase != kPhaseBA0)) {
            if (UranusNode::getInstance()->getBaxCount() > echo.baxCount) {
                return true;
            }
        }

        return false;
    }

    bool UranusController::processEchoMsg(const EchoMsg &echo) {
        msgkey msg_key;
        msg_key.blockNum = echo.blockHeader.block_num();
        msg_key.phase = echo.phase + echo.baxCount;
        echo_msg_buff echo_msg_map;

        auto map_it = m_echoMsgAllPhase.find(msg_key);
        if (map_it == m_echoMsgAllPhase.end()) {
            if (m_echoMsgAllPhase.size() >= m_maxCachedAllPhaseKeys) {
                clearOldCachedAllPhaseMsg();
            }
            auto result = m_echoMsgAllPhase.insert(make_pair(msg_key, echo_msg_map));
            map_it = result.first;
        }

        auto itor = map_it->second.find(echo.blockHeader.id());
        if (itor != map_it->second.end()) {
            if (updateAndMayResponse(itor->second, echo, true) || isMinEcho(itor->second)) {
                return true;
            }
        } else {
            echo_message_info info;
            info.echo = echo;
            map_it->second.insert(make_pair(echo.blockHeader.id(), info));
            if (updateAndMayResponse(info, echo, true) || isMinEcho(info)) {
                return true;
            }
        }
        return false;
    }

    bool UranusController::updateAndMayResponse(echo_message_info &info, const EchoMsg &echo, bool response) {
        auto pkItor = std::find(info.pk_pool.begin(), info.pk_pool.end(), echo.pk);
        if (pkItor == info.pk_pool.end()) {
            info.pk_pool.push_back(echo.pk);
            VoterSystem voter;
            int stakes = UranusNode::getInstance()->getStakes(echo.pk);
            info.totalVoter += voter.vote((uint8_t *) echo.proof.data(), stakes, VoterSystem::VOTER_RATIO);
            if (response && info.totalVoter >= THRESHOLD_SEND_ECHO && !info.hasSend
                && UranusNode::getInstance()->getPhase() == kPhaseBA0 && isMin2fEcho(info)) {
                if (MessageManager::getInstance()->isVoter(UranusNode::getInstance()->getBlockNum(), echo.phase,
                                                           echo.baxCount)) {
                    info.hasSend = true;
                    EchoMsg myEcho = constructMsg(echo);
                    UranusNode::getInstance()->sendMessage(myEcho);
                    return true;
                }
            }
        }
        return false;
    }

    bool UranusController::isBeforeMsgAndProcess(const EchoMsg &echo) {
        if (isBeforeMsg(echo)) {
            processEchoMsg(echo);
            return true;
        }

        return false;
    }

    uint32_t UranusController::isSyncing() {
        uint32_t maxBlockNum = UranusNode::getInstance()->getBlockNum();
        std::string this_pk = std::string((const char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);

        if (m_cacheEchoMsgMap.empty()) {
            return INVALID_BLOCK_NUM;
        }

        if (UranusNode::getInstance()->getSyncingStatus()) {
            return INVALID_BLOCK_NUM;
        }

        for (auto vector_itor = m_cacheEchoMsgMap.begin(); vector_itor != m_cacheEchoMsgMap.end(); ++vector_itor) {
            if (vector_itor->first.blockNum > maxBlockNum) {
                echo_msg_buff echo_msg_map;
                echo_message_info echo_info;

                for (auto &echo : vector_itor->second) {
                    if (this_pk == echo.pk) {
                        continue;
                    }

                    auto itor = echo_msg_map.find(echo.blockHeader.id());
                    if (itor != echo_msg_map.end()) {
                        updateAndMayResponse(itor->second, echo, false);
                    } else {
                        echo_message_info info;
                        info.echo = echo;
                        updateAndMayResponse(info, echo, false);
                        echo_msg_map.insert(make_pair(echo.blockHeader.id(), info));
                    }
                }

                for (auto echo_itor = echo_msg_map.begin(); echo_itor != echo_msg_map.end(); ++echo_itor) {
                    if (echo_itor->second.totalVoter >= THRESHOLD_SYNCING) {
                        maxBlockNum = vector_itor->first.blockNum;
                        break;
                    }
                }
            }
        }

        if (maxBlockNum > UranusNode::getInstance()->getBlockNum()) {
            return maxBlockNum;
        }

        return INVALID_BLOCK_NUM;
    }

    bool UranusController::isValid(const EchoMsg &echo) {
        std::string this_pk = std::string((const char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);

        if (UranusNode::getInstance()->getSyncingStatus()) {
            return false;
        }

        if (this_pk == echo.pk) {
            return false;
        }
        if (echo.blockHeader.block_num() != UranusNode::getInstance()->getBlockNum()) {
            return false;
        }
        if (static_cast<ConsensusPhase>(echo.phase) != UranusNode::getInstance()->getPhase()) {
            return false;
        }
        return true;
    }

    bool UranusController::isValid(const ProposeMsg &propose) {
        std::string this_pk = std::string((const char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);

        if (UranusNode::getInstance()->getSyncingStatus()) {
            return false;
        }

        if (this_pk == propose.block.proposerPk) {
            return false;
        }

        if (propose.block.block_num() != UranusNode::getInstance()->getBlockNum()) {
            return false;
        }
        return true;
    }

    bool UranusController::fastHandleMessage(const ProposeMsg &propose) {
        if (!isValid(propose)) {
            return false;
        }

        //save timestamp
        if (m_fast_timestamp < propose.block.timestamp.to_time_point()) {
            m_fast_timestamp = propose.block.timestamp.to_time_point();
        }

        auto itor = m_proposerMsgMap.find(propose.block.id());
        if (itor == m_proposerMsgMap.end()) {
            if (isMinPropose(propose)) {
                m_proposerMsgMap.insert(make_pair(propose.block.id(), propose));
                return true;
            }
        }
        return false;
    }

    bool UranusController::fastHandleMessage(const EchoMsg &echo) {
        if (!isValid(echo)) {
            return false;
        }

        //save timestamp
        if (m_fast_timestamp < echo.blockHeader.timestamp.to_time_point()) {
            m_fast_timestamp = echo.blockHeader.timestamp.to_time_point();
        }

        auto itor = m_echoMsgMap.find(echo.blockHeader.id());
        if (itor != m_echoMsgMap.end()) {
            updateAndMayResponse(itor->second, echo, false);
        } else {
            echo_message_info info;
            info.echo = echo;
            updateAndMayResponse(info, echo, false);
            if (isMinEcho(info)) {
                m_echoMsgMap.insert(make_pair(echo.blockHeader.id(), info));
                return true;
            }
        }
        return false;
    }

    bool UranusController::handleMessage(const ProposeMsg &propose) {
        bool duplicate = false;
        if (isLaterMsgAndCache(propose, duplicate)) {
            return (!duplicate);
        }

        if (!isValid(propose)) {
            return false;
        }

        auto itor = m_proposerMsgMap.find(propose.block.id());
        if (itor == m_proposerMsgMap.end()) {
            if (isMinPropose(propose)) {
                if (MessageManager::getInstance()->isVoter(propose.block.block_num(), kPhaseBA0, 0)) {
                    EchoMsg echo = constructMsg(propose);
                    UranusNode::getInstance()->sendMessage(echo);
                }
                m_proposerMsgMap.insert(make_pair(propose.block.id(), propose));
                return true;
            }
        }
        return false;
    }

    bool UranusController::handleMessage(const EchoMsg &echo) {
        bool duplicate = false;
        if (isLaterMsgAndCache(echo, duplicate)) {
            return (!duplicate);
        }

        if (isBeforeMsgAndProcess(echo)) {
            return true;
        }
        if (!isValid(echo)) {
            return false;
        }

        auto itor = m_echoMsgMap.find(echo.blockHeader.id());
        if (itor != m_echoMsgMap.end()) {
            updateAndMayResponse(itor->second, echo, true);
            if (isMinEcho(itor->second) || isMin2fEcho(itor->second)) {
                return true;
            }
        } else {
            echo_message_info info;
            info.echo = echo;
            updateAndMayResponse(info, echo, true);
            m_echoMsgMap.insert(make_pair(echo.blockHeader.id(), info));
            if (isMinEcho(info) || isMin2fEcho(itor->second)) {
                return true;
            }
        }
        return false;
    }

    bool UranusController::handleMessage(const string &peer_addr, const SyncRequestMessage &msg) {
        if (UranusNode::getInstance()->getSyncingStatus()) {
            return true;
        }

        if (peer_addr.empty() || m_syncTaskQueue.size() >= m_maxSyncClients) {
            return false;
        }

        for (std::list<SyncTask>::iterator l_it = m_syncTaskQueue.begin(); l_it != m_syncTaskQueue.end(); ++l_it) {
            if (l_it->peerAddr == peer_addr) {
                return false;
            }
        }

        uint32_t end_block_num = msg.endBlockNum <= getLastBlocknum() + 1 ? msg.endBlockNum : getLastBlocknum() + 1;
        uint32_t max_count = m_maxPacketsOnce / 3;
        uint32_t send_count = 0;
        uint32_t num = msg.startBlockNum;

        for (; num <= end_block_num && send_count < max_count; num++, send_count++) {
            auto b = Chain::getIntance()->fetchBlockByNumber(num);
            if (b) {
                UranusNode::getInstance()->sendMessage(peer_addr, *b);
            } else if (num == end_block_num) { // try to send last block next time
                break;
            } // else: skip the block if not exist
        }

        if (num <= end_block_num) {
            m_syncTaskQueue.emplace_back(peer_addr, num, end_block_num);
        }

        return true;
    }

    bool UranusController::handleMessage(const string &peer_addr, const ReqLastBlockNumMsg &msg) {
        RspLastBlockNumMsg rsp_msg;
        rsp_msg.seqNum = msg.seqNum;
        rsp_msg.blockNum = getLastBlocknum();

        auto b = Chain::getIntance()->fetchBlockByNumber(rsp_msg.blockNum);
        if (b) {
            rsp_msg.blockHash = b->id();
            rsp_msg.prevBlockHash = b->previous;
        } else {
            rsp_msg.blockNum = INVALID_BLOCK_NUM;
        }

        UranusNode::getInstance()->sendMessage(peer_addr, rsp_msg);
        return true;
    }

    uint32_t UranusController::getLastBlocknum() {
        return Chain::getIntance()->headBlockNum();
    }

    bool UranusController::handleMessage(const Block &block) {
        uint32_t last_num = getLastBlocknum();
        auto b = Chain::getIntance()->fetchBlockByNumber(last_num);
        if (b) {
            if (block.previous == b->id()) {
                // TODO(yufengshen) -- Do not copy here, should have shared_ptr at the first place.
                produceBlock(std::make_shared<SignedBlock>(block));
                return true;
            } else {
                return false;
            }
        }

        return false;
    }

    bool UranusController::isMinPropose(const ProposeMsg &propose_msg) {
        VoterSystem voter;
        uint32_t priority = voter.proof2Priority((const uint8_t *) propose_msg.block.proposerProof.data());
        for (auto propose_itor = m_proposerMsgMap.begin(); propose_itor != m_proposerMsgMap.end(); ++propose_itor) {
            uint32_t p = voter.proof2Priority((const uint8_t *) propose_itor->second.block.proposerProof.data());
            if (p < priority) {
                return false;
            }
        }
        return true;
    }

    bool UranusController::isMin2fEcho(const echo_message_info &info) {
        VoterSystem voter;
        uint32_t priority = voter.proof2Priority((const uint8_t *) info.echo.blockHeader.proposerProof.data());
        for (auto echo_itor = m_echoMsgMap.begin(); echo_itor != m_echoMsgMap.end(); ++echo_itor) {
            if (echo_itor->second.totalVoter >= THRESHOLD_SEND_ECHO) {
                if (voter.proof2Priority((const uint8_t *) echo_itor->second.echo.blockHeader.proposerProof.data()) <
                    priority) {
                    return false;
                }
            }
        }
        return true;
    }

    bool UranusController::isMinEcho(const echo_message_info &info) {
        VoterSystem voter;
        uint32_t priority = voter.proof2Priority((const uint8_t *) info.echo.blockHeader.proposerProof.data());
        for (auto echo_itor = m_echoMsgMap.begin(); echo_itor != m_echoMsgMap.end(); ++echo_itor) {
            if (voter.proof2Priority((const uint8_t *) echo_itor->second.echo.blockHeader.proposerProof.data()) <
                priority) {
                return false;
            }
        }
        return true;
    }

    size_t UranusController::runUnappliedTrxs(const std::vector<std::shared_ptr<TransactionMetadata>> &trxs,
                                              ultrainio::time_point start_timestamp) {
        std::shared_ptr<Chain> chain = Chain::getInstance();
        size_t count = 0;
        for (const auto &trx : trxs) {
            if (!trx) {
                chain->dropUnappliedTransaction(trx);
                // nulled in the loop above, skip it
                continue;
            }

            if (chain->isKnownUnexpiredTransaction(trx->id)) {
                chain->dropUnappliedTransaction(trx);
                continue;
            }

            try {
                auto deadline = ultrainio::time_point::now() + ultrainio::milliseconds(100);
                auto trace = chain->pushTransaction(trx, deadline);
                if (trace->except) {
                    // this failed our configured maximum transaction time, we don't want to replay it
                    chain->dropUnappliedTransaction(trx);
                }

                m_initTrxCount++;
                count++;
                //  Every 100 trxs we check if we have exceeds the allowed trx running time.
                if (m_initTrxCount % 100 == 0 &&
                    (ultrainio::time_point::now() - start_timestamp) > ultrainio::seconds(CODE_EXEC_MAX_TIME_S)) {
                    break;
                }
                if (m_initTrxCount >= MAX_PROPOSE_TRX_COUNT) {
                    break;
                }
            } FC_LOG_AND_DROP();
        }
        return count;
    }

    size_t UranusController::runPendingTrxs(std::list<std::shared_ptr<TransactionMetadata>> *trxs,
                                            ultrainio::time_point start_timestamp) {
        std::shared_ptr<Chain> chain = Chain::getInstance();
        // TODO(yufengshen) : also scheduled trxs.
        size_t count = 0;
        while (!trxs->empty()) {
            const auto &trx = trxs->front();
            if (!trx) {
                chain->dropUnappliedTransaction(trx);
                trxs->pop_front();
                // nulled in the loop above, skip it
                continue;
            }

            if (chain->isKnownUnexpiredTransaction(trx->id)) {
                chain->dropUnappliedTransaction(trx);
                trxs->pop_front();
                continue;
            }

            // TODO -- yufengshen -- We still need this.
            //	       if (trx->packed_trx.expiration() > pbs->header.timestamp.to_time_point()) {
            // expired, drop it
            //		 ilog("-----------initProposeMsg expired trx exp ${exp}, blocktime ${bt}",
            //		      ("exp",trx->packed_trx.expiration())("bt",pbs->header.timestamp));
            //                 chain->dropUnappliedTransaction(trx);
            //                 continue;
            //	       }

            try {
                auto deadline = ultrainio::time_point::now() + ultrainio::milliseconds(100);
                auto trace = chain->pushTransaction(trx, deadline);
                if (trace->except) {
                    // this failed our configured maximum transaction time, we don't want to replay it
                    chain->dropUnappliedTransaction(trx);
                }
                trxs->pop_front();

                m_initTrxCount++;
                count++;
                //  Every 100 trxs we check if we have exceeds the allowed trx running time.
                if (m_initTrxCount % 100 == 0 &&
                    (ultrainio::time_point::now() - start_timestamp) > ultrainio::seconds(CODE_EXEC_MAX_TIME_S)) {
                    break;
                }
                if (m_initTrxCount >= MAX_PROPOSE_TRX_COUNT) {
                    break;
                }
            } FC_LOG_AND_DROP();
        }
        return count;
    }

    bool UranusController::initProposeMsg(ProposeMsg *propose_msg) {
        auto &block = propose_msg->block;
        auto start_timestamp = ultrainio::time_point::now();
        std::shared_ptr<Chain> chain = Chain::getInstance();
        try {

            // TODO(yufengshen): We have to cap the block size, cpu/net resource when packing a block.
            // Refer to the subjective and exhausted design.  
            std::list<std::shared_ptr<TransactionMetadata> > *pending_trxs = chain->getPendingTransactions();
            const auto &unapplied_trxs = chain->getUnappliedTransactions();

            m_initTrxCount = 0;
            size_t count1 = runPendingTrxs(pending_trxs, start_timestamp);
            size_t count2 = runUnappliedTrxs(unapplied_trxs, start_timestamp);

            // We are under very heavy pressure, lets drop transactions.
            if (m_initTrxCount >= MAX_PROPOSE_TRX_COUNT) {
                pending_trxs->clear();
                chain->clearUnappliedTransaction();
            }
            // TODO(yufengshen) - Do we finalize here ?
            // If we finalize here, we insert the block summary into the database.
            // TODO(yufengshen) - Do we need to include the merkle in the block propose?
            chain->setActionMerkleHack();
            chain->setTrxMerkleHack();
            // Construct the block msg from pbs.
            const auto &pbs = chain->pendingBlockState();
            const auto &bh = pbs->header;
            block.timestamp = bh.timestamp;
            block.producer = "ultrainio";
            block.proposerPk = std::string((char *) UranusNode::URANUS_PUBLIC_KEY, VRF_PUBLIC_KEY_LEN);
            block.proposerProof = std::string(
                    (char *) MessageManager::getInstance()->getProposerProof(UranusNode::getInstance()->getBlockNum()),
                    VRF_PROOF_LEN);
            block.version = 0;
            block.confirmed = 1;
            block.previous = bh.previous;
            block.transaction_mroot = bh.transaction_mroot;
            block.action_mroot = bh.action_mroot;
            block.transactions = pbs->block->transactions;

            uint8_t signature[VRF_PROOF_LEN] = {0};
            std::string blockHash = (block.id()).str();
            if (!Vrf::prove(signature, (uint8_t *) blockHash.c_str(), blockHash.length(),
                                                UranusNode::URANUS_PRIVATE_KEY)) {
                return false;
            }
            block.signature = std::string((char *) signature, VRF_PROOF_LEN);
        } catch (const ultrainio::exception &e) {
            edump((e.to_detail_string()));
            chain->abortBlock();
            throw;
        }
        return true;
    }

    void UranusController::processCache(const msgkey &msg_key) {
        auto propose_itor = m_cacheProposeMsgMap.find(msg_key);
        if (propose_itor != m_cacheProposeMsgMap.end()) {
            for (auto &propose : propose_itor->second) {
                handleMessage(propose);
            }
            m_cacheProposeMsgMap.erase(propose_itor);
        }

        auto echo_itor = m_cacheEchoMsgMap.find(msg_key);
        if (echo_itor != m_cacheEchoMsgMap.end()) {
            for (auto &echo : echo_itor->second) {
                handleMessage(echo);
            }
            m_cacheEchoMsgMap.erase(echo_itor);
        }
    }

    void UranusController::fastProcessCache(const msgkey &msg_key) {
        auto propose_itor = m_cacheProposeMsgMap.find(msg_key);
        if (propose_itor != m_cacheProposeMsgMap.end()) {
            for (auto &propose : propose_itor->second) {
                fastHandleMessage(propose);
            }
            m_cacheProposeMsgMap.erase(propose_itor);
        }

        auto echo_itor = m_cacheEchoMsgMap.find(msg_key);
        if (echo_itor != m_cacheEchoMsgMap.end()) {
            for (auto &echo : echo_itor->second) {
                fastHandleMessage(echo);
            }
            m_cacheEchoMsgMap.erase(echo_itor);
        }
    }

    bool UranusController::findEchoCache(const msgkey &msg_key) {
        auto echo_itor = m_cacheEchoMsgMap.find(msg_key);
        if (echo_itor != m_cacheEchoMsgMap.end()) {
            return true;
        }
        return false;
    }

    BlockRecord UranusController::produceBaxBlock() {
        VoterSystem voter;
        uint32_t min_priority = std::numeric_limits<uint32_t>::max();
        BlockRecord blockRecord;
        echo_message_info *echo_info = nullptr;

        for (auto map_itor = m_echoMsgAllPhase.begin(); map_itor != m_echoMsgAllPhase.end(); ++map_itor) {
            echo_msg_buff &echo_msg_map = map_itor->second;
            for (auto echo_itor = echo_msg_map.begin(); echo_itor != echo_msg_map.end(); ++echo_itor) {
                if (echo_itor->second.totalVoter >= THRESHOLD_NEXT_ROUND) {
                    uint32_t priority = voter.proof2Priority(
                            (const uint8_t *) echo_itor->second.echo.blockHeader.proposerProof.data());
                    if (min_priority >= priority) {
                        echo_info = &(echo_itor->second);
                        min_priority = priority;
                    }
                }
            }

            if (!echo_info || EmptyBlock(echo_info->echo.blockHeader)) {
                continue;
            }

            auto propose_itor = m_proposerMsgMap.find(echo_info->echo.blockHeader.id());
            if (propose_itor != m_proposerMsgMap.end()) {
                blockRecord.block = propose_itor->second.block;
                blockRecord.pk_pool = echo_info->pk_pool;
                return blockRecord;
            }
        }

        return blockRecord;
    }

    BlockRecord UranusController::produceTentativeBlock() {
        VoterSystem voter;
        uint32_t min_priority = std::numeric_limits<uint32_t>::max();
        echo_message_info echo_info;
        for (auto echo_itor = m_echoMsgMap.begin(); echo_itor != m_echoMsgMap.end(); ++echo_itor) {
            if (echo_itor->second.totalVoter >= THRESHOLD_NEXT_ROUND) {
                uint32_t priority = voter.proof2Priority(
                        (const uint8_t *) echo_itor->second.echo.blockHeader.proposerProof.data());
                if (min_priority >= priority) {
                    echo_info = echo_itor->second;
                    min_priority = priority;
                }
            }
        }

        BlockRecord blockRecord;
        if (EmptyBlock(echo_info.echo.blockHeader)) {
            if ((!m_echoMsgAllPhase.empty()) && (UranusNode::getInstance()->getPhase() == kPhaseBAX)) {
                return produceBaxBlock();
            }
            return blockRecord;
        }
        auto propose_itor = m_proposerMsgMap.find(echo_info.echo.blockHeader.id());
        if (propose_itor != m_proposerMsgMap.end()) {
            blockRecord.block = propose_itor->second.block;
            blockRecord.pk_pool = echo_info.pk_pool;
            if (kPhaseBA0 == UranusNode::getInstance()->getPhase()) {
                m_ba0Block = blockRecord;
            }
        } else {
            LOG_INFO("error find propose msg.");
        }
        return blockRecord;
    }

    void UranusController::clearPreRunStatus() {
        m_voterPreRunBa0InProgress = false;
        m_currentPreRunBa0TrxIndex = -1;
        std::shared_ptr<Chain> chain = Chain::getInstance();
        chain->abortBlock();
    }

    bool UranusController::verifyBa0Block() {
        std::shared_ptr<Chain> chain = Chain::getInstance();
        chain->abortBlock();
        const SignedBlock &block = m_ba0Block.block;
        if (EmptyBlock(block))
            return false;

        auto id = block.id();
        auto existing = chain->fetchBlockById(id);
        if (existing) {
            return false;
        }
        // Here is the hack, we are actually using the template of ba0_block, but we don't use
        // chain's pushBlock, so we have to copy some members of ba0_block into the head state,
        // e.g. pk, proof, producer.
        chain->startBlock(block.timestamp, block.confirmed);
        std::shared_ptr<BlockState> pbs = chain->pendingBlockStateHack();
        std::shared_ptr<SignedBlock> bp = pbs->block;
        SignedBlockHeader *hp = &(pbs->header);
        // TODO(yufengshen): Move all this into startBlock() to remove dup codes.
        bp->producer = block.producer;
        bp->proposerPk = block.proposerPk;
        bp->proposerProof = block.proposerProof;
        hp->producer = block.producer;
        hp->proposerPk = block.proposerPk;
        hp->proposerProof = block.proposerProof;
        bp->confirmed = block.confirmed;
        auto start_timestamp = ultrainio::time_point::now();
        try {
            for (int i = 0; i < block.transactions.size(); i++) {
                const auto &receipt = block.transactions[i];
                std::shared_ptr<TransactionTrace> trace;
                if (receipt.trx.contains<PackedTransaction>()) {
                    auto &pt = receipt.trx.get<PackedTransaction>();
                    auto mtrx = std::make_shared<TransactionMetadata>(pt);
                    trace = chain->pushTransaction(mtrx);
                } else if (receipt.trx.contains<TransactionIdType>()) {
                    trace = chain->pushScheduledTransaction(receipt.trx.get<TransactionIdType>());
                }
                if (trace->except) {
                    throw trace->except;
                }
                if (i % 100 == 0 &&
                    (ultrainio::time_point::now() - start_timestamp) > ultrainio::seconds(5)) {
                    chain->abortBlock();
                    return false;
                }
            }
        } catch (const ultrainio::exception &e) {
            edump((e.to_detail_string()));
            chain->abortBlock();
            return false;
        }
        // TODO(yufengshen): SHOULD CHECK the signature and block's validity.
        m_voterPreRunBa0InProgress = true;
        return true;
    }

    bool UranusController::preRunBa0BlockStart() {
        std::shared_ptr<Chain> chain = Chain::getInstance();
        chain->abortBlock();
        const SignedBlock &block = m_ba0Block.block;
        if (EmptyBlock(block) || block.transactions.empty()) {
            return false;
        }

        auto id = block.id();
        auto existing = chain->fetchBlockById(id);
        if (existing) {
            return false;
        }
        // Here is the hack, we are actually using the template of ba0_block, but we don't use
        // chain's pushBlock, so we have to copy some members of ba0_block into the head state,
        // e.g. pk, proof, producer.
        chain->startBlock(block.timestamp, block.confirmed);
        std::shared_ptr<BlockState> pbs = chain->pendingBlockStateHack();
        std::shared_ptr<SignedBlock> bp = pbs->block;
        SignedBlockHeader *hp = &(pbs->header);
        bp->producer = block.producer;
        bp->proposerPk = block.proposerPk;
        bp->proposerProof = block.proposerProof;
        hp->producer = block.producer;
        hp->proposerPk = block.proposerPk;
        hp->proposerProof = block.proposerProof;
        bp->confirmed = block.confirmed;
        m_currentPreRunBa0TrxIndex = 0;
        return true;
    }

    bool UranusController::preRunBa0BlockStep() {
        std::shared_ptr<Chain> chain = Chain::getInstance();
        const auto &pbs = chain->pendingBlockState();
        if (!pbs) {
            return false;
        }
        const SignedBlock &b = m_ba0Block.block;
        int trx_count = 0;
        try {
            for (; m_currentPreRunBa0TrxIndex < b.transactions.size() &&
                   trx_count <= 1000; m_currentPreRunBa0TrxIndex++, trx_count++) {
                const auto &receipt = b.transactions[m_currentPreRunBa0TrxIndex];
                if (receipt.trx.contains<PackedTransaction>()) {
                    auto &pt = receipt.trx.get<PackedTransaction>();
                    auto mtrx = std::make_shared<TransactionMetadata>(pt);
                    chain->pushTransaction(mtrx);
                } else if (receipt.trx.contains<TransactionIdType>()) {
                    chain->pushScheduledTransaction(receipt.trx.get<TransactionIdType>());
                }
            }
        } catch (const ultrainio::exception &e) {
            edump((e.to_detail_string()));
            chain->abortBlock();
            m_currentPreRunBa0TrxIndex = -1;
            return false;
        }

        return true;
    }

    void UranusController::produceBlock(const std::shared_ptr<SignedBlock> &block) {
        std::shared_ptr<Chain> chain = Chain::getInstance();

        auto id = block->id();
        auto existing = chain->fetchBlockById(id);
        if (existing) {
            return;
        }

        const auto &pbs = chain->pendingBlockState();
        bool needs_push_whole_block = true;

        if (pbs && m_voterPreRunBa0InProgress) {
            // first check if ba1 block is indeed ba0 block.
            const SignedBlock &b = m_ba0Block.block;
            if (b.proposerPk == block->proposerPk &&
                b.proposerProof == block->proposerProof &&
                b.block_num() == block->block_num() &&
                b.timestamp == block->timestamp &&
                b.producer == block->producer) {

                chain->finalizeBlock();
                chain->commitBlock();
                needs_push_whole_block = false;
                // TODO(yufengshen) : CHECK if the produced block is the same as the ba1 block, e.g.
                // action/trx_mroot ...
            }
        }

        // We are already pre-running ba0_block
        if (pbs && m_currentPreRunBa0TrxIndex >= 0) {
            // first check if ba1 block is indeed ba0 block.
            const SignedBlock &b = m_ba0Block.block;
            if (b.proposerPk == block->proposerPk &&
                b.proposerProof == block->proposerProof &&
                b.block_num() == block->block_num() &&
                b.timestamp == block->timestamp &&
                b.producer == block->producer) {
                try {
                    for (; m_currentPreRunBa0TrxIndex < b.transactions.size(); m_currentPreRunBa0TrxIndex++) {
                        const auto &receipt = b.transactions[m_currentPreRunBa0TrxIndex];
                        if (receipt.trx.contains<PackedTransaction>()) {
                            auto &pt = receipt.trx.get<PackedTransaction>();
                            auto mtrx = std::make_shared<TransactionMetadata>(pt);
                            chain->pushTransaction(mtrx, ultrainio::time_point::maximum(), receipt.cpu_usage_us);
                        } else if (receipt.trx.contains<TransactionIdType>()) {
                            chain->pushScheduledTransaction(receipt.trx.get<TransactionIdType>(),
                                                             ultrainio::time_point::maximum(), receipt.cpu_usage_us);
                        }
                    }

                    chain->finalizeBlock();
                    chain->commitBlock();
                    needs_push_whole_block = false;
                    // TODO(yufengshen) : CHECK if the produced block is the same as the ba1 block, e.g.
                    // action/trx_mroot ...
                } catch (const ultrainio::exception &e) {
                    edump((e.to_detail_string()));
                }

            }
        }

        if (needs_push_whole_block) {
            chain->abortBlock();
            chain->pushBlock(block);
        }
        m_currentPreRunBa0TrxIndex = -1;
        m_voterPreRunBa0InProgress = false;

        std::shared_ptr<BlockState> new_bs = chain->headBlockState();
    }

    void UranusController::init() {
        m_proposerMsgMap.clear();
        m_echoMsgMap.clear();
        m_cacheProposeMsgMap.clear();
        m_cacheEchoMsgMap.clear();
        m_echoMsgAllPhase.clear();
        startSyncTaskTimer();
    }

    const BlockRecord *UranusController::getBa0Block() {
        return &m_ba0Block;
    }

    ultrainio::BlockIdType UranusController::getPreviousBlockhash() {
        return Chain::getInstance->headBlockId();
    }

    void UranusController::saveEchoMsg() {
        if (m_echoMsgAllPhase.size() >= m_maxCachedAllPhaseKeys) {
            clearOldCachedAllPhaseMsg();
        }

        msgkey msg_key;
        msg_key.blockNum = UranusNode::getInstance()->getBlockNum();
        msg_key.phase = UranusNode::getInstance()->getPhase();
        msg_key.phase += UranusNode::getInstance()->getBaxCount();
        m_echoMsgAllPhase.insert(make_pair(msg_key, m_echoMsgMap));
    }

    void UranusController::startSyncTaskTimer() {
        m_syncTaskTimer->expires_from_now(m_syncTaskPeriod);
        m_syncTaskTimer->async_wait([this](boost::system::error_code ec) {
            if (ec.value() == boost::asio::error::operation_aborted) {
            } else {
                processSyncTask();
                startSyncTaskTimer();
            }
        });
    }

    void UranusController::processSyncTask() {
        if (m_syncTaskQueue.empty()) {
            return;
        }
        std::shared_ptr<Chain> chain = Chain::getInstance();
        uint32_t last_num = getLastBlocknum();
        uint32_t max_count = m_maxPacketsOnce / m_syncTaskQueue.size() + 1;
        uint32_t send_count = 0;
        for (std::list<SyncTask>::iterator it = m_syncTaskQueue.begin(); it != m_syncTaskQueue.end();) {
            while (send_count < max_count && it->startBlock <= it->endBlock && it->startBlock <= last_num) {
                auto b = chain->fetchBlockByNumber(it->startBlock);
                if (b) {
                    UranusNode::getInstance()->sendMessage(it->peerAddr, *b);
                } else if (it->startBlock == last_num) { // try to send last block next time
                    break;
                } // else: skip the block if not exist

                it->startBlock++;
                send_count++;
            }

            if (it->startBlock > it->endBlock) {
                it = m_syncTaskQueue.erase(it);
            } else {
                ++it;
            }
        }

    }

    //NOTE: The template T must be type of map because the erase operation is not generalized.
    template<class T>
    void UranusController::clearMsgCache(T cache, uint32_t blockNum) {
        for (auto msg_it = cache.begin(); msg_it != cache.end();) {
            if (msg_it->first.blockNum <= blockNum) {
                cache.erase(msg_it++);
            } else {
                ++msg_it;
            }
        }
    }

    ultrainio::time_point UranusController::getFastTimestamp() {
        return m_fast_timestamp;
    }

    void UranusController::resetTimestamp() {
        m_fast_timestamp = ultrainio::time_point::now();
    }

    void UranusController::clearOldCachedProposeMsg() {
        uint32_t old_block_num = 0xffffffff;
        for (auto &it : m_cacheProposeMsgMap) {
            if (it.first.blockNum < old_block_num) {
                old_block_num = it.first.blockNum;
            }
        }

        for (auto it = m_cacheProposeMsgMap.begin(); it != m_cacheProposeMsgMap.end();) {
            if (it->first.blockNum == old_block_num) {
                m_cacheProposeMsgMap.erase(it++);
            } else {
                ++it;
            }
        }
    }

    void UranusController::clearOldCachedEchoMsg() {
        uint32_t old_block_num = 0xffffffff;
        for (auto &it : m_cacheEchoMsgMap) {
            if (it.first.blockNum < old_block_num) {
                old_block_num = it.first.blockNum;
            }
        }

        for (auto it = m_cacheEchoMsgMap.begin(); it != m_cacheEchoMsgMap.end();) {
            if (it->first.blockNum == old_block_num) {
                m_cacheEchoMsgMap.erase(it++);
            } else {
                ++it;
            }
        }
    }

    void UranusController::clearOldCachedAllPhaseMsg() {
        if (m_echoMsgAllPhase.empty()) {
            return;
        }

        msgkey key = m_echoMsgAllPhase.begin()->first;
        for (auto &it : m_echoMsgAllPhase) {
            if (it.first.phase < key.phase) {
                key.phase = it.first.phase;
            }
        }

        auto itor = m_echoMsgAllPhase.find(key);
        if (itor != m_echoMsgAllPhase.end()) {
            m_echoMsgAllPhase.erase(itor);
        }
    }
}  // namespace ultrainio
