/**
 *  @file
 *  @copyright defined in ultrain-core-for-open-source/LICENSE.txt
 */
#pragma once

#include <chrono>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include <boost/chrono/include.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <core/Message.h>
#include <core/Transaction.h>
#include <crypto/Vrf.h>

#include <rpos/VoterSystem.h>

namespace ultrainio {

#define GLOBAL_NODE_NUMBER         6
#define MOST_ATTACK_NUMBER_F       ((VoterSystem::VOTER_STAKES - 50) / 3)
#define THRESHOLD_SEND_ECHO        (MOST_ATTACK_NUMBER_F + 1)
#define THRESHOLD_NEXT_ROUND       (2 * MOST_ATTACK_NUMBER_F + 1)
#define THRESHOLD_SYNCING          (2 * MOST_ATTACK_NUMBER_F + 1)
#define INVALID_BLOCK_NUM          0xFFFFFFFF

#define CODE_EXEC_MAX_TIME_S       3
#define MAX_PROPOSE_TRX_COUNT      5000

    class UranusController;

    class UranusNode : public std::enable_shared_from_this<UranusNode> {
    public:
        static const int MAX_ROUND_SECONDS;
        static const int MAX_PHASE_SECONDS;
        static boost::chrono::system_clock::time_point GENESIS;
        static uint8_t URANUS_PUBLIC_KEY[VRF_PUBLIC_KEY_LEN];
        static uint8_t URANUS_PRIVATE_KEY[VRF_PRIVATE_KEY_LEN];

        static std::shared_ptr<UranusNode> initAndGetInstance(boost::asio::io_service &ioservice);

        static std::shared_ptr<UranusNode> getInstance();

        void setNonProducingNode(bool);

        static bool verifyRole(uint32_t blockNum, uint16_t phase, const std::string &role_proof, const std::string &pk);

        uint32_t getBlockNum() const;

        uint32_t getBaxCount() const;

        bool getSyncingStatus() const;

        void init();

        void readyToJoin();

        void readyToConnect();

        void readyLoop(uint32_t timeout);

        bool startup();

        void run();

        void join();

        void reset();

        void sendMessage(const EchoMsg &echo);

        void sendMessage(const ProposeMsg &propose);

        void sendMessage(const std::string &peer_addr, const Block &msg);

        bool sendMessage(const SyncRequestMessage &msg);

        void sendMessage(const std::string &peer_addr, const RspLastBlockNumMsg &msg);

        ConsensusPhase getPhase() const;

        void ba0Process();

        uint32_t isSyncing();

        void ba1Process();

        void baxProcess();

        void ba0Loop(uint32_t timeout);

        void ba1Loop(uint32_t timeout);

        void baxLoop(uint32_t timeout);

        bool handleMessage(const EchoMsg &echo);

        bool handleMessage(const ProposeMsg &propose);

        bool handleMessage(const std::string &peer_addr, const SyncRequestMessage &msg);

        bool handleMessage(const std::string &peer_addr, const ReqLastBlockNumMsg &msg);

        bool handleMessage(const Block &block, bool last_block);

        uint32_t getLastBlocknum();

        bool syncFail();

        void cancelTimer();

        void applyBlockLoop(uint32_t timeout);

        int getStakes(const std::string &pk);

        ultrainio::BlockIdType getPreviousHash();

        bool isProcessNow();

    private:
        explicit UranusNode(boost::asio::io_service &ioservice);

        void applyBlock();

        void applyBlockOnce();

        void applyBlock(bool once);

        void fastBlock(uint32_t blockNum);

        void fastBa0();

        void fastBa1();

        void fastBax();

        void preRunBa0BlockLoop(uint32_t timeout);

        void preRunBa0BlockStep();

        uint32_t getRoundInterval();

        static std::shared_ptr<UranusNode> s_self;
        bool m_ready;
        bool m_connected;
        bool m_syncing;
        bool m_syncFailed;
        bool m_isNonProducingNode = false;
        ConsensusPhase m_phase;
        uint32_t m_baxCount;
        boost::asio::deadline_timer m_timer;
        boost::asio::deadline_timer m_preRunTimer;
        std::shared_ptr<UranusController> m_controllerPtr;
    };
}
