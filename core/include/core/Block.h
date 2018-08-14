#pragma once

namespace ultrainio {
    struct BlockHeader {
        std::string                      proposerPk;
        std::string                      proposerProof;
        uint32_t                         version = 0;
        /**
         * DO NOT MAKE THIS OPEN SOURCE THIS TIME
         */
    };

    struct Block : public BlockHeader {
        /**
         * DO NOT MAKE THIS OPEN SOURCE THIS TIME
         */
    };
}