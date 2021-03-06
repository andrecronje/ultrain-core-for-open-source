#include <log/Log.h>

#include <iostream>
#include <string>

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/attributes/named_scope.hpp>
/**
 *  @file
 *  @copyright defined in ultrain-core-for-open-source/LICENSE.txt
 */
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/detail/format.hpp>

namespace ultrainio {

    namespace logging = boost::log;
    namespace src = boost::log::sources;
    namespace keywords = boost::log::keywords;
    namespace sinks = boost::log::sinks;
    namespace expr = boost::log::expressions;

    void UltrainLog::init(const std::string &dir) {
        if (boost::filesystem::exists(dir) == false) {
            boost::filesystem::create_directories(dir);
        }

        auto pSink = logging::add_file_log
            (
                keywords::open_mode = std::ios::app,
                keywords::file_name = dir + "/%Y%m%d_" + boost::asio::ip::host_name() + ".log",
                keywords::rotation_size = 10 * 1024 * 1024,
                keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0),
                keywords::format =
                    (
                        expr::stream
                            << "[" << expr::format_date_time<boost::posix_time::ptime>("TimeStamp","%Y-%m-%d %H:%M:%S.%f")
                            << "] [" << logging::trivial::severity
                            << "] " << expr::smessage
                    )
            );

        pSink->locked_backend()->auto_flush(true);//使日志实时更新
        logging::add_common_attributes();
    }

    std::string UltrainLog::convert2Hex(const std::string& str) {
        std::string hex_str;
        uint8_t* c_str = (uint8_t*)str.data();
        char hex_char[3];
        for (int i = 0; i < str.length(); i++) {
            snprintf(hex_char, sizeof(hex_char), "%02x", c_str[i]);
            hex_str.append(hex_char);
            if (i != 0 && i%8 == 0) {
                hex_str.append(" ");
            }
        }
        return hex_str;
    }
}

