// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "LoggerManager.hpp"
//#include <thread>
#include "ConsoleLogger.hpp"
#include "FileLogger.hpp"
#include "platform/PathTools.hpp"

namespace logging {

void LoggerManager::write(
    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) {
	//	std::unique_lock<std::mutex> lock(reconfigure_lock);
	LoggerGroup::write(category, level, time, body);
}

void LoggerManager::configure_default(
    const std::string &log_folder, const std::string &log_prefix, const std::string &version) {
	{
		loggers.clear();
		LoggerGroup::loggers.clear();

		std::unique_ptr<logging::CommonLogger> logger =
		    std::make_unique<FileLogger>(log_folder + "/" + log_prefix + "verbose", 1024 * 1024, DEBUGGING);
		loggers.emplace_back(std::move(logger));
		add_logger(*loggers.back());

		logger = std::make_unique<FileLogger>(log_folder + "/" + log_prefix + "errors", 1024 * 1024, ERROR);
		loggers.emplace_back(std::move(logger));
		add_logger(*loggers.back());

		logger = std::make_unique<ConsoleLogger>(INFO);
		logger->set_pattern("%T %l %C ");
		loggers.emplace_back(std::move(logger));
		add_logger(*loggers.back());
	}
	write("START", TRACE, boost::posix_time::microsec_clock::local_time(),
	    version + " ----------------------------------------\n");
}

}  // namespace logging
