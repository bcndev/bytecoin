// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "LoggerManager.hpp"
#include <thread>
#include "ConsoleLogger.hpp"
#include "FileLogger.hpp"
#include "platform/PathTools.hpp"

namespace logging {

using common::JsonValue;

LoggerManager::LoggerManager() {}

void LoggerManager::write(
    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) {
	std::unique_lock<std::mutex> lock(reconfigure_lock);
	LoggerGroup::write(category, level, time, body);
}

void LoggerManager::configure_default(const std::string &log_folder, const std::string &log_prefix) {
	{
		std::unique_lock<std::mutex> lock(reconfigure_lock);  // TODO - investigate possible deadlocks
		loggers.clear();
		LoggerGroup::loggers.clear();

		std::unique_ptr<logging::CommonLogger> logger(
		    new FileLogger(log_folder + "/" + log_prefix + "verbose", 10 * 1024 * 1024, TRACE));
		loggers.emplace_back(std::move(logger));
		add_logger(*loggers.back());

		logger.reset(new FileLogger(log_folder + "/" + log_prefix + "errors", 10 * 1024 * 1024, ERROR));
		loggers.emplace_back(std::move(logger));
		add_logger(*loggers.back());

		logger.reset(new ConsoleLogger(INFO));
		logger->set_pattern("%T %l %C ");
		loggers.emplace_back(std::move(logger));
		add_logger(*loggers.back());
	}
	write(
	    "START", TRACE, boost::posix_time::microsec_clock::local_time(), "----------------------------------------\n");
}

void LoggerManager::configure(const JsonValue &val) {
	std::unique_lock<std::mutex> lock(reconfigure_lock);  // TODO - investigate possible deadlocks
	loggers.clear();
	LoggerGroup::loggers.clear();
	Level global_level;
	if (val.contains("globalLevel")) {
		auto level_val = val("globalLevel");
		if (level_val.is_integer()) {
			global_level = static_cast<Level>(level_val.get_integer());
		} else {
			throw std::runtime_error("parameter globalLevel has wrong type");
		}
	} else {
		global_level = TRACE;
	}
	std::vector<std::string> global_disabled_categories;

	if (val.contains("globalDisabledCategories")) {
		auto gdc = val("globalDisabledCategories");
		if (gdc.is_array()) {
			for (size_t i = 0; i < gdc.size(); ++i) {
				auto category_val = gdc[i];
				if (category_val.is_string()) {
					global_disabled_categories.push_back(category_val.get_string());
				}
			}
		} else {
			throw std::runtime_error("parameter globalDisabledCategories has wrong type");
		}
	}

	if (val.contains("loggers")) {
		auto loggers_list = val("loggers");
		if (loggers_list.is_array()) {
			for (size_t i = 0; i < loggers_list.size(); ++i) {
				auto logger_configuration = loggers_list[i];
				if (!logger_configuration.is_object()) {
					throw std::runtime_error("loggers element must be objects");
				}

				Level level = INFO;
				if (logger_configuration.contains("level")) {
					level = static_cast<Level>(logger_configuration("level").get_integer());
				}

				std::string type = logger_configuration("type").get_string();
				std::unique_ptr<logging::CommonLogger> logger;

				if (type == "console") {
					logger.reset(new ConsoleLogger(level));
				} else if (type == "file") {
					std::string filename = logger_configuration("filename").get_string();
					auto file_logger     = new FileLogger(filename, level);
					logger.reset(file_logger);
				} else {
					throw std::runtime_error("Unknown logger type: " + type);
				}

				if (logger_configuration.contains("pattern")) {
					logger->set_pattern(logger_configuration("pattern").get_string());
				}

				std::vector<std::string> disabled_categories;
				if (logger_configuration.contains("disabledCategories")) {
					auto dcv = logger_configuration("disabledCategories");
					for (size_t i = 0; i < dcv.size(); ++i) {
						auto category_val = dcv[i];
						if (category_val.is_string()) {
							logger->disable_category(category_val.get_string());
						}
					}
				}

				loggers.emplace_back(std::move(logger));
				add_logger(*loggers.back());
			}
		} else {
			throw std::runtime_error("loggers parameter has wrong type");
		}
	} else {
		throw std::runtime_error("loggers parameter missing");
	}
	set_max_level(global_level);
	for (const auto &category : global_disabled_categories) {
		disable_category(category);
	}
}
}
