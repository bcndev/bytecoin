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

void LoggerManager::operator()(
    const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) {
	std::unique_lock<std::mutex> lock(reconfigure_lock);
	LoggerGroup::operator()(category, level, time, body);
}

void LoggerManager::configure_default(const std::string &log_folder, const std::string &log_prefix) {
	std::unique_lock<std::mutex> lock(reconfigure_lock);  // TODO - investigate possible deadlocks
	loggers.clear();
	LoggerGroup::loggers.clear();

	std::unique_ptr<logging::CommonLogger> logger(
	    new FileLogger(log_folder + "/" + log_prefix + "verbose", 128 * 1024, TRACE));
	loggers.emplace_back(std::move(logger));
	add_logger(*loggers.back());

	logger.reset(new FileLogger(log_folder + "/" + log_prefix + "errors", 128 * 1024, WARNING));
	loggers.emplace_back(std::move(logger));
	add_logger(*loggers.back());

	logger.reset(new ConsoleLogger(INFO));
	logger->set_pattern("%T %l %C ");
	loggers.emplace_back(std::move(logger));
	add_logger(*loggers.back());
}

void LoggerManager::configure(const JsonValue &val) {
	std::unique_lock<std::mutex> lock(reconfigure_lock);  // TODO - investigate possible deadlocks
	loggers.clear();
	LoggerGroup::loggers.clear();
	Level globalLevel;
	if (val.contains("globalLevel")) {
		auto levelVal = val("globalLevel");
		if (levelVal.is_integer()) {
			globalLevel = static_cast<Level>(levelVal.get_integer());
		} else {
			throw std::runtime_error("parameter globalLevel has wrong type");
		}
	} else {
		globalLevel = TRACE;
	}
	std::vector<std::string> globalDisabledCategories;

	if (val.contains("globalDisabledCategories")) {
		auto globalDisabledCategoriesList = val("globalDisabledCategories");
		if (globalDisabledCategoriesList.is_array()) {
			size_t countOfCategories = globalDisabledCategoriesList.size();
			for (size_t i = 0; i < countOfCategories; ++i) {
				auto categoryVal = globalDisabledCategoriesList[i];
				if (categoryVal.is_string()) {
					globalDisabledCategories.push_back(categoryVal.get_string());
				}
			}
		} else {
			throw std::runtime_error("parameter globalDisabledCategories has wrong type");
		}
	}

	if (val.contains("loggers")) {
		auto loggersList = val("loggers");
		if (loggersList.is_array()) {
			size_t countOfLoggers = loggersList.size();
			for (size_t i = 0; i < countOfLoggers; ++i) {
				auto loggerConfiguration = loggersList[i];
				if (!loggerConfiguration.is_object()) {
					throw std::runtime_error("loggers element must be objects");
				}

				Level level = INFO;
				if (loggerConfiguration.contains("level")) {
					level = static_cast<Level>(loggerConfiguration("level").get_integer());
				}

				std::string type = loggerConfiguration("type").get_string();
				std::unique_ptr<logging::CommonLogger> logger;

				if (type == "console") {
					logger.reset(new ConsoleLogger(level));
				} else if (type == "file") {
					std::string filename = loggerConfiguration("filename").get_string();
					auto fileLogger      = new FileLogger(filename, level);
					logger.reset(fileLogger);
				} else {
					throw std::runtime_error("Unknown logger type: " + type);
				}

				if (loggerConfiguration.contains("pattern")) {
					logger->set_pattern(loggerConfiguration("pattern").get_string());
				}

				std::vector<std::string> disabledCategories;
				if (loggerConfiguration.contains("disabledCategories")) {
					auto disabledCategoriesVal = loggerConfiguration("disabledCategories");
					size_t countOfCategories   = disabledCategoriesVal.size();
					for (size_t i = 0; i < countOfCategories; ++i) {
						auto categoryVal = disabledCategoriesVal[i];
						if (categoryVal.is_string()) {
							logger->disable_category(categoryVal.get_string());
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
	set_max_level(globalLevel);
	for (const auto &category : globalDisabledCategories) {
		disable_category(category);
	}
}
}
