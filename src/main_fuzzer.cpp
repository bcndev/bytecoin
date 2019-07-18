// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <seria/BinaryInputStream.hpp>
#include <string>
#include "common/Base58.hpp"
#include "p2p/LevinProtocol.hpp"
#include "p2p/P2pProtocolDefinitions.hpp"
#include "p2p/P2pProtocolTypes.hpp"
#include "platform/PathTools.hpp"

static size_t sideeffects_counter = 0;

static void sideeffect(bool result) {
	sideeffects_counter += result ? 1 : 0;
	if (sideeffects_counter % 1000000 == 0)
		std::cout << "Side Effect counter=" << sideeffects_counter << std::endl;
}

template<typename T, typename... Context>
void binary_parse(const cn::BinaryArray &msg, Context... context) {
	try {
		T t{};
		seria::from_binary(t, msg, context...);
		sideeffect(true);
	} catch (const std::exception &ex) {
	}
}

template<typename T>
void levin_parse(const cn::BinaryArray &msg) {
	T t{};

	sideeffect(cn::LevinProtocol::decode(msg, t));
}

void json_parse(const cn::BinaryArray &msg) {
	try {
		common::JsonValue::from_string(common::as_string(msg));
		sideeffect(true);
	} catch (const std::exception &ex) {
	}
}

void address_parse(const cn::BinaryArray &msg) {
	uint64_t tag = 0;
	common::BinaryArray data;
	sideeffect(common::base58::decode_addr(common::as_string(msg), &tag, &data));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0) {
		return 0;
	}

	auto tag = data[0];
	auto msg = cn::BinaryArray(data + 1, data + size);

	switch (tag) {
		/*	case 0:
		        levin_parse<cn::p2p::Handshake::Request>(msg);
		        break;
		    case 1:
		        levin_parse<cn::p2p::Handshake::Response>(msg);
		        break;
		    case 2:
		        levin_parse<cn::p2p::TimedSync::Notify>(msg);
		        break;
		    case 3:
		        levin_parse<cn::p2p::TimedSync::Response>(msg);
		        break;
		    case 4:
		        levin_parse<cn::p2p::RelayBlock::Notify>(msg);
		        break;
		    case 5:
		        levin_parse<cn::p2p::RelayTransactions::Notify>(msg);
		        break;
		    case 6:
		        levin_parse<cn::p2p::GetObjects::Request>(msg);
		        break;
		    case 7:
		        levin_parse<cn::p2p::GetObjects::Response>(msg);
		        break;
		    case 8:
		        levin_parse<cn::p2p::GetChain::Request>(msg);
		        break;
		    case 9:
		        levin_parse<cn::p2p::GetChain::Response>(msg);
		        break;
		    case 10:
		        levin_parse<cn::p2p::SyncPool::Request>(msg);
		        break;
		    case 11:
		        levin_parse<cn::p2p::SyncPool::Response>(msg);
		        break;
		    case 12:
		        levin_parse<cn::p2p::Checkpoint::Notify>(msg);
		        break;
		    case 13:
		        levin_parse<cn::p2p::GetStatInfo::Request>(msg);
		        break;
		    case 14:
		        levin_parse<cn::p2p::GetStatInfo::Response>(msg);
		        break;
		    case 128:
		        binary_parse<cn::BlockTemplate>(msg);
		        break;
		    case 129:
		        binary_parse<cn::TransactionInput>(msg, uint8_t(1));  // V1
		        break;
		    case 130:
		        binary_parse<cn::TransactionInput>(msg, uint8_t(4));  // V4
		        break;
		    case 131:
		        binary_parse<cn::TransactionOutput>(msg, uint8_t(1));  // V1
		        break;
		    case 132:
		        binary_parse<cn::TransactionOutput>(msg, uint8_t(4));  // V4
		        break;
		    case 133:
		        binary_parse<cn::Transaction>(msg);
		        break;
		    case 134:
		        binary_parse<cn::RootBlock>(msg);
		        break;
		    case 135:
		        binary_parse<cn::BlockTemplate>(msg);
		        break;
		    case 136:
		        binary_parse<cn::SignedCheckpoint>(msg);
		        break;
		    case 137:
		        binary_parse<cn::SendproofAmethyst>(msg);
		        break;*/
	case 200:
		json_parse(msg);
		break;
	case 201:
		address_parse(msg);
		break;
	}
	return 0;
}

#if !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

int main() {
	common::BinaryArray ba;
	invariant(platform::load_file("../../bytecoin2/build/crash-2a4b9774188d29665fe90968723689749ef44045", ba), "");
	LLVMFuzzerTestOneInput(ba.data(), ba.size());
}

#endif
