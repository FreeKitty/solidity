/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @author Christian <c@ethdev.com>
 * @date 2016
 * Framework for executing contracts and testing them using RPC.
 */

#include <test/ExecutionFramework.h>

#include <libdevcore/CommonIO.h>

#include <boost/test/framework.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <evmc/include/evmc/evmc.hpp>
#include <evmc/include/evmc/loader.h>
#include <evmc/include/evmc/helpers.hpp>

#include <cstdlib>

#include <chrono>
#include <thread>

using namespace std;
using namespace dev;
using namespace dev::test;

namespace // anonymous
{


h256 const EmptyTrie("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

string getIPCSocketPath()
{
	string ipcPath = dev::test::Options::get().ipcPath.string();
	if (ipcPath.empty())
		BOOST_FAIL("ERROR: ipcPath not set! (use --ipcpath <path> or the environment variable ETH_TEST_IPC)");

	return ipcPath;
}

evmc::vm& getVM()
{
	static evmc_loader_error_code errorCode;
	static evmc::vm theVM(
		evmc_load_and_create("/home/chris/ethereum/solidity/deps/lib/libevmone.so", &errorCode)
	);
	return theVM;
}

Address convertFromEVMC(evmc_address const& _addr)
{
	return Address(bytes(begin(_addr.bytes), end(_addr.bytes)));
}
evmc_address convertToEVMC(Address const& _addr)
{
	evmc_address a;
	for (size_t i = 0; i < 20; ++i)
		a.bytes[i] = _addr[i];
	return a;
}
h256 convertFromEVMC(evmc_bytes32 const& _data)
{
	return h256(bytes(begin(_data.bytes), end(_data.bytes)));
}
evmc_bytes32 convertToEVMC(h256 const& _data)
{
	evmc_bytes32 d;
	for (size_t i = 0; i < 32; ++i)
		d.bytes[i] = _data[i];
	return d;
}


}

class ExecutionFramework::Host: public evmc::Host
{
public:
	explicit Host(evmc::vm& _vm): m_vm(_vm) {}

	struct Account
	{
		evmc_uint256be balance = {};
		size_t nonce = 0;
		bytes code;
		evmc_bytes32 codeHash = {};
		std::map<evmc_bytes32, evmc_bytes32> storage;
	};

	struct State
	{
		std::map<evmc_address, Account> accounts;
		std::vector<LogEntry> logs;
	};

	Account* account(evmc_address const& _address)
	{
		auto it = m_state.accounts.find(_address);
		return it == m_state.accounts.end() ? nullptr : &it->second;
	}

	void reset() { m_state = State{}; m_currentAddress = {}; }

	bool account_exists(evmc_address const& _addr) noexcept final
	{
		return account(_addr) != nullptr;
	}

	evmc_bytes32 get_storage(evmc_address const& _addr, evmc_bytes32 const& _key) noexcept final
	{
		if (Account* acc = account(_addr))
			return acc->storage[_key];
		return {};
	}

	evmc_storage_status set_storage(
		evmc_address const& _addr,
		evmc_bytes32 const& _key,
		evmc_bytes32 const& _value
	) noexcept final
	{
		evmc_bytes32 previousValue = m_state.accounts[_addr].storage[_key];
		m_state.accounts[_addr].storage[_key] = _value;

		// TODO there are more possible values, especially "MODIFIED_AGAIN".
		return previousValue == _value ? EVMC_STORAGE_UNCHANGED : EVMC_STORAGE_MODIFIED;
	}

	evmc_uint256be get_balance(evmc_address const& _addr) noexcept final
	{
		if (Account const* acc = account(_addr))
			return acc->balance;
		return {};
	}

	size_t get_code_size(evmc_address const& _addr) noexcept final
	{
		if (Account const* acc = account(_addr))
			return acc->code.size();
		return 0;
	}

	evmc_bytes32 get_code_hash(evmc_address const& _addr) noexcept final
	{
		if (Account const* acc = account(_addr))
			return acc->codeHash;
		return {};
	}

	size_t copy_code(
		evmc_address const& _addr,
		size_t _codeOffset,
		uint8_t* _bufferData,
		size_t _bufferSize
	) noexcept final
	{
		// TODO is this supposed to fill with zero bytes?
		Account const* acc = account(_addr);
		if (!acc)
			return 0;
		size_t i = 0;
		for (; i < _bufferSize && _codeOffset + i < acc->code.size(); i++)
			_bufferData[i] = acc->code[_codeOffset + i];
		return i;
	}

	void selfdestruct(evmc_address const& _addr, evmc_address const& _beneficiary) noexcept final
	{
		m_state.accounts[_beneficiary].balance = m_state.accounts[_addr].balance;
		m_state.accounts.erase(_addr);
	}

	evmc::result call(evmc_message const& _message) noexcept final
	{
		u256 value{convertFromEVMC(_message.value)};
		Account* sender = account(_message.sender);
		// TODO are we responsible for checking balance?
		if (!sender)// || u256(convertFromEVMC(sender->balance)) < value)
		{
			evmc_result res{};
			// TODO correct to use revert here?
			res.status_code = EVMC_REVERT;
			return evmc::result{res};
		}

		State stateBackup = m_state;

		bytes code;

		evmc_message message = _message;
		if (message.kind == EVMC_CREATE)
		{
			// TODO this is not the right formula
			// TODO is the nonce incremented on failure, too?
			Address createAddress(keccak256(
				bytes(begin(message.sender.bytes), end(message.sender.bytes)) +
				asBytes(to_string(sender->nonce++))
			));
			message.destination = convertToEVMC(createAddress);
			code = bytes(message.input_data, message.input_data + message.input_size);
		}
		else if (message.kind == EVMC_DELEGATECALL)
		{
			code = m_state.accounts[message.destination].code;
			message.destination = m_currentAddress;
		}
		else if (message.kind == EVMC_CALLCODE)
		{
			code = m_state.accounts[message.destination].code;
			message.destination = m_currentAddress;
		}
		else
			code = m_state.accounts[message.destination].code;
		//TODO CREATE2

		Account& destination = m_state.accounts[message.destination];

		if (value != 0 && message.kind != EVMC_DELEGATECALL && message.kind != EVMC_CALLCODE)
		{
			sender->balance = convertToEVMC(u256(convertFromEVMC(sender->balance)) - value);
			destination.balance = convertToEVMC(u256(convertFromEVMC(destination.balance)) + value);
		}

		evmc_address currentAddress = m_currentAddress;
		m_currentAddress = message.destination;
		evmc::result result = m_vm.execute(*this, EVMC_PETERSBURG, message, code.data(), code.size());
		m_currentAddress = currentAddress;

		if (result.status_code != EVMC_SUCCESS)
			m_state = stateBackup;
		else if (message.kind == EVMC_CREATE)
		{
			result.create_address = message.destination;
			destination.code = bytes(result.output_data, result.output_data + result.output_size);
			destination.codeHash = convertToEVMC(keccak256(destination.code));
		}

		return result;
	}

	evmc_tx_context get_tx_context() noexcept final { return {}; }

	evmc_bytes32 get_block_hash(int64_t number) noexcept final
	{
		int64_t current_block_number = get_tx_context().block_number;

		auto example_block_hash = evmc_bytes32{};
		if (number < current_block_number && number >= current_block_number - 256)
			example_block_hash = {{1, 1, 1, 1}};
		return example_block_hash;
	}

	void emit_log(
		evmc_address const& _addr,
		uint8_t const* _data,
		size_t _dataSize,
		evmc_bytes32 const _topics[],
		size_t _topicsCount
	) noexcept final
	{
		LogEntry entry;
		entry.address = convertFromEVMC(_addr);
		for (size_t i = 0; i < _topicsCount; ++i)
			entry.topics.emplace_back(convertFromEVMC(_topics[i]));
		entry.data = bytes(_data, _data + _dataSize);
		m_state.logs.emplace_back(std::move(entry));
	}

	State m_state;
	evmc_address m_currentAddress = {};

private:
	evmc::vm& m_vm;
};


ExecutionFramework::ExecutionFramework():
	ExecutionFramework(getIPCSocketPath(), dev::test::Options::get().evmVersion())
{
}

ExecutionFramework::ExecutionFramework(string const&, langutil::EVMVersion _evmVersion):
	m_evmVersion(_evmVersion),
	m_optimiserSettings(solidity::OptimiserSettings::minimal()),
	m_showMessages(dev::test::Options::get().showMessages),
	m_evmcHost(make_shared<Host>(getVM()))
{
	if (dev::test::Options::get().optimizeYul)
		m_optimiserSettings = solidity::OptimiserSettings::full();
	else if (dev::test::Options::get().optimize)
		m_optimiserSettings = solidity::OptimiserSettings::standard();
	m_evmcHost->reset();
}

std::pair<bool, string> ExecutionFramework::compareAndCreateMessage(
	bytes const& _result,
	bytes const& _expectation
)
{
	if (_result == _expectation)
		return std::make_pair(true, std::string{});
	std::string message =
			"Invalid encoded data\n"
			"   Result                                                           Expectation\n";
	auto resultHex = boost::replace_all_copy(toHex(_result), "0", ".");
	auto expectedHex = boost::replace_all_copy(toHex(_expectation), "0", ".");
	for (size_t i = 0; i < std::max(resultHex.size(), expectedHex.size()); i += 0x40)
	{
		std::string result{i >= resultHex.size() ? string{} : resultHex.substr(i, 0x40)};
		std::string expected{i > expectedHex.size() ? string{} : expectedHex.substr(i, 0x40)};
		message +=
			(result == expected ? "   " : " X ") +
			result +
			std::string(0x41 - result.size(), ' ') +
			expected +
			"\n";
	}
	return make_pair(false, message);
}

u256 ExecutionFramework::gasLimit() const
{
	return 0;
}

u256 ExecutionFramework::gasPrice() const
{
	return 0;
}

u256 ExecutionFramework::blockHash(u256 const&) const
{
	return 0;
}

void ExecutionFramework::sendMessage(bytes const& _data, bool _isCreation, u256 const& _value)
{
	if (m_showMessages)
	{
		if (_isCreation)
			cout << "CREATE " << m_sender.hex() << ":" << endl;
		else
			cout << "CALL   " << m_sender.hex() << " -> " << m_contractAddress.hex() << ":" << endl;
		if (_value > 0)
			cout << " value: " << _value << endl;
		cout << " in:      " << toHex(_data) << endl;
	}
	evmc_message message = {};
	message.input_data = _data.data();
	message.input_size = _data.size();
	message.sender = convertToEVMC(m_sender);
	message.value = convertToEVMC(_value);
	// ensure account exists and has enough money
	m_evmcHost->m_state.accounts[message.sender].balance = convertToEVMC(_value);
	if (_isCreation)
	{
		message.kind = EVMC_CREATE;
		message.destination = convertToEVMC(Address{});
	}
	else
	{
		message.kind = EVMC_CALL;
		message.destination = convertToEVMC(m_contractAddress);
	}
	message.gas = m_gas.convert_to<int64_t>();

	evmc::result result = m_evmcHost->call(message);

	m_output = bytes(result.output_data, result.output_data + result.output_size);
	if (_isCreation)
	{
		m_code = m_output;
		m_contractAddress = convertFromEVMC(result.create_address);
	}

	m_gasUsed = m_gas - result.gas_left;
	m_transactionSuccessful = (result.status_code == EVMC_SUCCESS);

	m_blockNumber++;
	m_logs = std::move(m_evmcHost->m_state.logs);
	m_evmcHost->m_state.logs.clear();

	if (m_showMessages)
	{
		cout << " out:     " << toHex(m_output) << endl;
		cout << " result: " << size_t(result.status_code) << endl;
		cout << " gas used: " << m_gasUsed.str() << endl;
	}
}

void ExecutionFramework::sendEther(Address const& _addr, u256 const& _amount)
{
	evmc_uint256be& balance = m_evmcHost->m_state.accounts[convertToEVMC(_addr)].balance;
	balance = convertToEVMC(u256(convertFromEVMC(balance)) + _amount);
}

size_t ExecutionFramework::currentTimestamp()
{
	return 0;
}

size_t ExecutionFramework::blockTimestamp(u256)
{
	return 0;
}

Address ExecutionFramework::account(size_t)
{
	return Address(0);
}

bool ExecutionFramework::addressHasCode(Address const& _addr)
{
	if (Host::Account const* acc = m_evmcHost->account(convertToEVMC(_addr)))
		return !acc->code.empty();
	else
		return false;
}

u256 ExecutionFramework::balanceAt(Address const& _addr)
{
	if (Host::Account const* acc = m_evmcHost->account(convertToEVMC(_addr)))
		return u256(convertFromEVMC(acc->balance));
	else
		return 0;
}

bool ExecutionFramework::storageEmpty(Address const& _addr)
{
	Host::Account const* acc = m_evmcHost->account(convertToEVMC(_addr));
	if (!acc)
		return true;
	for (auto const& entry: acc->storage)
		if (!(entry.second == evmc_bytes32{}))
			return false;
	return true;
}
