#include <iostream>
#include <fstream>
#include <iterator>
#include <vector>
#include <filesystem>
#include <map>
#include <string>
#include <regex>

const size_t FILE_HEADER_LEN = 24;
const size_t PACKET_HEADER_LEN = 12;
const size_t PACKET_SIZE_LEN = 4;

const size_t TCP_TYPE = 0x88;
const size_t TCP_HEADER_LEN = 74;

namespace fs = std::filesystem;
using Data = std::vector<uint8_t>;

union Size32
{
	struct {
		uint8_t Size3;
		uint8_t Size2;
		uint8_t Size1;
		uint8_t Size0;
	} Raw;
	uint32_t Value;
};

struct Params
{
	std::string file;
	std::string uri;
	std::vector<std::string> fields;
} params;

struct Result
{
	std::string Method;
	std::string Uri;
	std::map<std::string, std::string> FormData;
};

bool GetFile(fs::path const& path, Data& output)
{
	// File not found
	if (!fs::exists(path)) {
		return false;
	}

	// Read data of file
	std::ifstream fin(path, std::ios::binary);
	if (!fin.is_open()) {
		return false;
	}

	// Resize output
	size_t fileSize = fs::file_size(path);
	output.clear();
	output.resize(fileSize);

	// Read file in array
	fin.seekg(0, std::ios::beg);
	fin.read((char*)output.data(), fileSize);

	// Close
	fin.close();
	return true;
}

bool ParseArguments(int argc, char* argv[], Params& params)
{
	if (argc < 2) {
		return false;
	}
	params.file = std::string(argv[1]);

	size_t parsed = 2;

	if (argc < parsed + 2) {
		return true;
	}
	if (std::string(argv[parsed]) == "-u") {
		params.uri = std::string(argv[parsed + 1]);
		parsed += 2;
	}

	if (argc < parsed + 2) {
		return true;
	}
	if (std::string(argv[parsed]) == "--") {
		for (size_t i = parsed + 1; i < argc; ++i) {
			params.fields.emplace_back(argv[i]);
		}
	}

	return true;
}

std::string ReadUntil(std::string const& data, size_t& cursor, char ch = '\0')
{
	std::string result;
	while (cursor < data.size() && data[cursor] != ch) {
		result += data[cursor];
		++cursor;
	}
	if (cursor < data.size()) ++cursor;
	return result;
}

size_t Skip(std::string const& data, size_t& cursor, char ch)
{
	size_t count = 0;
	for (; cursor < data.size() && data[cursor] == ch; ++cursor, ++count);
	return count;
}

size_t SkipUntil(std::string const& data, size_t& cursor, char ch)
{
	size_t count = 0;
	for (; cursor < data.size() && data[cursor] != ch; ++cursor, ++count);
	if (cursor < data.size()) ++cursor;
	return count;
}

bool IsLetter(char ch)
{
	return ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z');
}

bool IsHttpMethod(std::string const& method)
{
	return method == "GET" || method == "POST" || method == "PUT" || method == "DELETE";
}

char ParseHex(char ch)
{
	if ('a' <= ch && ch <= 'f') {
		return ch - 'a' + 10;
	}
	if ('A' <= ch && ch <= 'F') {
		return ch - 'A' + 10;
	}
	if ('0' <= ch && ch <= '9') {
		return ch - '0';
	}
	return 0;
}

std::string DecodeUrl(std::string const& url)
{
	std::string result;
	for (size_t i = 0; i < url.size(); ++i) {
		if (url[i] == '%' && i + 2 < url.size()) {
			uint16_t code = ParseHex(url[i + 1]) * 16 + ParseHex(url[i + 2]);
			result += std::wctob(code);
			i += 2;
		}
		else if (url[i] == '+') {
			result += ' ';
		}
		else {
			result += url[i];
		}
	}
	return result;
}

std::map<std::string, std::string> ParseFormData(std::string const& input)
{
	size_t cursor = 0;
	SkipUntil(input, cursor, '?');
	if (cursor == input.size()) {
		cursor = 0;
	}

	std::map<std::string, std::string> output;
	while (true) {
		std::string row = ReadUntil(input, cursor, '&');
		if (row.empty() || row.size() == input.size()) {
			break;
		}

		size_t i = 0;

		std::string name = ReadUntil(row, i, '=');
		if (name.empty()) {
			continue;
		}
		std::string value = ReadUntil(row, i);

		output.insert(std::make_pair(DecodeUrl(name), DecodeUrl(value)));
	}
	return output;
}

bool ParseHttp(std::string const& raw, Result& result)
{
	size_t cursor = 0;

	std::string method = ReadUntil(raw, cursor, ' ');
	if (!IsHttpMethod(method)) {
		return false;
	}
	std::string urn = ReadUntil(raw, cursor, ' ');
	SkipUntil(raw, cursor, '\n');

	std::map<std::string, std::string> headers;
	while (true) {
		std::string row = ReadUntil(raw, cursor, '\r');
		++cursor; // skip \n
		if (row.empty()) {
			break;
		}

		size_t i = 0;

		std::string name = ReadUntil(row, i, ':');
		if (name.empty()) {
			continue;
		}
		Skip(row, i, ' ');
		std::string value = ReadUntil(row, i);

		headers.insert(std::make_pair(name, value));
	}

	std::string body = ReadUntil(raw, cursor);

	size_t i = 0;
	result.Method = method;
	result.Uri = ReadUntil(headers["Host"] + urn, i, '?');
	result.FormData = ParseFormData(urn);
	if (result.FormData.empty()) {
		result.FormData = ParseFormData(body);
	}

	return true;
}

bool ParseTcp(Data const& data, size_t pos, size_t size)
{
	if (pos + TCP_HEADER_LEN > data.size()) {
		return false;
	}
	if (TCP_HEADER_LEN > size) {
		return false;
	}
	pos += TCP_HEADER_LEN;
	size -= TCP_HEADER_LEN;

	while (size != 0 && pos < data.size() && !IsLetter(data[pos])) {
		++pos;
		--size;
	}
	if (size == 0 || pos >= data.size()) {
		return false;
	}

	std::string payload;
	std::copy(data.begin() + pos, data.begin() + pos + size, std::back_inserter(payload));

	Result res;
	if (ParseHttp(payload, res)) {
		if (!res.FormData.empty()) {
			if (params.uri.empty() || res.Uri.find(params.uri) != std::string::npos) {
				std::cout << "URI = " << res.Uri << std::endl;
				if (!params.fields.empty()) {
					std::cout << "Method = " << res.Method << std::endl;
					for (std::string const& field : params.fields) {
						std::cout << field << " = " << res.FormData[field] << std::endl;
					}
				}
				else if (!res.FormData.empty()) {
					std::cout << "Method = " << res.Method << std::endl;
					for (auto const& field : res.FormData) {
						std::cout << field.first << " = " << field.second << std::endl;
					}
				}
				std::cout << std::endl;
			}
		}
	}

	return true;
}

bool ParseSize(Data const& data, size_t& pos, size_t& size)
{
	if (pos + PACKET_SIZE_LEN > data.size()) {
		return false;
	}
	Size32 packetSize;
	packetSize.Raw.Size3 = data[pos + 0];
	packetSize.Raw.Size2 = data[pos + 1];
	packetSize.Raw.Size1 = data[pos + 2];
	packetSize.Raw.Size0 = data[pos + 3];
	size = packetSize.Value;
	pos += PACKET_SIZE_LEN;
	return true;
}

bool ParsePacket(Data const& data, size_t& pos)
{
	pos += PACKET_HEADER_LEN;
	size_t size = 0;
	if (!ParseSize(data, pos, size)) {
		return false;
	}
	if (pos + size > data.size()) {
		return false;
	}
	switch (data[pos]) {
	case TCP_TYPE:
		ParseTcp(data, pos, size);
		break;
	}
	pos += size;
	return true;
}

bool Parse(Data const& data)
{
	if (!params.uri.empty()) {
		std::cout << "URI = " << params.uri << std::endl;
		std::cout << std::endl;
	}
	for (size_t pos = FILE_HEADER_LEN; pos < data.size(); ) {
		if (!ParsePacket(data, pos)) {
			return false;
		}
	}
	return true;
}

int main(int argc, char* argv[])
{
	Data data;
	if (!ParseArguments(argc, argv, params)) {
		std::cout << "Usage: ./parser file -u uri -- [fields]" << std::endl;
		return 1;
	}
	if (!GetFile(params.file, data)) {
		std::cout << "Impossoble to load file " << params.file << "!" << std::endl;
		return 2;
	}
	if (!Parse(data)) {
		std::cout << "Impossoble to parse!" << std::endl;
		return 3;
	}
	return 0;
}
