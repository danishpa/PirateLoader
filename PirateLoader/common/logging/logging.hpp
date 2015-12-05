#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <Windows.h>
#include <strsafe.h>

namespace common {
namespace logging {

using std::string;
using std::vector;
using std::cout;
using std::endl;

static const size_t BUFFER_SIZE = 200;
static const size_t MAX_FORMATTING_ATTEMPTS = 50;

static const string TRACE_FORMAT = "[%hs@%lu] ";

template <typename... Args>
string format_string(string format, Args... args) {

	vector<byte> buffer;

	HRESULT result = S_OK;
	auto formatting_attempts_left = MAX_FORMATTING_ATTEMPTS;
	do {
		buffer.resize(buffer.size() + BUFFER_SIZE);
		result = StringCchPrintfA((STRSAFE_LPSTR)(buffer.data()), buffer.size(), (STRSAFE_LPCSTR)(format.c_str()), args...);
	} while ((STRSAFE_E_INSUFFICIENT_BUFFER == result) && (0 < (formatting_attempts_left--)));
	
	
	if (FAILED(result)) {
		// Will not make any more attempts
		return string();
	}
	return string((char *)(buffer.data()));
}

template <typename... Args>
void trace(string function_name, size_t line_number, string format, Args... args) {

	string trace_format = format_string(TRACE_FORMAT, function_name.c_str(), line_number);
	string message = format_string(format, args...);
	
	trace_format.append(message.c_str());
	

	cout << trace_format << endl;
}


#define TRACE(format, ...) trace(__FUNCTION__, __LINE__, format, __VA_ARGS__);

}
}
