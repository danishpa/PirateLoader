#pragma once

#include <stdexcept>

namespace common {
namespace exceptions {

using std::exception;

#define DECLARE_EXCEPTION(name, base) \
class name : public base { };


DECLARE_EXCEPTION(CommonException, exception);
DECLARE_EXCEPTION(CreateFileFailedException, CommonException);
DECLARE_EXCEPTION(GetFileSizeFailedException, CommonException);
DECLARE_EXCEPTION(DllTooLargeException, CommonException);
DECLARE_EXCEPTION(VirtualAllocFailedException, CommonException);
DECLARE_EXCEPTION(ReadFileFailedException, CommonException);
DECLARE_EXCEPTION(ReadFileSizeMismatchException, CommonException);
DECLARE_EXCEPTION(DllMagicException, CommonException);
DECLARE_EXCEPTION(PEMagicException, CommonException);
DECLARE_EXCEPTION(TimeStampFormatException, CommonException);

#define LOG_AND_THROW(exception_type, msg, ...) \
{												\
	TRACE(msg, __VA_ARGS__);					\
	throw exception_type();						\
}

#define LOG_AND_THROW_WINAPI(exception_type, winapi_func)	\
{															\
	TRACE(#winapi_func " Failed. GLE=%lu", GetLastError());	\
	throw exception_type();									\
}


}
}