#ifndef __HTTP_H__
#define __HTTP_H__

#include <unordered_map>
#include "socket.h"

namespace nsNW
{

enum class Method
{
	HTTP_GET,
	HTTP_HEAD,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
	HTTP_CONNECT,
	HTTP_OPTION,
	HTTP_TRACE
};

std::string to_string(Method m)
{
	std::string method;
	switch (m)
	{
		case nsNW::Method::HTTP_GET:
			method = "GET";
			break;
		case nsNW::Method::HTTP_HEAD:
			method = "HEAD";
			break;
		case nsNW::Method::HTTP_POST:
			method = "POST";
			break;
		case nsNW::Method::HTTP_PUT:
			method = "PUT";
			break;
		case nsNW::Method::HTTP_DELETE:
			method = "DELETE";
			break;
		case nsNW::Method::HTTP_CONNECT:
			method = "CONNECT";
			break;
		case nsNW::Method::HTTP_OPTION:
			method = "OPTION";
			break;
		case nsNW::Method::HTTP_TRACE:
			method = "TRACE";
			break;
		default:
			break;
	}
	return method;
}

enum class RESPONSE_CODE
{
	INFORMATION		= 100,
	SUCCESS			= 200,
	REDIRECT		= 300,
	CLIENT_ERROR	= 400,
	SERVER_ERROR	= 500
};

struct Response
{
	RESPONSE_CODE		responseCategory{};
	int					responseCode{};
	std::string			body;
};

class Http
{
public:
	bool init(const std::string& version, const std::string& scheme, const std::string& host, int port = 80);	// Default for HTTP
	std::string formRequest(Method method, const std::string& uri, const std::string& body);

	bool http_GET(std::string& request);
	bool http_HEAD(std::string& request);
	bool http_POST(std::string& request);
	bool http_PUT(std::string& request);
	bool http_DELETE(std::string& request);
	bool http_CONNECT(std::string& request);
	bool http_OPTION(std::string& request);
	bool http_TRACE(std::string& request);

protected:
	bool parseVersion(const std::string& version);
	bool parseUri(const std::string& uri);
	bool parseParams(const std::string& params);

protected:
	std::string											m_version;
	std::string											m_host;
	std::string											m_scheme;
	std::string											m_uriPath;
	int													m_port;
	std::vector<std::pair<std::string, std::string>>	m_queries;
};

bool Http::init(const std::string& version, const std::string &scheme, const std::string& host, int port)
{
	if (scheme == "http")
	{
		m_scheme = "http://";
	}
	else if (scheme == "https")
	{
		m_scheme = "https://";
	}
	else
	{
		return false;
	}
	m_host = host;
	m_port = port;
	if (!parseVersion(version))
	{
		return false;
	}
	return true;
}

std::string Http::formRequest(Method method, const std::string& uri, const std::string& body)
{
	std::string request{};
	if (!parseUri(uri))
	{
		ns_Util::Logger::LOG_ERROR("Failed to parse URI.\n");
		return request;
	}
	
	bool bSuccess = true;
	switch (method)
	{
		case nsNW::Method::HTTP_GET:
			bSuccess = http_GET(request);
			break;
		case nsNW::Method::HTTP_HEAD:
			bSuccess = http_HEAD(request);
			break;
		case nsNW::Method::HTTP_POST:
			bSuccess = http_POST(request);
			break;
		case nsNW::Method::HTTP_PUT:
			bSuccess = http_PUT(request);
			break;
		case nsNW::Method::HTTP_DELETE:
			bSuccess = http_DELETE(request);
			break;
		case nsNW::Method::HTTP_CONNECT:
			bSuccess = http_CONNECT(request);
			break;
		case nsNW::Method::HTTP_OPTION:
			bSuccess = http_OPTION(request);
			break;
		case nsNW::Method::HTTP_TRACE:
			bSuccess = http_TRACE(request);
			break;
		default:
			break;
	}

	if (!bSuccess)
	{
		ns_Util::Logger::LOG_ERROR("HTTP ", to_string(method), " failed.\n");
		return {};
	}
	return request + body;
}

bool Http::http_GET(std::string& request)
{
	// http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
	request = "GET ";
	request += m_uriPath + ' ' + m_version + "\r\n";
	request += "Host: " + m_host + ':' + std::to_string(m_port) + "\r\n";

	return true;
}

bool Http::http_HEAD(std::string& request)
{
	(void)request;
	return true;
}

bool Http::http_POST(std::string& request)
{
	(void)request;
	return true;
}

bool Http::http_PUT(std::string& request)
{
	(void)request;
	return true;
}

bool Http::http_DELETE(std::string& request)
{
	(void)request;
	return true;
}

bool Http::http_CONNECT(std::string& request)
{
	(void)request;
	return true;
}

bool Http::http_OPTION(std::string& request)
{
	(void)request;
	return true;
}

bool Http::http_TRACE(std::string& request)
{
	(void)request;
	return true;
}

bool Http::parseVersion(const std::string& version)
{
	// HTTP-version  = "HTTP" "/" 1*DIGIT "." 1*DIGIT
	if (version.find("HTTP/") != 0)
	{
		return false;
	}
	m_version = "HTTP/";
	int i = static_cast<int>(m_version.size());
	while (i < version.size())
	{
		if (std::isdigit(version[i]))
		{
			m_version.push_back(version[i++]);
		}
		else if (version[i] == '.')
		{
			m_version.push_back(version[i++]);
			break;
		}
		else
		{
			return false;
		}
	}

	while (i < version.size())
	{
		if (std::isdigit(version[i]))
		{
			m_version.push_back(version[i]);
			++i;
		}
		else
		{
			return false;
		}
	}
	return true;
}

bool Http::parseUri(const std::string& uri)
{
	// http_URL = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
	size_t pos = uri.find('?');
	if (pos != std::string::npos)
	{
		m_uriPath = uri.substr(0, pos);
		return parseParams(uri.substr(pos + 1));
	}
	m_uriPath = uri;
	return true;
}

bool Http::parseParams(const std::string& params)
{
	m_queries.clear();

	size_t offset = 0;
	size_t pos = params.find('&', offset);

	while (pos != std::string::npos)
	{
		std::string str = params.substr(offset, pos - offset);
		
		m_queries.push_back({});
		m_queries.back().first = str.substr(0, str.find('='));
		m_queries.back().second = str.substr(str.find('=') + 1);

		offset = pos;
		pos = params.find('&', offset);
	}
	return true;
}
}
#endif //#ifndef __HTTP_H__