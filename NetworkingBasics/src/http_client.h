#include "http.h"
#include "client.h"

namespace nsNW
{
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
	bool				successful{ true };
};

class HttpClient : public Http, public Client
{
public:
	Response http_GET(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_HEAD(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_POST(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_PUT(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_DELETE(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_CONNECT(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_OPTION(const std::string& uri, const bodyType& bodyKeyValue);
	Response http_TRACE(const std::string& uri, const bodyType& bodyKeyValue);
};

Response HttpClient::http_GET(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_HEAD(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_POST(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_PUT(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_DELETE(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_CONNECT(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_OPTION(const std::string& uri, const bodyType& bodyKeyValue)
{

}

Response HttpClient::http_TRACE(const std::string& uri, const bodyType& bodyKeyValue)
{

}
}