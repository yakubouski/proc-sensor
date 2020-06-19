#pragma once
#include <cinttypes>
#include <string>
#include <functional>

extern "C" {
#include <libssh/libssh.h>
}

namespace ci {
	class cssh {
	public:
		cssh();
		~cssh();
		ssize_t connect(const std::string& host, const std::string& port = "22");
		ssize_t verify(bool auto_trust = true);
		ssize_t disconnect();

		ssize_t authorize_password(const std::string& user, const std::string& pwd);
		ssize_t authorize_identity_key(const std::string& user, const std::string& identity_key, const std::string& pass = {});

		ssize_t execute(const std::string& cmd, const std::function<void(const std::string&)>& callback);

	private:
		ssh_session hSession{ nullptr };
	};
}