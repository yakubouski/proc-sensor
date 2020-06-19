#include "cssh.h"
#include <stdexcept>
#include <cstring>


using namespace ci;

ssize_t cssh::execute(const std::string& cmd, const std::function<void(const std::string&)>& callback) {
    ssh_channel channel;
    int rc;
    char buffer[65536];
    int nbytes;
    
    std::string result;

    channel = ssh_channel_new(hSession);
    if (channel == NULL)
        return SSH_ERROR;
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }
    rc = ssh_channel_request_exec(channel, cmd.c_str());
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
        result.append(buffer, buffer + nbytes);
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    callback(result);

    return SSH_OK;
}

ssize_t cssh::authorize_password(const std::string& user, const std::string& pwd) {
    // Authenticate ourselves
    //password = getpass("Password: ");
    
    if (auto rc = ssh_userauth_password(hSession, user.empty() ? nullptr : user.c_str(), pwd.c_str()); rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(hSession));
        disconnect();
        return -1;
    }
    return 0;
}

ssize_t cssh::authorize_identity_key(const std::string& user, const std::string& identity_key, const std::string& pass) {
    ssh_key key;
    if (auto rc = ssh_pki_import_privkey_file(identity_key.c_str(), pass.empty() ? nullptr : pass.c_str(),nullptr,nullptr, &key); rc != 0) {
        fprintf(stderr, "Error authenticating with identity-key: %s\n", ssh_get_error(hSession));
        disconnect();
        return -1;
    }
    if (auto rc = ssh_userauth_publickey(hSession, user.empty() ? nullptr : user.c_str(), key); rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with identity-key: %s\n", ssh_get_error(hSession));
        disconnect();
        return -1;
    }
    ssh_key_free(key);
    return 0;
}

ssize_t cssh::verify(bool auto_trust) {
    unsigned char* hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char* hexa;
    char* p;
    int cmp;
    int rc;

    rc = ssh_get_server_publickey(hSession, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
        SSH_PUBLICKEY_HASH_SHA1,
        &hash,
        &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    ;
    switch (auto state = ssh_session_is_known_server(hSession);state) {
    case SSH_KNOWN_HOSTS_OK:
        /* OK */

        break;
    case SSH_KNOWN_HOSTS_CHANGED:
        fprintf(stderr, "Host key for server changed: it is now:\n");
        ssh_print_hexa("Public key hash", hash, hlen);
        fprintf(stderr, "For security reasons, connection will be stopped\n");
        ssh_clean_pubkey_hash(&hash);

        return -1;
    case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other"
            "type of key exists.\n");
        fprintf(stderr, "An attacker might change the default server key to"
            "confuse your client into thinking the key does not exist\n");
        ssh_clean_pubkey_hash(&hash);

        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        fprintf(stderr, "Could not find known host file.\n");
        fprintf(stderr, "If you accept the host key here, the file will be"
            "automatically created.\n");

        /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */

    case SSH_KNOWN_HOSTS_UNKNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa);
        ssh_string_free_char(hexa);
        ssh_clean_pubkey_hash(&hash);
        if (auto_trust) {
            rc = ssh_session_update_known_hosts(hSession);
            if (rc < 0) {
                fprintf(stderr, "Error %s\n", strerror(errno));
                return -1;
            }
            return 0;
        }
        else {
            return -1;
        }
        break;
    case SSH_KNOWN_HOSTS_ERROR:
        fprintf(stderr, "Error %s", ssh_get_error(hSession));
        ssh_clean_pubkey_hash(&hash);
        return -1;
    }

    ssh_clean_pubkey_hash(&hash);
    return 0;
}

ssize_t cssh::connect(const std::string& host, const std::string& port) {
    disconnect();

    int nVerbosity = SSH_LOG_PROTOCOL;
    int nPort = port.empty() ? 22 : std::stol(port);

    if (host.empty()) { return -EINVAL; }

    if (hSession = ssh_new(); hSession == nullptr) { return -ENOMEM; }

    ssh_options_set(hSession, SSH_OPTIONS_HOST, host.c_str());
    ssh_options_set(hSession, SSH_OPTIONS_LOG_VERBOSITY, &nVerbosity);
    ssh_options_set(hSession, SSH_OPTIONS_PORT, &nPort);

    ;
    if (auto rc = ssh_connect(hSession); rc != SSH_OK)
    {
        fprintf(stdout, "[ cssh::connect ] %s\n", ssh_get_error(hSession));
        ssh_free(hSession);
        hSession = nullptr;
        return -ECONNRESET;
    }
    return 0;
}

ssize_t cssh::disconnect() {
    if (hSession) {
        ssh_disconnect(hSession);
        ssh_free(hSession);
        hSession = nullptr;
        return 0;
    }
    return -EBADF;
}

cssh::cssh() { ; }

cssh::~cssh() {
    disconnect();
}