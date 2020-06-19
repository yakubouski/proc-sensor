#include <cstdio>
#include "ci/cssh.h"
#include "ci/cconsole.h"

int main()
{
    ci::cconsole::run();
    /*
    ci::cssh ssh;

    //if (ssh.connect("localhost") == 0) {
    if (ssh.connect("testnsms1.navekscreen.video","20022") == 0) {
        if (ssh.verify() == 0) {
            //if (ssh.authorize_password("irokez","q1w2e3r4") == 0) {
            if (ssh.authorize_identity_key("root", "/home/irokez/Workspace/Credentials/Auth-keys/a.yakubouski.naveksoft.com.private") == 0) {
                ssh.execute("ls -la", [](const std::string& result) {
                    printf("%s", result.c_str());
                });
            }
        }
    }
    */
    return 0;
}