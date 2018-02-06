@load base/frameworks/notice
@load base/protocols/http

export {
    redef enum Notice::Type += {
        UserAgent::Abnormal,
    };
}


# ref: https://www.bro.org/sphinx/scripts/base/protocols/http/main.bro.html#type-HTTP::Info
#event HTTP::log_http(rec: HTTP::Info) {
event http_header(c: connection, is_orig: bool, name: string, value: string) {

# ref: https://stackoverflow.com/questions/20569000/regex-for-http-user-agent
# online test cases： https://regexr.com/3kam2
    local ua_pattern = /.+?[\/\s][\d.]+/;

# ref: https://www.sans.org/reading-room/whitepapers/hackers/user-agent-field-analyzing-detecting-abnormal-malicious-organization-33874
#    print(fmt("user-agent: %s", rec$user_agent));

    #print(fmt("header-name: %s", name));
    if ( name != "USER-AGENT" ) {
        return;
    }

    if ( !(ua_pattern in c$http$user_agent) ) {
        NOTICE([$note=UserAgent::Abnormal, $conn=c, $msg=fmt("Abnormal UserAgent detected! %s", value)]);
    }

}


