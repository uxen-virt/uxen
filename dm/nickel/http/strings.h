/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HTTP_STRINGS_H_
#define _HTTP_STRINGS_H_


#define STRLEN(a)   (sizeof(a)-1)

#define IE7_cred_key "abe2869f-9b47-4cd9-a358-c22904dba7f7"
#define S_HTTP11 "HTTP/1.1"
#define S_CONNECT "CONNECT"
#define S_HEAD "HEAD"
#define S_END "\r\n"
#define S_COLON ":"
#define S_HOST "Host"
#define S_SPACE " "
#define S_PROXY_CONNECTION "Proxy-Connection"
#define S_CONNECTION "Connection"
#define S_KEEPALIVE "Keep-Alive"
#define S_SCHEME_HTTP "http://"
#define S_SCHEME_FTP "ftp://"
#define S_CLOSE "close"
#define S_USER_AGENT "User-Agent"
#define S_PROXY_CHALLENGE_HEADER "proxy-authenticate"
#define S_PROXY_AUTH_HEADER "Proxy-Authorization"
#define S_HTTP_VERSION_TEMPLATE "HTTP/%u.%u"
#define S_HEADER_CONTENT_LENGTH "content-length"
#define S_REDIRECT_WITH_URL "HTTP/1.1 302 Found\r\nLocation: http://%s:%s%s\r\n\r\n"
#define S_REDIRECT_WITHOUT_URL "HTTP/1.1 302 Found\r\nLocation: http://%s:%s\r\n\r\n"
#define S_WWW_AUTHENTICATE "WWW-Authenticate"
#define S_PROXY_SUPPORT "Proxy-support"
#define S_PS_SESSION_BASED_AUTH "Session-Based-Authentication"
#define S_HDR_PS_SESSION_BASED_AUTH "Proxy-support: Session-Based-Authentication\r\n"

#endif
