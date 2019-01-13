create or replace package body pkg_aws_s3_api as

    /*
            VARIABLES
            */
    g_acess_key_id varchar2(1000) := null;
    g_secrec_acess_key varchar2(1000) := null;
    g_wallet_path varchar2(1000) := null;
    g_wallet_password varchar2(1000) := null;
    /*
            Region AWS - Amazon Simple Storage Service (Amazon S3)
            https://docs.aws.amazon.com/pt_br/general/latest/gr/rande.html */
    g_region varchar2(40) := null;
    g_host_idx pls_integer;
    g_auth_idx pls_integer;

    /*
          CONSTANTS AUTH
            */
    G_ACESS_KEY_ID_DEFAULT constant varchar2(20) := 'AKIEXAMPLE12345678A'; /* Access Key ID DEFAULT */
    G_SECREC_ACESS_KEY_DEFAULT constant varchar2(40) := 'abc123abc123abc213abc123ABC123ABC123ABC1'; /* Secret access Key DEFAULT */
    G_WALLET_PATH_DEFAULT constant varchar2(1000) := 'file:/opt/oracle/wallets/amazon_aws'; /* Wallet DEFAUL */
    G_WALLET_PASSWORD_DEFAULT constant varchar2(1000) := 'password'; /* Wallet Password  DEFAULT*/
    G_REGION_DEFAULT constant varchar2(40) := 'sa-east-1'; /* Region S3 DEFAULT */
    G_CONTENT_TYPE_DEFAULT constant varchar2(24) := 'application/octet-stream';

    /*
            CONSTANTS API
            */
    G_ALGORITHM constant varchar2(16) := 'AWS4-HMAC-SHA256';
    G_DATE_FORMAT_ISO8601 constant varchar2(22) := 'YYYYMMDD"T"HH24MISS"Z"';
    G_SERVICE constant varchar2(5) := 's3';
    G_TERMINATION_STRING constant varchar2(12) := 'aws4_request';
    G_NULL_HASH constant varchar2(100) := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    LF constant varchar2(1) := chr(10);
    CRLF constant varchar2(2) := chr(13) || chr(10);
    /*
            Http request method
            */
    G_METHOD_PUT constant varchar2(3) := 'PUT';
    G_METHOD_POST constant varchar2(4) := 'POST';
    G_METHOD_GET constant varchar2(3) := 'GET';
    G_METHOD_DELETE constant varchar2(6) := 'DELETE';

    procedure init(
        p_acess_key_id varchar2 default null,
        p_secrec_acess_key varchar2 default null,
        p_wallet_path varchar2 default null,
        p_wallet_password varchar2 default null,
        p_region varchar2 default null) is
    begin
    g_acess_key_id      := nvl(p_acess_key_id, G_ACESS_KEY_ID_DEFAULT);
    g_secrec_acess_key  := nvl(p_secrec_acess_key, G_SECREC_ACESS_KEY_DEFAULT);
    g_wallet_path       := nvl(p_wallet_path, G_WALLET_PATH_DEFAULT);
    g_wallet_password   := nvl(p_wallet_password, G_WALLET_PASSWORD_DEFAULT);
    g_region            := nvl(p_region, G_REGION_DEFAULT);
    end;

    procedure set_acess_key_id(
        p_acess_key_id varchar2) is
    begin
    g_acess_key_id := p_acess_key_id;
    end set_acess_key_id;

    procedure set_secrec_acess_key(
        p_secrec_acess_key varchar2) is
    begin
    g_secrec_acess_key := p_secrec_acess_key;
    end set_secrec_acess_key;

    procedure set_wallet_path(
        p_wallet_path varchar2) is
    begin
    g_wallet_path := p_wallet_path;
    end set_wallet_path;

    procedure set_wallet_password(
        p_wallet_password varchar2) is
    begin
    g_wallet_password := p_wallet_password;
    end set_wallet_password;

    procedure set_region(
        p_region varchar2) is
    begin
    g_region := p_region;
    end set_region;

    procedure add_header(
        p_headers in out nocopy t_headers_list,
        p_header_name varchar2,
        p_header_value varchar2 default null) is

    l_idx pls_integer;
    begin
/*
            Common Request Headers
            -- https://docs.aws.amazon.com/pt_br/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
            UTL_HTTP.SET_HEADER(req, 'Authorization', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Length', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Type', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-MD5', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Date', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Expect', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Host', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-content-sha256', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-date', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-security-token', 'Mozilla/4.0');
*/
    p_headers(0).name := 'offset';
    p_headers(0).value := nvl(p_headers(0).value,p_headers.count());
    l_idx := p_headers.count() - p_headers(0).value + 1;

    if  (lower(p_header_name) = 'host') then
        p_headers(-1).name := 'host_idx';
        p_headers(-1).value := l_idx;
        p_headers(0).value := p_headers(0).value + 1;
    end if;

    if  (lower(p_header_name) = 'authorization') then
        p_headers(-2).name := 'authorization_idx';
        p_headers(-2).value := l_idx;
        p_headers(0).value := p_headers(0).value + 1;
    end if;

    p_headers(l_idx).name := p_header_name;
    p_headers(l_idx).value := p_header_value;

    end add_header;

    /* https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html */
    function uri_encode(
        p_char_sequence in varchar2,
        p_encode_slash in pls_integer default 1)
        return varchar2 is
    /*
            p_encode_slash
                0 - false
                1 - true
            */
    l_result varchar2(4000);
    l_ch varchar2(1);
    begin

    l_result := null;
    if (p_char_sequence is not null) then
        for i in 1..length(p_char_sequence) loop
            l_ch := substr(p_char_sequence,i,1);
            if  ((l_ch between 'A' and 'Z') or
                (l_ch between 'a' and 'z') or
                (l_ch between '0' and '9') or
                (l_ch = '_') or
                (l_ch = '-') or
                (l_ch = '~') or
                (l_ch = '.')) then
                l_result := l_result || l_ch;
            elsif (l_ch = '/') then
                if (p_encode_slash = 1) then
                    l_result := l_result || '%2F';
                else
                    l_result := l_result || l_ch;
                end if;
            else
                l_result := l_result||'%'|| upper(rawtohex(utl_i18n.string_to_raw(l_ch,'AL32UTF8')));
            end if;
        end loop;
    end if;

    return l_result;
    end uri_encode;

    function format_iso_8601(
        p_date in date)
        return varchar2 is
    l_timestamp   timestamp;
    l_iso_8601    varchar2(60);
    begin
    return to_char(sys_extract_utc(cast(p_date as timestamp with time zone)), G_DATE_FORMAT_ISO8601);
    end format_iso_8601;

    function base64_md5_hash(
        p_src in blob)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    l_base64 raw(4000);
    begin

    l_hash          := dbms_crypto.hash(
                            src => p_src,
                            typ => dbms_crypto.hash_md5
                            );
    l_base64:= utl_encode.base64_encode(l_hash);
    l_return:= utl_raw.cast_to_varchar2(l_base64);

    return l_return;
    end base64_md5_hash;

    function base64_md5_hash(
        p_src in varchar2)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    l_base64 raw(4000);
    l_src raw(4000);
    begin

    l_src := utl_i18n.string_to_raw(p_src,'AL32UTF8');
    l_hash := dbms_crypto.hash(
                src => l_src,
                typ => dbms_crypto.hash_md5);
    l_base64:= utl_encode.base64_encode(l_hash);
    l_return:= utl_raw.cast_to_varchar2(l_base64);

    return l_return;
    end base64_md5_hash;

    function sha256_hash(
        p_src in varchar2)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    l_src raw(2000);
    begin

    l_src := utl_i18n.string_to_raw(p_src,'AL32UTF8');
    l_hash := dbms_crypto.hash(
                src => l_src,
                typ => dbms_crypto.hash_sh256);

    l_return := lower(rawtohex(l_hash));
    return l_return;
    end sha256_hash;

    function sha256_hash(
        p_src in blob)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    l_src raw(2000);
    begin
    l_hash := dbms_crypto.hash(
                src => p_src,
                typ => dbms_crypto.hash_sh256);

    l_return := lower(rawtohex(l_hash));
    return l_return;
    end sha256_hash;

    function hmac_sha256(
        p_key_raw in raw,
        p_src_varchar2 in varchar2)
        return raw is
    l_return raw(2000);
    l_src_varchar2 varchar2(2000);
    begin
    l_src_varchar2 := utl_i18n.string_to_raw(p_src_varchar2,'AL32UTF8');
    l_return := dbms_crypto.mac (
                    src => l_src_varchar2,
                    typ => dbms_crypto.hmac_sh256,
                    key => p_key_raw);
    return l_return;
    end hmac_sha256;

    function hmac_sha256(
        p_key_varchar2 in varchar2,
        p_src_varchar2 in varchar2)
        return raw is
    l_return raw(2000);
    l_key_varchar2 varchar2(2000);
    begin
    l_key_varchar2 := utl_i18n.string_to_raw(p_key_varchar2,'AL32UTF8');
    l_return := hmac_sha256(
                    p_key_raw => l_key_varchar2,
                    p_src_varchar2 => p_src_varchar2);
    return l_return;
    end hmac_sha256;

    /*
            https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
            */
    function canonical_request(
        p_httpmethod in varchar2,
        p_bucketname in varchar2,
        p_uri in varchar2,
        p_querystring in t_query_string_list,
        p_headers in out nocopy t_headers_list,
        p_hashed_payload in varchar2,
        p_date in date,
        p_url out varchar2)
        return varchar2 is
    l_return varchar2(4000);
    l_canonical_uri varchar2(200);
    l_canonical_query_string varchar2(1000);
    l_canonical_headers varchar2(1000);
    l_signed_headers varchar2(1000);
    l_hashed_payload varchar2(4000);
    l_host varchar2(4000);
    begin

    /*
            CanonicalRequest =
            HTTPRequestMethod + '\n' +
            CanonicalURI + '\n' +
            CanonicalQueryString + '\n' +
            CanonicalHeaders + '\n' +
            SignedHeaders + '\n' +
            HexEncode(Hash(RequestPayload))
            */
  -- HTTPMethod is one of the HTTP methods, for example GET, PUT, HEAD, and DELETE.
  -- p_httpmethod

    /*
            CanonicalURI is the URI-encoded version of the absolute path component of the URI
            everything starting with the "/" that follows the domain name and up to the end of the string or
            to the question mark character ('?') if you have query string parameters.
            */
    l_canonical_uri := nvl(trim(p_uri),'/');
    if  substr(p_uri,1,1) = '/' then
        l_canonical_uri := uri_encode(p_uri,0);
    else
        l_canonical_uri := uri_encode('/'||p_uri,0);
    end if;

    if  (p_bucketname is not null) then
        if  (g_region = 'us-east-1') then
            l_host := p_bucketname||'.s3.amazonaws.com';
            p_url := 'https://'||p_bucketname||'.s3.amazonaws.com'||l_canonical_uri;
            -- l_host := '.s3.amazonaws.com/'||p_bucketname;
            -- p_url := 'https://'||'s3.amazonaws.com/'||p_bucketname||'/'||l_canonical_uri;
        else
            l_host := p_bucketname||'.s3.'||g_region||'.amazonaws.com';
            p_url := 'https://'||p_bucketname||'.s3.'||g_region||'.amazonaws.com'||l_canonical_uri;
        end if;
    else
        l_host := 'host:s3.amazonaws.com';
        p_url := 'https://s3.amazonaws.com';
    end if;
    p_headers(p_headers(-1).value).value := l_host;

    /*
            CanonicalQueryString specifies the URI-encoded query string parameters.
            You URI-encode name and values individually.
            You must also sort the parameters in the canonical query string alphabetically by key name.
            The sorting occurs after encoding.
            If the URI does not include a '?',
            there is no query string in the request,
            and you set the canonical query string to an empty string ("")
            UriEncode("marker")+"="+UriEncode("someMarker")+"&"+
            UriEncode("max-keys")+"="+UriEncode("20") + "&" +
            */
    l_canonical_query_string := null;
    if  (p_querystring is not null) and
        (p_querystring.count > 0) then
        p_url := p_url||'?';
        for i in 1 .. p_querystring.count loop
            l_canonical_query_string := l_canonical_query_string ||
            uri_encode(p_querystring(i).name)||'='||uri_encode(p_querystring(i).value)||'&';
            if (p_querystring(i).value is not null) then
                p_url := p_url||uri_encode(p_querystring(i).name)||'='||uri_encode(p_querystring(i).value)||'&';
            else
                p_url := p_url||uri_encode(p_querystring(i).name)||'&';
            end if;
        end loop;
        l_canonical_query_string := substr(l_canonical_query_string,1,length(l_canonical_query_string)-1);
        p_url := substr(p_url,1,length(p_url)-1);
    end if;

    /*
            CanonicalHeaders is a list of request headers with their values.
            Individual header name and value pairs are separated by the newline character ("\n").
            Header names must be in lowercase.
            You must sort the header names alphabetically to construct the string
            Lowercase(<HeaderName1>)+":"+Trim(<value>)+"\n"
            Lowercase(<HeaderName2>)+":"+Trim(<value>)+"\n"

            The CanonicalHeaders list must include the following:

            HTTP host header.

            If the Content-Type header is present in the request, you must add it to the CanonicalHeaders list.

            Any x-amz-* headers that you plan to include in your request must also be added.
            For example, if you are using temporary security credentials,
            you need to include x-amz-security-token in your request

            The x-amz-content-sha256 header is required for all AWS Signature Version 4 requests.
            It provides a hash of the request payload. If there is no payload,
            you must provide the hash of an empty string.

            ******

            SignedHeaders is an alphabetically sorted, semicolon-separated list of lowercase request header names.
            The request headers in the list are the same headers that you included in the CanonicalHeaders string.
            */
    l_canonical_headers := null;
    l_signed_headers := '';
    if  (p_headers is not null) and
        ((p_headers.count - (p_headers(0).value)) > 0) then
        for i in 1 .. (p_headers.count - to_number(p_headers(0).value)) loop
            if  ((lower(p_headers(i).name) in ('host',/*'content-type',*/'range','content-md5')) or
                (substr(lower(p_headers(i).name),1,6) = 'x-amz-')) then
                l_canonical_headers := l_canonical_headers ||
                lower(p_headers(i).name)||':'||trim(p_headers(i).value)||LF;

                l_signed_headers := l_signed_headers ||
                lower(p_headers(i).name)||';';
            end if;
        end loop;
        l_signed_headers := substr(l_signed_headers,1,length(l_signed_headers)-1);
    end if;

    /*
            hashed_payload is the hexadecimal value of the SHA256 hash of the request payload.
            */
    l_hashed_payload := p_hashed_payload;

    l_return :=
        p_httpmethod||LF||
        l_canonical_uri||LF||
        l_canonical_query_string||LF||
        l_canonical_headers||LF||
        l_signed_headers||LF||
        l_hashed_payload;

    return l_return;
    end canonical_request;

    /*
            https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
            */
    function string_to_sign(
        p_canonical_request in varchar2,
        p_date in date)
        return varchar2 is
    l_return varchar2(1000);
    l_hashed_request varchar2(1000);
    begin

    l_hashed_request := sha256_hash(p_canonical_request);

    l_return := G_ALGORITHM||LF||
    format_iso_8601(p_date)||LF||
    to_char(p_date, 'yyyymmdd')||'/'||g_region||'/'||G_SERVICE||'/'||G_TERMINATION_STRING||LF||
    l_hashed_request;

    return l_return;
    end string_to_sign;

    /*
            https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
            */
    function signature(
        p_string_to_sign in varchar2,
        p_date in date)
        return varchar2 is
    l_return varchar2(2000);
    l_raw_return raw(2000);
    l_datekey raw(2000);
    l_dateregionkey raw(2000);
    l_dateregionservicekey raw(2000);
    l_signingkey raw(2000);
    begin
    /*
            DateKey              = HMAC-SHA256("AWS4"+"<SecretAccessKey>", "<YYYYMMDD>")
            DateRegionKey        = HMAC-SHA256(<DateKey>, "<aws-region>")
            DateRegionServiceKey = HMAC-SHA256(<DateRegionKey>, "<aws-service>")
            SigningKey           = HMAC-SHA256(<DateRegionServiceKey>, "aws4_request")
            */
    l_datekey               := hmac_sha256(p_key_varchar2 =>  'AWS4'||g_secrec_acess_key, p_src_varchar2 => to_char(p_date, 'yyyymmdd'));
    l_dateregionkey         := hmac_sha256(p_key_raw => l_datekey, p_src_varchar2 => g_region);
    l_dateregionserviceKey  := hmac_sha256(p_key_raw => l_dateregionkey, p_src_varchar2 => G_SERVICE);
    l_signingkey            := hmac_sha256(p_key_raw => l_dateregionserviceKey, p_src_varchar2 => G_TERMINATION_STRING);

    l_raw_return            := hmac_sha256(p_key_raw => l_signingkey, p_src_varchar2 => p_string_to_sign);
    l_return                := lower(rawtohex(l_raw_return));

    return l_return;
    end signature;

    procedure authorization_string(
        p_httpmethod in varchar2,
        p_bucketname in varchar2,
        p_uri in varchar2,
        p_querystring in t_query_string_list,
        p_headers in out nocopy t_headers_list,
        p_hashed_payload in varchar2,
        p_date in date,
        p_url out varchar2) is
    l_canonical_request varchar2(1000);
    l_string_to_sign varchar2(1000);
    l_signature varchar2(200);
    l_authorization_string varchar2(4000);
    l_signed_headers varchar2(1000);
    begin
    l_canonical_request := canonical_request(
                            p_httpmethod => p_httpmethod,
                            p_bucketname => p_bucketname,
                            p_uri => p_uri,
                            p_querystring => p_querystring,
                            p_headers => p_headers,
                            p_hashed_payload => p_hashed_payload,
                            p_date => p_date,
                            p_url => p_url);

    l_string_to_sign := string_to_sign(
                            p_canonical_request => l_canonical_request,
                            p_date => p_date);

    l_signature := signature(
                        p_string_to_sign =>l_string_to_sign,
                        p_date => p_date);

    l_signed_headers := '';
    if  (p_headers is not null) and
        ((p_headers.count - to_number(p_headers(0).value)) > 0) then
        for i in 1 .. (p_headers.count - to_number(p_headers(0).value)) loop
            if  ((lower(p_headers(i).name) in ('host',/*'content-type',*/'range','content-md5')) or
                (substr(lower(p_headers(i).name),1,6) = 'x-amz-')) then
                l_signed_headers := l_signed_headers ||
                lower(p_headers(i).name)||';';
            end if;
        end loop;
        l_signed_headers := substr(l_signed_headers,1,length(l_signed_headers)-1);
    end if;
    l_authorization_string := G_ALGORITHM||
                            ' Credential='||g_acess_key_id||'/'||to_char(p_date,'yyyymmdd')||'/'||g_region||'/s3/aws4_request,'||
                            ' SignedHeaders='||l_signed_headers||','||
                            ' Signature='||l_signature ;
    p_headers(p_headers(-2).value).value := l_authorization_string;

    end authorization_string;

    /*
            https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingRESTError.html
            */
    procedure raise_error_response(
        p_response in out nocopy utl_http.resp,
        p_clob in clob) is
    l_xml xmltype;
    l_error varchar2(4000) ;
    l_name varchar2(256);
    l_value varchar2(1024);
    begin
    l_error := null;
    if  (p_clob is not null) and
        (length(p_clob) > 0) then
        begin
        l_xml := xmltype(p_clob);
        if  l_xml.existsnode('/Error') = 1 then
            for i in 1..utl_http.get_header_count(p_response) loop
                utl_http.get_header(p_response, i, l_name, l_value);
                l_error := substr(l_error ||CRLF|| (l_name || ': ' || l_value),1,4000);
            end loop;
            l_error := substr(
                        'HTTP STATUS = ' ||CRLF||
                        'http_version: ' || p_response.http_version ||CRLF||
                        'status_code: ' || p_response.status_code ||CRLF||
                        'reason_phrase: ' || p_response.reason_phrase ||CRLF||
                        CRLF||
                        'HEADERS = ' ||
                        l_error||CRLF||
                        CRLF||
                        'ERROR = ' ||CRLF||
                        'code: ' || l_xml.extract('/Error/Code/text()').getstringval() ||CRLF||
                        'message' || l_xml.extract('/Error/Message/text()').getstringval()||CRLF||
                        CRLF||
                        'BODY = ' ||CRLF||
                        dbms_lob.substr( p_clob, 4000, 1 )
                        ,1,4000);
        end if;
       -- exception
       -- when others then

        end;

    end if;
    if (l_error is not null) then
        Raise_application_error(-20011,l_error);
    end if;
    end raise_error_response;

    procedure make_request(
        p_url in varchar2,
        p_http_method in varchar2,
        p_headers in t_headers_list,
        p_request in out nocopy utl_http.req,
        p_response in out nocopy utl_http.resp,
        p_blob in blob default null,
        p_clob in clob default null/*,
        p_close_response in number default 1*/) is

    l_buffer_raw raw(32767);
    l_buffer_varchar2 varchar2(32767);

    l_length number(10);
    l_offset number(15) := 1;
    l_value varchar2(1024);
    l_amount number(15) := 32767;
    l_clob clob;

    begin
    begin
    utl_http.set_wallet(g_wallet_path, g_wallet_password);

    p_request := utl_http.begin_request(url => p_url, method => p_http_method, http_version => utl_http.http_version_1_1);

    if  (p_headers is not null) and
        ((p_headers.count - to_number(p_headers(0).value)) > 0) then
        for i in 1 .. (p_headers.count - to_number(p_headers(0).value)) loop
            if  lower(p_headers(i).name) <> 'host' then
                utl_http.set_header(p_request, p_headers(i).name, p_headers(i).value);
            end if;
        end loop;
    end if;

    if (p_blob is not null) then
        l_length := dbms_lob.getlength(p_blob);
        while l_offset < l_length loop
            dbms_lob.read(p_blob, l_amount, l_offset, l_buffer_raw);
            utl_http.write_raw(p_request, l_buffer_raw);
            l_offset := l_offset + l_amount;
        end loop;
    elsif (p_clob is not null) then
        l_length := dbms_lob.getlength(p_clob);
        while l_offset < l_length loop
            dbms_lob.read(p_clob, l_amount, l_offset, l_buffer_varchar2);
            utl_http.write_text(p_request, l_buffer_varchar2);
            l_offset := l_offset + l_amount;
        end loop;
    end if;

    p_response := utl_http.get_response(p_request);

    exception
    when others then
        utl_http.end_response(p_response);
        raise;
    end;

    end make_request;

    function get_clob_from_response(
            p_response in out nocopy utl_http.resp,
            p_close_response in pls_integer default 0)
    return clob is
    /*
            p_close_response
            0 - false
            1 - true
            */

    l_clob clob;
    l_data varchar2(32767);
    begin

    begin
    dbms_lob.createtemporary(l_clob, false);
    -- dbms_lob.open (l_clob, dbms_lob.lob_readwrite);
    loop
        utl_http.read_text(p_response, l_data, 32767);
        dbms_lob.writeappend(l_clob, length(l_data), l_data);
    end loop;
    exception
    when utl_http.end_of_body then
        if (p_close_response = 1) then
            utl_http.end_response(p_response);
        end if;
    end;

    return l_clob;

    end get_clob_from_response;

    function get_blob_from_response(
        p_response in out nocopy utl_http.resp,
        p_close_response in pls_integer default 0)
    return blob is
    /*
            p_close_response
            0 - false
            1 - true
            */

    l_blob blob;
    l_data raw(32767);
    begin

    begin
    dbms_lob.createtemporary(l_blob, false);
    -- dbms_lob.open (l_clob, dbms_lob.lob_readwrite);
    loop
        utl_http.read_raw(p_response, l_data, 32767);
        dbms_lob.writeappend(l_blob, dbms_lob.getlength(l_data), l_data);
    end loop;
    exception
    when utl_http.end_of_body then
        if (p_close_response = 1) then
            utl_http.end_response(p_response);
        end if;
    end;

    return l_blob;

    end get_blob_from_response;

    procedure put_object(
        p_bucketname in varchar2,
        p_objectname in varchar2,
        p_blob in blob,
        p_storage_class in varchar2 default null,
        p_content_type in varchar2 default null,
        p_tags in varchar2 default null) as

    l_req utl_http.req;
    l_resp utl_http.resp;

    l_clob clob;
    l_date date;
    l_url varchar2(4000);
    l_method varchar2(6);
    l_headers t_headers_list;
    l_content_length number(20);
    l_base64_md5_hash varchar2(1000);
    l_hashed_payload varchar2(4000);
    l_query_string t_query_string_list;
    begin

    l_method := G_METHOD_PUT;
    l_hashed_payload := sha256_hash(p_blob);
    l_content_length := dbms_lob.getlength(p_blob);
    l_base64_md5_hash := base64_md5_hash(p_src => p_blob);
    -- l_query_string.delete;
    l_date := sysdate;

    /*
            Common Request Headers
            https://docs.aws.amazon.com/pt_br/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
            UTL_HTTP.SET_HEADER(req, 'Authorization', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Length', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Type', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-MD5', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Date', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Expect', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Host', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-content-sha256', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-date', 'Mozilla/4.0');
            x-amz-storage-class: REDUCED_REDUNDANCY
            UTL_HTTP.SET_HEADER(req, 'x-amz-security-token', 'Mozilla/4.0');
            */
    add_header(p_headers => l_headers, p_header_name => 'Authorization');
    add_header(p_headers => l_headers, p_header_name => 'Content-Length', p_header_value => l_content_length);
    add_header(p_headers => l_headers, p_header_name => 'Content-Type', p_header_value => nvl(p_content_type, G_CONTENT_TYPE_DEFAULT));
    add_header(p_headers => l_headers, p_header_name => 'Content-MD5', p_header_value => l_base64_md5_hash);
    add_header(p_headers => l_headers, p_header_name => 'Host');
    add_header(p_headers => l_headers, p_header_name => 'x-amz-content-sha256', p_header_value => l_hashed_payload);
    add_header(p_headers => l_headers, p_header_name => 'x-amz-date', p_header_value => format_iso_8601(l_date));

    add_header(p_headers => l_headers, p_header_name => 'x-amz-storage-class', p_header_value => nvl(p_storage_class,G_STANDARD));

    /*
            https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/allocation-tag-restrictions.html
            -> Maximum key length: 128 Unicode characters
            -> Maximum value length: 256 Unicode characters
            -> Case sensitive
            -> Maximum number of tags per resource: 50
            -> Maximum active tag keys for Billing and Cost Management reports: 500
            -> Reserved prefix—aws:
            -> AWS-generated tag names and values are automatically assigned the aws: prefix, which you cannot assign. User-defined tag names have the prefix user: in the Cost Allocation Report.
            -> Use each key only once for each resource. If you attempt to use the same key twice on the same resource, your request will be rejected.
            -> You cannot tag a resource at the same time you create it. Tagging requires a separate action after the resource is created.
            -> You cannot backdate the application of a tag. This means that tags only start appearing on your cost allocation report after you apply them, and don't appear on earlier reports.
            -> Allowed characters are Unicode letters, whitespace, and numbers, plus the following special characters: + - = . _ : /
            */
    if (p_tags is not null) then
        add_header(p_headers => l_headers, p_header_name => 'x-amz-tagging', p_header_value => p_tags);
    end if;

    authorization_string(
        l_method,
        p_bucketname,
        p_objectname,
        l_query_string,
        l_headers,
        l_hashed_payload,
        l_date,
        l_url);

    make_request(
        p_url => l_url,
        p_http_method => l_method,
        p_request => l_req,
        p_response => l_resp,
        p_headers => l_headers,
        p_blob => p_blob);

    if (l_resp.status_code <> 200) then
        l_clob := get_clob_from_response(l_resp);
        raise_error_response(l_resp,l_clob);
    end if;

    utl_http.end_response(l_resp);

    end put_object;

    procedure put_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2,
        p_tags clob) as

    l_req utl_http.req;
    l_resp utl_http.resp;

    l_clob clob;
    l_date date;
    l_url varchar2(4000);
    l_method varchar2(6);
    l_headers t_headers_list;
    l_content_length number(20);
    l_base64_md5_hash varchar2(1000);
    l_hashed_payload varchar2(4000);
    l_query_string t_query_string_list;

    begin
    l_method := G_METHOD_PUT;
    l_hashed_payload := sha256_hash(p_tags);
    l_content_length := dbms_lob.getlength(p_tags);
    l_base64_md5_hash := base64_md5_hash(p_tags);
    l_query_string(1).name := 'tagging';
    l_date := sysdate;

   /*
            Common Request Headers
            https://docs.aws.amazon.com/pt_br/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
            UTL_HTTP.SET_HEADER(req, 'Authorization', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Length', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Type', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-MD5', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Date', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Expect', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Host', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-content-sha256', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-date', 'Mozilla/4.0');
            x-amz-storage-class: REDUCED_REDUNDANCY
            UTL_HTTP.SET_HEADER(req, 'x-amz-security-token', 'Mozilla/4.0');
            */
    add_header(p_headers => l_headers, p_header_name => 'Authorization');
    add_header(p_headers => l_headers, p_header_name => 'Content-Length', p_header_value => l_content_length);
    add_header(p_headers => l_headers, p_header_name => 'Content-MD5', p_header_value => l_base64_md5_hash);
    add_header(p_headers => l_headers, p_header_name => 'Host');
    add_header(p_headers => l_headers, p_header_name => 'x-amz-content-sha256', p_header_value => l_hashed_payload);
    add_header(p_headers => l_headers, p_header_name => 'x-amz-date', p_header_value => format_iso_8601(l_date));

    authorization_string(
        l_method,
        p_bucketname,
        p_objectname,
        l_query_string,
        l_headers,
        l_hashed_payload,
        l_date,
        l_url);

    make_request(
        p_url => l_url,
        p_http_method => l_method,
        p_request => l_req,
        p_response => l_resp,
        p_headers => l_headers,
        p_clob => p_tags);

    if (l_resp.status_code <> 200) then
        l_clob := get_clob_from_response(l_resp);
        raise_error_response(l_resp,l_clob);
    end if;

    utl_http.end_response(l_resp);
    end put_object_tagging;

    function get_object(
        p_bucketname varchar2,
        p_objectname varchar2)
        return blob as

    l_req utl_http.req;
    l_resp utl_http.resp;

    l_clob clob;
    l_blob blob;
    l_date date;
    l_url varchar2(4000);
    l_method varchar2(6);
    l_headers t_headers_list;
    l_content_length number(20);
    l_base64_md5_hash varchar2(1000);
    l_hashed_payload varchar2(4000);
    l_query_string t_query_string_list;
    begin

    l_method := G_METHOD_GET;
    l_hashed_payload := G_NULL_HASH;
    --l_content_length := dbms_lob.getlength(p_blob);
    --l_base64_md5_hash := base64_md5_hash(p_src => p_blob);
    -- l_query_string.delete;
    l_date := sysdate;

    /*
            Common Request Headers
            https://docs.aws.amazon.com/pt_br/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
            UTL_HTTP.SET_HEADER(req, 'Authorization', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Length', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Type', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-MD5', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Date', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Expect', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Host', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-content-sha256', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-date', 'Mozilla/4.0');
            x-amz-storage-class: REDUCED_REDUNDANCY
            UTL_HTTP.SET_HEADER(req, 'x-amz-security-token', 'Mozilla/4.0');
            */
    add_header(p_headers => l_headers, p_header_name => 'Authorization');
    --add_header(p_headers => l_headers, p_header_name => 'Content-Length', p_header_value => l_content_length);
    --add_header(p_headers => l_headers, p_header_name => 'Content-Type', p_header_value => nvl(p_content_type, G_CONTENT_TYPE_DEFAULT));
    --add_header(p_headers => l_headers, p_header_name => 'Content-MD5', p_header_value => l_base64_md5_hash);
    add_header(p_headers => l_headers, p_header_name => 'Host');
    add_header(p_headers => l_headers, p_header_name => 'x-amz-content-sha256', p_header_value => l_hashed_payload);
    add_header(p_headers => l_headers, p_header_name => 'x-amz-date', p_header_value => format_iso_8601(l_date));

    --add_header(p_headers => l_headers, p_header_name => 'x-amz-storage-class', p_header_value => nvl(p_storage_class,G_STANDARD));

    authorization_string(
        l_method,
        p_bucketname,
        p_objectname,
        l_query_string,
        l_headers,
        l_hashed_payload,
        l_date,
        l_url);

    make_request(
        p_url => l_url,
        p_http_method => l_method,
        p_request => l_req,
        p_response => l_resp,
        p_headers => l_headers);

    if  (l_resp.status_code = 200) then
        l_blob := get_blob_from_response(l_resp);
    else
        l_clob := get_clob_from_response(l_resp);
        raise_error_response(l_resp,l_clob);
    end if;

    utl_http.end_response(l_resp);

    return l_blob;
    end get_object;

    function get_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2)
        return clob as

    l_req utl_http.req;
    l_resp utl_http.resp;

    l_clob clob;
    l_date date;
    l_url varchar2(4000);
    l_method varchar2(6);
    l_headers t_headers_list;
    l_content_length number(20);
    l_base64_md5_hash varchar2(1000);
    l_hashed_payload varchar2(4000);
    l_query_string t_query_string_list;
    begin

    l_method := G_METHOD_GET;
    l_hashed_payload := G_NULL_HASH;
    --l_content_length := dbms_lob.getlength(p_blob);
    --l_base64_md5_hash := base64_md5_hash(p_src => p_blob);
    -- l_query_string.delete;
    l_query_string(1).name := 'tagging';
    l_date := sysdate;

    /*
            Common Request Headers
            https://docs.aws.amazon.com/pt_br/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
            UTL_HTTP.SET_HEADER(req, 'Authorization', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Length', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-Type', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Content-MD5', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Date', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Expect', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'Host', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-content-sha256', 'Mozilla/4.0');
            UTL_HTTP.SET_HEADER(req, 'x-amz-date', 'Mozilla/4.0');
            x-amz-storage-class: REDUCED_REDUNDANCY
            UTL_HTTP.SET_HEADER(req, 'x-amz-security-token', 'Mozilla/4.0');
            */
    add_header(p_headers => l_headers, p_header_name => 'Authorization');
    add_header(p_headers => l_headers, p_header_name => 'Host');
    add_header(p_headers => l_headers, p_header_name => 'x-amz-content-sha256', p_header_value => l_hashed_payload);
    add_header(p_headers => l_headers, p_header_name => 'x-amz-date', p_header_value => format_iso_8601(l_date));

    authorization_string(
        l_method,
        p_bucketname,
        p_objectname,
        l_query_string,
        l_headers,
        l_hashed_payload,
        l_date,
        l_url);

    make_request(
        p_url => l_url,
        p_http_method => l_method,
        p_request => l_req,
        p_response => l_resp,
        p_headers => l_headers);

    l_clob := get_clob_from_response(l_resp);

    if  (l_resp.status_code <> 200) then
        raise_error_response(l_resp,l_clob);
    end if;

    utl_http.end_response(l_resp);

    return l_clob;
    end get_object_tagging;

end pkg_aws_s3_api;
/