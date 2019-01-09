create or replace package body pkg_aws_s3_api as

    /*
            VARIABLES
            */
    g_acess_key_id varchar2(20) := null;
    g_secrec_acess_key varchar2(40) := null;
    g_wallet_path varchar2(1000) := null;
    g_wallet_password varchar2(1000) := null;
    g_region varchar2(40) := null;
    --g_region varchar2(40) := 'us-east-1';

    /*
          CONSTANTS AUTH
            */
    g_acess_key_id_default constant varchar2(20) := '== Access Key ID =='; /* Access Key ID DEFAULT */
    g_secrec_acess_key_default constant varchar2(40) := '== Secret access Key =='; /* Secret access Key DEFAULT */
    g_wallet_path_default constant varchar2(1000) := '== Wallet Path =='; /* Wallet DEFAUL */
    g_wallet_password_default constant varchar2(1000) := '== Wallet Password =='; /* Wallet Password  DEFAULT*/
    g_region_default constant varchar2(40) := 'sa-east-1'; /* Region S3 DEFAULT */

    /*
            CONSTANTS API
            */
    g_algorithm constant varchar2(16) := 'AWS4-HMAC-SHA256';
    g_ISO8601_format constant varchar2(22) := 'YYYYMMDD"T"HH24MISS"Z"';
    g_service constant varchar2(5) := 's3';
    g_termination_string constant varchar2(12) := 'aws4_request';
    g_null_hash constant varchar2(100) := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    lf constant varchar2(1) := chr(10);

    function uri_encode(
        p_char_sequence in varchar2,
        p_encode_slash in pls_integer default 0)
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
                l_result := l_result||'%'|| rawtohex(utl_i18n.string_to_raw(l_ch,'AL32UTF8'));
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
    return to_char(sys_extract_utc(cast(p_date as timestamp with time zone)), g_ISO8601_format);
    end format_iso_8601;

    function base64(
        p_src_raw in raw)
        return varchar2 is
    begin
    return utl_encode.base64_encode(p_src_raw);
    end base64;

    function base64(
        p_src_varchar2 in varchar2)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    l_src raw(4000);
    begin
    l_src := utl_i18n.string_to_raw(p_src_varchar2,'AL32UTF8');
    l_return := base64(p_src_raw => l_src);
    return rawtohex(l_return);
    end base64;

    function md5_hash(
        p_src in blob)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    begin

    l_hash := dbms_crypto.hash(
                src => p_src,
                typ => dbms_crypto.hash_md5);

    /*
            testar com retorno sem o LOWER;
            testar com retorno em RAW
            */
    -- l_return := utl_raw.cast_to_varchar2(l_hash);
    l_return := lower(rawtohex(l_hash));
    return l_return;
    end md5_hash;

    function md5_hash(
        p_src in varchar2)
        return varchar2 is
    l_return varchar2(2000);
    l_hash raw(2000);
    l_src raw(4000);
    begin

    l_src := substr(utl_i18n.string_to_raw(p_src,'AL32UTF8'),1,4000);
    l_hash := dbms_crypto.hash(
                src => l_src,
                typ => dbms_crypto.hash_md5);

    /*
            testar com retorno sem o LOWER;
            testar com retorno em RAW
            */
    -- l_return := utl_raw.cast_to_varchar2(l_hash);
    l_return := lower(rawtohex(l_hash));
    return l_return;
    end md5_hash;

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
        l_canonical_uri := uri_encode(p_uri);
    else
        l_canonical_uri := uri_encode('/'||p_uri);
    end if;

    if  (p_bucketname is not null) then
        if  (g_region = 'us-east-1') then
            l_host := p_bucketname||'.s3.amazonaws.com';
            p_url := 'https://'||p_bucketname||'.s3.amazonaws.com'||l_canonical_uri;
        else
            l_host := p_bucketname||'.s3.'||g_region||'.amazonaws.com';
            p_url := 'https://'||p_bucketname||'.s3.'||g_region||'.amazonaws.com'||l_canonical_uri;
        end if;
    else
        l_host := 'host:s3.amazonaws.com';
        p_url := 'https://s3.amazonaws.com';
    end if;
    p_headers(1).value := l_host;

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
        (p_headers.count > 0) then
        for i in 1 .. p_headers.count loop
            if  ((lower(p_headers(i).name) in ('host',/*'content-type',*/'range')) or
                (substr(lower(p_headers(i).name),1,6) = 'x-amz-')) then
                l_canonical_headers := l_canonical_headers ||
                lower(p_headers(i).name)||':'||trim(p_headers(i).value)||lf;

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
        p_httpmethod||lf||
        l_canonical_uri||lf||
        l_canonical_query_string||lf||
        l_canonical_headers||lf||
        l_signed_headers||lf||
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

    l_return := g_algorithm||lf||
    format_iso_8601(p_date)||lf||
    to_char(p_date, 'yyyymmdd')||'/'||g_region||'/'||g_service||'/'||g_termination_string||lf||
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
    l_dateregionserviceKey  := hmac_sha256(p_key_raw => l_dateregionkey, p_src_varchar2 => g_service);
    l_signingkey            := hmac_sha256(p_key_raw => l_dateregionserviceKey, p_src_varchar2 => g_termination_string);

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
        (p_headers.count > 0) then
        for i in 1 .. p_headers.count loop
            if  ((lower(p_headers(i).name) in ('host',/*'content-type',*/'range')) or
                (substr(lower(p_headers(i).name),1,6) = 'x-amz-')) then
                l_signed_headers := l_signed_headers ||
                lower(p_headers(i).name)||';';
            end if;
        end loop;
        l_signed_headers := substr(l_signed_headers,1,length(l_signed_headers)-1);
    end if;
    l_authorization_string := g_algorithm||
                            ' Credential='||g_acess_key_id||'/'||to_char(p_date,'yyyymmdd')||'/'||g_region||'/s3/aws4_request,'||
                            ' SignedHeaders='||l_signed_headers||','||
                            ' Signature='||l_signature ;
    p_headers(2).value := l_authorization_string;

  end authorization_string;

/*
  function signature(
    l_stringtosign   out number)
    return varchar2 is
  begin

  return null;
  end signature;
*/

    procedure put_object(
        p_bucketname in varchar2,
        p_objectname in varchar2,
        p_blob       in blob) as

    l_clob clob;
    l_blob blob;
    l_url varchar2(4000);
    l_req utl_http.req;
    l_resp utl_http.resp;
    l_data varchar2(32767);
    l_raw raw(32767);

    l_method varchar2(6);
    l_headers t_headers_list;
    l_query_string t_query_string_list;
    l_date date;
    l_hashed_payload varchar2(4000);

    l_buffer    raw(32767);

    l_length    integer;
    l_offset    number(15) := 1;
    l_value     varchar2(1024);
    l_amount    number(15) := 32767;
    l_content_length    number;
    begin

    l_date := sysdate;
    l_hashed_payload := sha256_hash(p_blob);
    l_content_length    := dbms_lob.getlength(P_BLOB);

    l_method := 'PUT';
    l_headers(1).name := 'host';
    l_headers(1).value := '';
    l_headers(2).name := 'Authorization';
    l_headers(2).value := '';
    l_headers(3).name := 'Content-Length';
    l_headers(3).value := l_content_length;
    l_headers(4).name := 'Content-Type';
    l_headers(4).value := 'application/pdf';
    l_headers(5).name := 'x-amz-content-sha256';
    l_headers(5).value := l_hashed_payload;
    l_headers(6).name := 'x-amz-date';
    l_headers(6).value := format_iso_8601(l_date);
    l_headers(7).name := 'x-amz-tagging';
    l_headers(7).value := 'tag1=value1'||'&'||'tag2=value2';

    authorization_string(
                        l_method,
                        p_bucketname,
                        p_objectname,
                        l_query_string,
                        l_headers,
                        l_hashed_payload,
                        l_date,
                        l_url);

    dbms_lob.createtemporary(l_clob, false);
    dbms_lob.createtemporary(l_blob, false);
    utl_http.set_wallet(g_wallet_path, g_wallet_password);
    l_req := utl_http.begin_request(url => l_url, method => l_method, http_version => utl_http.http_version_1_1);

    if  (l_headers is not null) and
        (l_headers.count > 0) then
        for i in 1 .. l_headers.count loop
            if  l_headers(i).name <> 'host' then
                UTL_HTTP.SET_HEADER(l_req, l_headers(i).name, l_headers(i).value);
            end if;
    end loop;
    end if;


    while l_offset < l_content_length loop
        dbms_output.put_line(l_offset);
        dbms_lob.read(p_blob, l_amount, l_offset, l_buffer);
        utl_http.write_raw(l_req, l_buffer);
        l_offset := l_offset + l_amount;
    end loop;

    l_resp := utl_http.get_response (l_req);

    begin
    loop
        --utl_http.read_text(l_resp, l_data, 32767);
        --dbms_lob.writeappend (l_clob, length(l_data), l_data);
        utl_http.read_raw(l_resp, l_raw, 32767);
        dbms_lob.writeappend (l_blob, utl_raw.length(l_raw), l_raw);
    end loop;
    exception
    when utl_http.end_of_body then
        utl_http.end_response(l_resp);
    end;
    utl_http.end_response(l_resp);
    end put_object;

    procedure put_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2,
        p_tags varchar2) as

    l_clob clob;
    l_blob blob;
    l_url varchar2(4000);
    l_req utl_http.req;
    l_resp utl_http.resp;
    l_data varchar2(32767);
    l_raw raw(32767);

    l_method varchar2(6);
    l_headers t_headers_list;
    l_query_string t_query_string_list;
    l_date date;
    l_hashed_payload varchar2(4000);
    begin

    l_date := sysdate;
    l_hashed_payload := g_null_hash;

    l_method := 'PUT';
    l_headers(1).name := 'host';
    l_headers(1).value := '';
    l_headers(2).name := 'Authorization';
    l_headers(2).value := '';
    l_headers(3).name := 'x-amz-content-sha256';
    l_headers(3).value := l_hashed_payload;
    l_headers(4).name := 'x-amz-date';
    l_headers(4).value := format_iso_8601(l_date);

    authorization_string(
                        l_method,
                        p_bucketname,
                        p_objectname,
                        l_query_string,
                        l_headers,
                        l_hashed_payload,
                        l_date,
                        l_url);

    dbms_lob.createtemporary(l_clob, false);
    dbms_lob.createtemporary(l_blob, false);
    utl_http.set_wallet(g_wallet_path, g_wallet_password);
    l_req := utl_http.begin_request(url => l_url, method => l_method, http_version => utl_http.http_version_1_1);

    if  (l_headers is not null) and
        (l_headers.count > 0) then
        for i in 1 .. l_headers.count loop
            if  l_headers(i).name <> 'host' then
                UTL_HTTP.SET_HEADER(l_req, l_headers(i).name, l_headers(i).value);
                dbms_output.put_line('name: '||l_headers(i).name||' |value: '||l_headers(i).value);
            end if;
        end loop;
    end if;

    l_resp := utl_http.get_response (l_req);
    begin
    loop
        utl_http.read_raw(l_resp, l_raw, 32767);
        dbms_lob.writeappend (l_blob, utl_raw.length(l_raw), l_raw);
    end loop;
    exception
    when utl_http.end_of_body then
        utl_http.end_response(l_resp);
    end;
    utl_http.end_response(l_resp);
    end put_object_tagging;

    function get_object(
        p_bucketname varchar2,
        p_objectname varchar2)
        return blob as

    l_clob clob;
    l_blob blob;
    l_url varchar2(4000);
    l_req utl_http.req;
    l_resp utl_http.resp;
    l_data varchar2(32767);
    l_raw raw(32767);

    l_method varchar2(6);
    l_headers t_headers_list;
    l_query_string t_query_string_list;
    l_date date;
    l_hashed_payload varchar2(4000);

    begin
    l_date := sysdate;
    --l_date              := p_date;
    --l_date := localtimestamp;
    -- l_date              := to_date('191220182211','ddmmyyyyhh24miss');
    --l_date              := to_date('20190106175033','yyyymmddhh24miss');
    l_hashed_payload := g_null_hash;

    l_method := 'GET';
    l_headers(1).name := 'host';
    l_headers(1).value := '';
    l_headers(2).name := 'Authorization';
    l_headers(2).value := '';
    l_headers(3).name := 'x-amz-content-sha256';
    l_headers(3).value := l_hashed_payload;
    l_headers(4).name := 'x-amz-date';
    l_headers(4).value := format_iso_8601(l_date);

    authorization_string(
                        l_method,
                        p_bucketname,
                        p_objectname,
                        l_query_string,
                        l_headers,
                        l_hashed_payload,
                        l_date,
                        l_url);

    dbms_lob.createtemporary(l_clob, false);
    dbms_lob.createtemporary(l_blob, false);
    utl_http.set_wallet(g_wallet_path, g_wallet_password);
    l_req := utl_http.begin_request(url => l_url, method => l_method, http_version => utl_http.http_version_1_1);

    if  (l_headers is not null) and
        (l_headers.count > 0) then
        for i in 1 .. l_headers.count loop
            if l_headers(i).name <> 'host' then
                UTL_HTTP.SET_HEADER(l_req, l_headers(i).name, l_headers(i).value);
                dbms_output.put_line('name: '||l_headers(i).name||' |value: '||l_headers(i).value);
            end if;
        end loop;
    end if;

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

    l_resp := utl_http.get_response (l_req);
    begin
    loop
        utl_http.read_raw(l_resp, l_raw, 32767);
        dbms_lob.writeappend (l_blob, utl_raw.length(l_raw), l_raw);
    end loop;
    exception
    when utl_http.end_of_body then
        utl_http.end_response(l_resp);
    end;
    utl_http.end_response(l_resp);
    return l_blob;
    end get_object;

    function get_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2)
        return clob as

    l_clob clob;
    l_url varchar2(4000);
    l_req utl_http.req;
    l_resp utl_http.resp;
    l_data varchar2(32767);
    l_method varchar2(6);
    l_headers t_headers_list;
    l_query_string t_query_string_list;
    l_date date;
    l_hashed_payload varchar2(4000);
    begin

    l_date := sysdate;
    --l_date              := to_date('20190106172022','yyyymmddhh24miss');
    l_hashed_payload := g_null_hash;

    l_method := 'GET';
    l_headers(1).name := 'host';
    l_headers(1).value := '';
    l_headers(2).name := 'Authorization';
    l_headers(2).value := '';
    l_headers(3).name := 'x-amz-content-sha256';
    l_headers(3).value := l_hashed_payload;
    l_headers(4).name := 'x-amz-date';
    l_headers(4).value := format_iso_8601(l_date);

    l_query_string(1).name := 'tagging';
    l_query_string(1).value := '';


    authorization_string(
                        l_method,
                        p_bucketname,
                        p_objectname,
                        l_query_string,
                        l_headers,
                        l_hashed_payload,
                        l_date,
                        l_url);

    dbms_lob.createtemporary(l_clob, false);
    utl_http.set_wallet(g_wallet_path, g_wallet_password);
    l_req := utl_http.begin_request(url => l_url, method => l_method, http_version => utl_http.http_version_1_1);

    if  (l_headers is not null) and
        (l_headers.count > 0) then
        for i in 1 .. l_headers.count loop
            if l_headers(i).name <> 'host' then
                utl_http.set_header(l_req, l_headers(i).name, l_headers(i).value);
            end if;
        end loop;
    end if;

    l_resp := utl_http.get_response(l_req);
    begin
    loop
        utl_http.read_text(l_resp, l_data, 32767);
        dbms_lob.writeappend (l_clob, length(l_data), l_data);
    end loop;
    exception
    when utl_http.end_of_body then
        utl_http.end_response(l_resp);
    end;
    utl_http.end_response(l_resp);
    return l_clob;
    end get_object_tagging;

end pkg_aws_s3_api;
/