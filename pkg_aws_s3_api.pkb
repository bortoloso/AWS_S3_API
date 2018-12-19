create or replace package body pkg_aws_s3_api as
  
  lf varchar2(1) := chr(10);
  g_aws_algorithm varchar2(16) := 'AWS4-HMAC-SHA256';
  g_aws_region varchar2(40) := 'sa-east-1';
  g_aws_service varchar2(5) := 's3';
  g_termination_string varchar2(12) := 'aws4_request';
  g_null_hash varchar2(100) := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  function uri_encode(
    l_string in varchar2)
    return varchar2 is
  begin
  /*
  Código em Java
  public static String UriEncode(CharSequence input, boolean encodeSlash) {
          StringBuilder result = new StringBuilder();
          for (int i = 0; i < input.length(); i++) {
              char ch = input.charAt(i);
              if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '~' || ch == '.') {
                  result.append(ch);
              } else if (ch == '/') {
                  result.append(encodeSlash ? "%2F" : ch);
              } else {
                  result.append(toHexUTF8(ch));
              }
          }
          return result.toString();
      }
  */
  return null;
  end uri_encode;

  function format_iso_8601(
    p_date in date)
    return varchar2 is
  begin
  
  return null;

  end format_iso_8601;

  function base64(
    p_src in raw)
    return varchar2 is
  begin
  
  return null;

  end base64;

  function sha256_hash(
    p_src in raw)
    return varchar2 is
  begin
  
  return null;

  end sha256_hash;

  function hmac_sha256(
    p_src in raw,
    p_key in raw)
    return raw is
  begin
  
  return null;
  end hmac_sha256;

  /*
  https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  */
  function aws_canonical_request(
    p_httpmethod in varchar2,
    p_uri in varchar2,
    p_querystring in varchar2,
    p_headers in varchar2,
    p_signedheaders in varchar2,
    p_payload in varchar2,
    p_date in date)
    return varchar2 is
  l_return varchar2(4000);
  l_canonical_uri varchar2(200);
  l_canonical_query_string varchar2(1000);
  l_canonical_headers varchar2(1000);
  l_signed_headers varchar2(1000);
  l_hashedpayload varchar2(4000);
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
  if substr(p_uri,1,1) = '/' then
    l_canonical_uri := uri_encode(p_uri);
  else
    l_canonical_uri := uri_encode('/'||p_uri);
  end if;

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
  l_canonical_query_string := '';

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
 */
  l_canonical_headers := '';

  /*
  SignedHeaders is an alphabetically sorted, semicolon-separated list of lowercase request header names.
  The request headers in the list are the same headers that you included in the CanonicalHeaders string.
  */
  l_signed_headers := '';

  /*
  HashedPayload is the hexadecimal value of the SHA256 hash of the request payload.
  */
  l_hashedpayload := sha256_hash(p_payload);

  l_return =
    p_httpmethod||lf||
    l_canonical_uri||lf||
    l_canonical_query_string||lf||
    l_canonical_headers||lf||
    l_signed_headers||lf||
    l_hashedpayload;

  return l_return;
  end aws_canonical_request;
  
  /*
  https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
  */
  function aws_string_to_sign(
    p_hashed_request in varchar2,
    p_date in date)
    return varchar2 is
    l_return varchar2(1000);
  begin
  l_return := g_aws_algorithm||lf||
  format_iso_8601(p_date)||lf||
  to_char(p_date, 'yyyymmdd')||'/'||g_aws_region||'/'||g_aws_service||'/'||g_termination_string||lf||
  p_hashed_request;

  return l_return;
  end aws_string_to_sign;

  /*
  https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
  */
  function aws_signature(
    l_stringtosign in varchar2)
    return varchar2 is
  l_return varchar2(200);
  begin
  
  return l_return;
  end aws_signature;
  
  function aws_authorization_header(
    l_stringtosign in varchar2)
    return varchar2 is
  l_canonical_request varchar2(1000);
  l_string_to_sign varchar2(1000);
  l_signature varchar2(200);
  begin
  l_canonical_request := aws_canonical_request(
                        p_httpmethod => ,
                        p_uri => ,
                        p_querystring => ,
                        p_headers => ,
                        p_signedheaders => ,
                        p_hashedpayload => 
                        p_date => );

  l_string_to_sign := aws_string_to_sign(
                        p_hashed_request => l_canonical_request
                        p_date => );

  l_signature := aws_signature();
  
  return l_signature;
  end aws_authorization_header;




/*
  function aws_signature(
    l_stringtosign   out number)
    return varchar2 is
  begin
  
  return null;
  end aws_signature;
*/

  procedure put_object(
    p_bucketname varchar2,
    p_objectname varchar2) as
  begin
    -- todo: implementação exigida para procedure pkg_aws_s3_api.put_object
    null;
  end put_object;

  procedure put_object_tagging(
    p_bucketname varchar2,
    p_objectname varchar2,
    p_tags varchar2) as
  begin
    -- todo: implementação exigida para procedure pkg_aws_s3_api.put_object_tagging
    null;
  end put_object_tagging;

  function get_object(
    p_bucketname varchar2,
    p_objectname varchar2)
    return blob as
  begin
    -- todo: implementação exigida para function pkg_aws_s3_api.get_object
    return null;
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
  begin
  -- Task 1: Create a Canonical Request
  get_canonical_request();

  get_string_to_sign();

  get_signature_sv4();

  -- Task 2: Create a String to Sign


  -- Task 3: Calculate Signature




  /*
  GET /example-object?tagging HTTP/1.1
  Host: examplebucket.s3.amazonaws.com
  Date: Thu, 22 Sep 2016 21:33:08 GMT
  Authorization: authorization string
  */
  l_url := 'https://'||p_bucketname||'.s3-sa-east-1.amazonaws.com/';


  l_url := l_url||'?tagging'; -- string de busca

  dbms_lob.createtemporary(l_clob, false);
  utl_http.set_wallet('wallet', 'password');
  l_req := utl_http.begin_request(url => l_url, method => 'GET', http_version => utl_http.http_version_1_1);


  /*
  Common Request Headers
  -- https://docs.aws.amazon.com/pt_br/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
  UTL_HTTP.SET_HEADER(req, 'Authorization', 'Mozilla/4.0');
  UTL_HTTP.SET_HEADER(req, 'Content-Length', 'Mozilla/4.0');
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
      utl_http.read_text(l_resp, l_data, 32767);
      dbms_lob.writeappend (l_clob, length(l_data), l_data);
    end loop;
  exception
    when utl_http.end_of_body then
      utl_http.end_response(l_resp);
  end;

  return l_clob;
  end get_object_tagging;

end pkg_aws_s3_api;