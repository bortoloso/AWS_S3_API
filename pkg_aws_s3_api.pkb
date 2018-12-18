create or replace package body pkg_aws_s3_api as
  
  lf varchar2(1) := chr(10);
  g_aws_region varchar2(40) := 'sa-east-1';
  g_aws_service varchar2(5) := 's3';
  
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

  function aws_canonical_request(
    p_httpmethod in varchar2,
    p_uri in varchar2,
    p_querystring in varchar2,
    p_headers in varchar2,
    p_signedheaders in varchar2,
    p_hashedpayload in varchar2)
    return varchar2 is
  begin
  
  return null;
  end aws_canonical_request;
  
  function aws_string_to_sign(
    p_hashed_request
    p_date   out number)
    return varchar2 is
    l_return varchar2(1000);
  begin
  /*
  StringToSign =
    Algorithm + \n +
    RequestDateTime + \n +
    CredentialScope + \n +
    HashedCanonicalRequest
  date.Format(<YYYYMMDD>) + "/" + <region> + "/" + <service> + "/aws4_request"
  */
  l_return := 'AWS4-HMAC-SHA256'||lf||
  format_iso_8601(p_date)||lf||
  to_char(p_date, 'yyyymmdd')||'/'||g_aws_region||'/'||g_aws_service||'/aws4_request'||lf||
  p_hashed_request;

  return l_return;
  end aws_string_to_sign;

  function aws_signature(
    l_stringtosign   out number)
    return varchar2 is
  begin
  
  return null;
  end aws_signature;
  









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