create or replace package body pkg_aws_s3_api as

  function uri_encode(
    l_stringtosign   out number)
    return varchar2 is
  begin
  
  return null;
  end uri_encode;

  function get_canonical_request(
    l_stringtosign   out number)
    return varchar2 is
  begin
  
  return null;
  end get_canonical_request;
  
  function get_string_to_sign(
    l_stringtosign   out number)
    return varchar2 is
  begin
  
  return null;
  end get_string_to_sign;

  function get_signature_sv4(
    l_stringtosign   out number)
    return varchar2 is
  begin
  
  return null;
  end get_signature_sv4;
  
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