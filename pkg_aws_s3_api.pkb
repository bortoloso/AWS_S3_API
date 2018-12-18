create or replace package body pkg_aws_s3_api as

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

  l_url := '';

  dbms_lob.createtemporary(l_clob, false);
  utl_http.set_wallet('wallet', 'password');
  l_req := utl_http.begin_request(url => l_url, method => 'GET', http_version => utl_http.http_version_1_1);

  --UTL_HTTP.SET_HEADER(req, 'User-Agent', 'Mozilla/4.0');

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