create or replace package body pkg_aws_s3_api as

  procedure put_object(
    p_bucketname varchar2,
    p_objectname varchar2) AS
  BEGIN
    -- TODO: implementação exigida para procedure PKG_AWS_S3_API.put_object
    NULL;
  END put_object;

  procedure put_object_tagging(
    p_bucketname varchar2,
    p_objectname varchar2,
    p_tags varchar2) AS
  BEGIN
    -- TODO: implementação exigida para procedure PKG_AWS_S3_API.put_object_tagging
    NULL;
  END put_object_tagging;

  function get_object(
    p_bucketname varchar2,
    p_objectname varchar2)
    return blob AS
  BEGIN
    -- TODO: implementação exigida para function PKG_AWS_S3_API.get_object
    RETURN NULL;
  END get_object;

  function get_object_tagging(
    p_bucketname varchar2,
    p_objectname varchar2)
    return varchar2 AS
  BEGIN
    -- TODO: implementação exigida para function PKG_AWS_S3_API.get_object_tagging
    RETURN NULL;
  END get_object_tagging;

end pkg_aws_s3_api;