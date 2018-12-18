create or replace 
package pkg_aws_s3_api as 

-- https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
  procedure put_object(
    p_bucketname varchar2,
    p_objectname varchar2);

-- https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTtagging.html
  procedure put_object_tagging(
    p_bucketname varchar2,
    p_objectname varchar2,
    p_tags varchar2); -- tag1=value1&tag2=value2

-- https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html
  function get_object(
    p_bucketname varchar2,
    p_objectname varchar2)
    return blob;

-- https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETtagging.html
  function get_object_tagging(
    p_bucketname varchar2,
    p_objectname varchar2)
    return varchar2; -- criar tipo para a tag 

end pkg_aws_s3_api;