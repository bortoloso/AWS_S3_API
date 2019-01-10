create or replace package pkg_aws_s3 as

    type t_headers is record (
        name varchar2(255),
        value varchar2(255)
    );
    type t_headers_list is table of t_headers index by pls_integer;

    type t_query_string is record (
        name varchar2(255),
        value varchar2(255)
    );
    type t_query_string_list is table of t_query_string index by pls_integer;

    procedure init(
        p_acess_key_id varchar2 default null,
        p_secrec_acess_key varchar2 default null,
        p_wallet_path varchar2 default null,
        p_wallet_password varchar2 default null,
        p_region varchar2 default null);

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html */
    procedure put_object(
        p_bucketname varchar2,
        p_objectname varchar2,
        p_blob       in blob);

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTtagging.html */
    procedure put_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2,
        p_tags varchar2);

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html */
    function get_object(
        p_bucketname varchar2,
        p_objectname varchar2)
        return blob;

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETtagging.html */
    function get_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2)
        return clob; -- criar tipo para a tag

end pkg_aws_s3;
/