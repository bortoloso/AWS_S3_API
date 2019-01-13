create or replace package pkg_aws_s3 as

    /*
    Storage class
    */
    G_STANDARD constant varchar2(8) := 'STANDARD';
    G_STANDARD_IA constant varchar2(11) := 'STANDARD_IA';
    G_INTELLIGENT_TIERING constant varchar2(19) := 'INTELLIGENT_TIERING';
    G_ONEZONE_IA constant varchar2(10) := 'ONEZONE_IA';
    G_GLACIER constant varchar2(7) := 'GLACIER';
    G_RRS constant varchar2(3) := 'RRS';

    type r_headers is record (
        name varchar2(256),
        value varchar2(4000)
    );
    type t_headers is table of r_headers index by pls_integer;

    type r_query_string is record (
        name varchar2(255),
        value varchar2(255)
    );
    type t_query_string is table of r_query_string index by pls_integer;

    type r_error is record (
        status_code pls_integer,
        reason_phrase varchar2(256),
        http_version varchar2(64),
        headers t_headers,
        code varchar2(100),
        message varchar2(1000),
        xmldata xmltype,
        clobdata clob
        );

    procedure init(
        p_acess_key_id varchar2 default null,
        p_secrec_acess_key varchar2 default null,
        p_wallet_path varchar2 default null,
        p_wallet_password varchar2 default null,
        p_region varchar2 default null);

    procedure set_acess_key_id(
        p_acess_key_id varchar2);

    procedure set_secrec_acess_key(
        p_secrec_acess_key varchar2);

    procedure set_wallet_path(
        p_wallet_path varchar2);

    procedure set_wallet_password(
        p_wallet_password varchar2);

    procedure set_region(
        p_region varchar2);

    function get_error_detail
        return r_error;

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html */
    procedure put_object(
        p_bucketname varchar2,
        p_objectname varchar2,
        p_blob in blob,
        p_storage_class in varchar2 default null,
        p_content_type in varchar2 default null,
        p_tags in varchar2 default null);

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUTtagging.html */
    procedure put_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2,
        p_tags clob);

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGET.html */
    function get_object(
        p_bucketname varchar2,
        p_objectname varchar2)
        return blob;

/* https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectGETtagging.html */
    function get_object_tagging(
        p_bucketname varchar2,
        p_objectname varchar2)
        return clob;

end pkg_aws_s3;
/