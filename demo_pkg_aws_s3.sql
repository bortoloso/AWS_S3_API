
/* Create tables */
-- create table test_blob_origin(ds blob);
-- create table test_blob_return(ds blob);
-- create table test_clob_return(ds clob);

/* insert 1 line with a blob file */
-- insert into test_blob_origin select blob_field from other_table;

/*
===============================================================================
PUT_OBJECT
    Put a object on a bucket
*/
declare
l_blob blob;
l_error pkg_aws_s3.r_error;
begin

delete from test_clob_return;
commit;

select ds
into l_blob
from test_blob_origin;

pkg_aws_s3.init(
    p_acess_key_id      => 'AKIAEXAMPLE12345678A',
    p_secrec_acess_key  => 'abc123abc123abc213abc123ABC123ABC123ABC1',
    p_wallet_path       => 'file:/opt/oracle/wallets/amazon_aws',
    p_wallet_password   => 'password',
    p_region            => 'us-east-1');

begin
    pkg_aws_s3.put_object(
        p_bucketname        => 'my-bucket-on-virginia'
      , p_objectname        => 'myObjectName'
      , p_blob              => l_blob
      , p_storage_class     => pkg_aws_s3.g_standard
      , p_content_type      => 'application/pdf'
      , p_tags              => 'tag01=info01'||'&'||'tag02=info02');
exception
when others then
    /* -20000 Error returned by PKG_AWS_S3.RAISE_ERROR_RESPONSE */
    if (sqlcode = -20000) then
        /* write a log or anything else */
        l_error := pkg_aws_s3.get_error_detail();
        dbms_output.put_line(l_error.http_version);
        dbms_output.put_line(l_error.status_code);
        dbms_output.put_line(l_error.reason_phrase);
        dbms_output.put_line(l_error.code);
        dbms_output.put_line(l_error.message);
        dbms_output.put_line(l_error.clobdata);
        insert into test_clob_return values(l_error.clobdata);
        commit;
    end if;
    raise;
end;

end;
/

select * from test_clob_return;

/*
===============================================================================
GET_OBJECT
    Get a object
*/
declare
l_blob blob;
l_clob clob;
l_error pkg_aws_s3.r_error;
begin

delete from test_clob_return;
delete from test_blob_return;
commit;

pkg_aws_s3.init(
    p_acess_key_id      => 'AKIAEXAMPLE12345678A',
    p_secrec_acess_key  => 'abc123abc123abc213abc123ABC123ABC123ABC1',
    p_wallet_path       => 'file:/opt/oracle/wallets/amazon_aws',
    p_wallet_password   => 'password',
    p_region            => 'us-east-1');

begin
    l_blob := pkg_aws_s3.get_object(
        p_bucketname => 'my-bucket-on-virginia',
        p_objectname => 'myObjectName');

    insert into test_blob_return values(l_blob);
    commit;
exception
when others then
    /* -20000 Error returned by PKG_AWS_S3.RAISE_ERROR_RESPONSE */
    if (sqlcode = -20000) then
        /* write a log or anything else */
        l_error := pkg_aws_s3.get_error_detail();
        dbms_output.put_line(l_error.http_version);
        dbms_output.put_line(l_error.status_code);
        dbms_output.put_line(l_error.reason_phrase);
        dbms_output.put_line(l_error.code);
        dbms_output.put_line(l_error.message);
        dbms_output.put_line(l_error.clobdata);
        insert into test_clob_return values(l_error.clobdata);
        commit;
    end if;
    raise;
end;
end;
/

select * from test_clob_return;

select * from test_blob_return;

/*
===============================================================================
PUT_OBJECT_TAGGING
    Put a object tagging
*/
declare
l_blob blob;
l_tags clob;
l_error pkg_aws_s3.r_error;
begin

delete from test_clob_return;
commit;

select ds
into l_blob
from test_blob_origin;

pkg_aws_s3.init(
    p_acess_key_id      => 'AKIAEXAMPLE12345678A',
    p_secrec_acess_key  => 'abc123abc123abc213abc123ABC123ABC123ABC1',
    p_wallet_path       => 'file:/opt/oracle/wallets/amazon_aws',
    p_wallet_password   => 'password',
    p_region            => 'us-east-1');

begin
    l_tags := '<Tagging><TagSet><Tag><Key>tag1</Key><Value>val1</Value></Tag><Tag><Key>tag2</Key><Value>val2</Value></Tag></TagSet></Tagging>';

    pkg_aws_s3.put_object_tagging(
        p_bucketname        => 'my-bucket-on-virginia'
      , p_objectname        => 'myObjectName'
      , p_tags              => l_tags);
exception
when others then
    /* -20000 Error returned by PKG_AWS_S3.RAISE_ERROR_RESPONSE */
    if (sqlcode = -20000) then
        /* write a log or anything else */
        l_error := pkg_aws_s3.get_error_detail();
        dbms_output.put_line(l_error.http_version);
        dbms_output.put_line(l_error.status_code);
        dbms_output.put_line(l_error.reason_phrase);
        dbms_output.put_line(l_error.code);
        dbms_output.put_line(l_error.message);
        dbms_output.put_line(l_error.clobdata);
        insert into test_clob_return values(l_error.clobdata);
        commit;
    end if;
    raise;
end;

end;
/

select * from test_clob_return;

/*
===============================================================================
GET_OBJECT_TAGGING
    Get a object tagging
*/
declare
l_blob blob;
l_tags clob;
l_error pkg_aws_s3.r_error;
begin

delete from test_clob_return;
commit;

select ds
into l_blob
from test_blob_origin;

pkg_aws_s3.init(
    p_acess_key_id      => 'AKIAEXAMPLE12345678A',
    p_secrec_acess_key  => 'abc123abc123abc213abc123ABC123ABC123ABC1',
    p_wallet_path       => 'file:/opt/oracle/wallets/amazon_aws',
    p_wallet_password   => 'password',
    p_region            => 'us-east-1');

begin
    l_tags := pkg_aws_s3.get_object_tagging(
        p_bucketname        => 'my-bucket-on-virginia'
      , p_objectname        => 'myObjectName');

        insert into test_clob_return values(l_tags);
        commit;
exception
when others then
    /* -20000 Error returned by PKG_AWS_S3.RAISE_ERROR_RESPONSE */
    if (sqlcode = -20000) then
        /* write a log or anything else */
        l_error := pkg_aws_s3.get_error_detail();
        dbms_output.put_line(l_error.http_version);
        dbms_output.put_line(l_error.status_code);
        dbms_output.put_line(l_error.reason_phrase);
        dbms_output.put_line(l_error.code);
        dbms_output.put_line(l_error.message);
        dbms_output.put_line(l_error.clobdata);
        insert into test_clob_return values(l_error.clobdata);
        commit;
    end if;
    raise;
end;

end;
/

select * from test_clob_return;