# AWS_S3_API

PL/SQL package that exposes a small Oracle-side API for Amazon S3 object operations.

The package signs requests with AWS Signature Version 4 and uses `UTL_HTTP` over HTTPS to interact with S3.

## What This Project Provides

`pkg_aws_s3` is an Oracle package for applications that need to move files between the database and Amazon S3 without leaving PL/SQL.

Current supported operations:

- Upload an object from a `BLOB`
- Download an object into a `BLOB`
- Set object tags
- Read object tags

This repository includes:

- `pkg_aws_s3.pks`: package specification
- `pkg_aws_s3.pkb`: package body
- `demo_pkg_aws_s3.sql`: usage examples

## How It Works

The package builds and signs HTTP requests using AWS Signature V4 for the S3 service. Internally it uses Oracle built-in packages such as:

- `UTL_HTTP`
- `DBMS_CRYPTO`
- `UTL_ENCODE`
- `UTL_I18N`
- `DBMS_LOB`
- `XMLTYPE`

The typical flow is:

1. Initialize credentials, wallet, and region.
2. Call one of the S3 operations.
3. Handle success normally.
4. If AWS returns an error, catch Oracle error `-20000` and inspect `pkg_aws_s3.get_error_detail()`.

## Requirements

Before using this package, make sure your Oracle environment is prepared for outbound HTTPS calls.

### Oracle Requirements

- Oracle database with access to `UTL_HTTP`
- Access to `DBMS_CRYPTO`
- Network ACL allowing outbound HTTPS traffic to Amazon S3 endpoints
- Oracle wallet configured for HTTPS/TLS

### AWS Requirements

- An AWS access key ID and secret access key
- An S3 bucket in the target region
- IAM permissions for the required operations

Minimum IAM actions typically required:

- `s3:PutObject`
- `s3:GetObject`
- `s3:PutObjectTagging`
- `s3:GetObjectTagging`

## Installation

Compile the package specification and body in your Oracle schema:

```sql
@pkg_aws_s3.pks
@pkg_aws_s3.pkb
```

Then run the demo script if you want sample usage:

```sql
@demo_pkg_aws_s3.sql
```

## Configuration

The package stores runtime configuration in package global variables. You can set everything at once with `init` or update values individually with the setter procedures.

### Important Note About Defaults

The implementation contains built-in default values for credentials, wallet, and region. These are example placeholders only and must not be used in production.

Always call `pkg_aws_s3.init(...)` with real values before making requests.

### Initialization

```sql
begin
	pkg_aws_s3.init(
		p_acess_key_id      => 'YOUR_ACCESS_KEY_ID',
		p_secrec_acess_key  => 'YOUR_SECRET_ACCESS_KEY',
		p_wallet_path       => 'file:/path/to/oracle/wallet',
		p_wallet_password   => 'YOUR_WALLET_PASSWORD',
		p_region            => 'us-east-1'
	);
end;
/
```

Parameters:

- `p_acess_key_id`: AWS access key ID
- `p_secrec_acess_key`: AWS secret access key
- `p_wallet_path`: Oracle wallet path used by `UTL_HTTP`
- `p_wallet_password`: Oracle wallet password
- `p_region`: AWS region for the target bucket

The package also exposes individual setters and getters:

- `set_acess_key_id` / `get_acess_key_id`
- `set_secrec_acess_key` / `get_secrec_acess_key`
- `set_wallet_path` / `get_wallet_path`
- `set_wallet_password` / `get_wallet_password`
- `set_region` / `get_region`

## Public API

### Constants

Available S3 storage class constants:

- `pkg_aws_s3.G_STANDARD`
- `pkg_aws_s3.G_STANDARD_IA`
- `pkg_aws_s3.G_INTELLIGENT_TIERING`
- `pkg_aws_s3.G_ONEZONE_IA`
- `pkg_aws_s3.G_GLACIER`
- `pkg_aws_s3.G_RRS`

### Upload an Object

```sql
procedure put_object(
	p_bucketname    varchar2,
	p_objectname    varchar2,
	p_blob          in blob,
	p_storage_class in varchar2 default null,
	p_content_type  in varchar2 default null,
	p_tags          in varchar2 default null);
```

Behavior:

- Uploads a `BLOB` to S3 using `PUT Object`
- Sends `Content-MD5`
- Sends `x-amz-content-sha256`
- Uses `application/octet-stream` when `p_content_type` is null
- Uses `STANDARD` when `p_storage_class` is null
- Optionally sends the `x-amz-tagging` header when `p_tags` is provided

Notes:

- `p_tags` must be sent in S3 header format, for example `key1=value1&key2=value2`
- The package URL-encodes the object path while preserving path separators

Example:

```sql
declare
	l_blob blob;
begin
	select ds
	  into l_blob
	  from test_blob_origin;

	pkg_aws_s3.init(
		p_acess_key_id      => 'YOUR_ACCESS_KEY_ID',
		p_secrec_acess_key  => 'YOUR_SECRET_ACCESS_KEY',
		p_wallet_path       => 'file:/path/to/oracle/wallet',
		p_wallet_password   => 'YOUR_WALLET_PASSWORD',
		p_region            => 'us-east-1');

	pkg_aws_s3.put_object(
		p_bucketname    => 'my-bucket',
		p_objectname    => 'documents/report.pdf',
		p_blob          => l_blob,
		p_storage_class => pkg_aws_s3.g_standard,
		p_content_type  => 'application/pdf',
		p_tags          => 'tag01=info01&tag02=info02');
end;
/
```

### Download an Object

```sql
function get_object(
	p_bucketname varchar2,
	p_objectname varchar2)
	return blob;
```

Behavior:

- Downloads an S3 object using `GET Object`
- Returns the object body as a `BLOB`

Example:

```sql
declare
	l_blob blob;
begin
	pkg_aws_s3.init(
		p_acess_key_id      => 'YOUR_ACCESS_KEY_ID',
		p_secrec_acess_key  => 'YOUR_SECRET_ACCESS_KEY',
		p_wallet_path       => 'file:/path/to/oracle/wallet',
		p_wallet_password   => 'YOUR_WALLET_PASSWORD',
		p_region            => 'us-east-1');

	l_blob := pkg_aws_s3.get_object(
		p_bucketname => 'my-bucket',
		p_objectname => 'documents/report.pdf');

	insert into test_blob_return values (l_blob);
	commit;
end;
/
```

### Update Object Tags

```sql
procedure put_object_tagging(
	p_bucketname varchar2,
	p_objectname varchar2,
	p_tags       clob);
```

Behavior:

- Calls the S3 `?tagging` endpoint
- Sends the tagging payload as XML in a `CLOB`

Expected payload format:

```xml
<Tagging>
  <TagSet>
	<Tag>
	  <Key>tag1</Key>
	  <Value>value1</Value>
	</Tag>
	<Tag>
	  <Key>tag2</Key>
	  <Value>value2</Value>
	</Tag>
  </TagSet>
</Tagging>
```

Example:

```sql
declare
	l_tags clob;
begin
	pkg_aws_s3.init(
		p_acess_key_id      => 'YOUR_ACCESS_KEY_ID',
		p_secrec_acess_key  => 'YOUR_SECRET_ACCESS_KEY',
		p_wallet_path       => 'file:/path/to/oracle/wallet',
		p_wallet_password   => 'YOUR_WALLET_PASSWORD',
		p_region            => 'us-east-1');

	l_tags := '<Tagging><TagSet><Tag><Key>tag1</Key><Value>value1</Value></Tag><Tag><Key>tag2</Key><Value>value2</Value></Tag></TagSet></Tagging>';

	pkg_aws_s3.put_object_tagging(
		p_bucketname => 'my-bucket',
		p_objectname => 'documents/report.pdf',
		p_tags       => l_tags);
end;
/
```

### Read Object Tags

```sql
function get_object_tagging(
	p_bucketname varchar2,
	p_objectname varchar2)
	return clob;
```

Behavior:

- Calls the S3 `?tagging` endpoint
- Returns the S3 XML response as a `CLOB`

Example:

```sql
declare
	l_tags clob;
begin
	pkg_aws_s3.init(
		p_acess_key_id      => 'YOUR_ACCESS_KEY_ID',
		p_secrec_acess_key  => 'YOUR_SECRET_ACCESS_KEY',
		p_wallet_path       => 'file:/path/to/oracle/wallet',
		p_wallet_password   => 'YOUR_WALLET_PASSWORD',
		p_region            => 'us-east-1');

	l_tags := pkg_aws_s3.get_object_tagging(
		p_bucketname => 'my-bucket',
		p_objectname => 'documents/report.pdf');

	insert into test_clob_return values (l_tags);
	commit;
end;
/
```

## Error Handling

When S3 returns an error response, the package raises:

```sql
raise_application_error(-20000, ...)
```

The detailed response is also stored internally and can be retrieved with:

```sql
pkg_aws_s3.get_error_detail
```

The returned record contains:

- HTTP version
- HTTP status code
- Reason phrase
- Response headers
- AWS error code
- AWS error message
- XML body when parseable
- Raw response body as `CLOB`

Example pattern:

```sql
declare
	l_error pkg_aws_s3.r_error;
begin
	begin
		pkg_aws_s3.put_object(
			p_bucketname => 'my-bucket',
			p_objectname => 'documents/report.pdf',
			p_blob       => empty_blob());
	exception
		when others then
			if sqlcode = -20000 then
				l_error := pkg_aws_s3.get_error_detail();
				dbms_output.put_line(l_error.http_version);
				dbms_output.put_line(l_error.status_code);
				dbms_output.put_line(l_error.reason_phrase);
				dbms_output.put_line(l_error.code);
				dbms_output.put_line(l_error.message);
				dbms_output.put_line(l_error.clobdata);
			end if;
			raise;
	end;
end;
/
```

## Demo Script

`demo_pkg_aws_s3.sql` contains complete examples for:

- `put_object`
- `get_object`
- `put_object_tagging`
- `get_object_tagging`

The demo assumes helper tables such as `test_blob_origin`, `test_blob_return`, and `test_clob_return`.

## Operational Notes

- The package currently targets object upload, download, and tagging only.
- It uses virtual-hosted-style S3 endpoints such as `bucket.s3.region.amazonaws.com`.
- For `us-east-1`, the host is generated as `bucket.s3.amazonaws.com`.
- Credentials are stored in package globals for the current database session.
- Because it depends on `UTL_HTTP`, correct wallet and ACL configuration is mandatory.

## Limitations

This package is intentionally small and does not currently implement the full S3 API. For example, it does not include:

- Bucket creation or deletion
- Object deletion
- Multipart upload
- Pre-signed URLs
- Temporary session token support
- Metadata management beyond the currently implemented headers

## License

This project is licensed under the MIT License. See `LICENSE` for details.
