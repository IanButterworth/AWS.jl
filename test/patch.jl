module Patches

using AWS
using Dates
using HTTP
using JSON
using GitHub
using Mocking
using OrderedCollections: LittleDict

version = v"1.1.0"
status = 200
headers = Pair[
    "x-amz-id-2" => "x-amz-id-2",
    "x-amz-request-id" => "x-amz-request-id",
    "Date" => "Tue, 16 Jun 2020 21:29:18 GMT",
    "x-amz-bucket-region" => "us-east-1",
    "Content-Type" => "application/xml",
    "Transfer-Encoding" => "chunked",
    "Server" => "AmazonS3"
]

body = """
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">
        <Name>sample-bucket</Name>
        <Prefix></Prefix>
        <Marker></Marker>
        <MaxKeys>1000</MaxKeys>
        <IsTruncated>false</IsTruncated>
        <Contents>
            <Key>test.txt</Key>
            <LastModified>2020-06-16T21:37:34.000Z</LastModified>
            <ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>
            <Size>0</Size>
            <Owner>
                <ID>id</ID>
                <DisplayName>matt.brzezinski</DisplayName>
            </Owner>
            <StorageClass>STANDARD</StorageClass>
        </Contents>
    </ListBucketResult>
    """

response = HTTP.Messages.Response()

web_access_key = "web_identity_access_key"
web_secret_key = "web_identity_secret_key"
web_sesh_token = "web_session_token"

function _response!(; version::VersionNumber=version, status::Int64=status, headers::Array=headers, body::String=body)
    response.version = version
    response.status = status
    response.headers = headers
    response.body = Vector{UInt8}(body)

    return response
end

_aws_http_request_patch = @patch function AWS._http_request(request::Request)
    return response
end

_cred_file_patch = @patch function dot_aws_credentials_file()
    return ""
end

_config_file_patch = @patch function dot_aws_config_file()
    return ""
end

_web_identity_patch = @patch function AWS._http_request(request)
    creds = Dict(
        "AccessKeyId" => web_access_key, 
        "SecretAccessKey" => web_secret_key,
        "SessionToken" => web_sesh_token, 
        "Expiration" => string(now(UTC))
    )

    result = Dict("AssumeRoleWithWebIdentityResult" => Dict("Credentials" => creds))

    return HTTP.Response(200, ["Content-Type" => "text/json", "charset" => "utf-8"], body=json(result))
end

_github_tree_patch = @patch function tree(repo, tree_obj; kwargs...)
    if tree_obj == "master"
        return Tree("test-sha", HTTP.URI(), [Dict("path"=>"apis", "sha"=>"apis-sha")], false)
    else
        return Tree("test-sha", HTTP.URI(), [Dict("path"=>"test-2020-01-01.normal.json")], false)
    end
end

end