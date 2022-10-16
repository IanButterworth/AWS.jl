function sign!(aws::AbstractAWSConfig, request::Request; time::DateTime=now(Dates.UTC))
    if request.service in ("sdb", "importexport")
        sign_aws2!(aws, request, time)
    else
        sign_aws4!(aws, request, time)
    end
end

function sign_aws2!(aws::AbstractAWSConfig, request::Request, time::DateTime)
    # Create AWS Signature Version 2 Authentication query parameters.
    # http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html

    query = Dict{String,String}()
    for elem in split(request.content, '&'; keepempty=false)
        (n, v) = split(elem, "=")
        query[n] = HTTP.unescapeuri(v)
    end

    request.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"

    creds = check_credentials(credentials(aws))
    query["AWSAccessKeyId"] = creds.access_key_id
    query["Expires"] = Dates.format(
        time + Dates.Minute(2), dateformat"yyyy-mm-dd\THH:MM:SS\Z"
    )
    query["SignatureVersion"] = "2"
    query["SignatureMethod"] = "HmacSHA256"

    if !isempty(creds.token)
        query["SecurityToken"] = creds.token
    end

    query = [k => query[k] for k in sort!(collect(keys(query)))]
    uri = HTTP.URI(request.url)
    to_sign = "POST\n$(uri.host)\n$(uri.path)\n$(HTTP.escapeuri(query))"
    push!(
        query,
        "Signature" => strip(base64encode(digest(MD_SHA256, to_sign, creds.secret_key))),
    )

    request.content = HTTP.escapeuri(query)

    return request
end

using InteractiveUtils

function sign_aws4!(aws::AbstractAWSConfig, request::Request, time::DateTime)
    # Create AWS Signature Version 4 Authentication Headers.
    # http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

    date = Dates.format(time, dateformat"yyyymmdd")
    datetime = Dates.format(time, dateformat"yyyymmdd\THHMMSS\Z")

    # Authentication scope...
    authentication_scope = [date, region(aws), request.service, "aws4_request"]

    creds = check_credentials(credentials(aws))
    signing_key = "AWS4$(creds.secret_key)"

    for scope in authentication_scope
        signing_key = digest(MD_SHA256, scope, signing_key)
    end

    # Authentication scope string...
    authentication_scope = join(authentication_scope, "/")

    # SHA256 hash of content...
    content_hash = bytes2hex(digest(MD_SHA256, request.content))

    # HTTP headers...
    delete!(request.headers, "Authorization")

    content_digested = digest(MD_MD5, request.content)

    # @info "base64encode called" MD_MD5 repr(MD_MD5) request.content repr(request.content) repr(content_digested)

    # fixed_content = UInt8[0x56, 0x94, 0xd0, 0x82, 0x60, 0xc3, 0x68, 0xe3, 0xac, 0x4a, 0x97, 0xc5, 0x24, 0xdb, 0xbf, 0x3e]
    # @show @code_native base64encode(fixed_content)


    s = IOBuffer()
    b = Base64.Base64EncodePipe(s)
    # write(b, fixed_content)

    # close --
    # @show b.buffer.size
    # @show b1 = b.buffer[1]
    # @show k = 1
    # @show empty!(b.buffer)
    write(s, UInt8('='), UInt8('='), UInt8('='), UInt8('='))
    # @show write(b.io, Base64.encode(b1 >> 2), Base64.encode(b1 << 4), UInt8('='), UInt8('='))
    # @show String(take!(s))
    # end close --

    # @info "done"


    # @show base64encode(fixed_content)

    merge!(
        request.headers,
        Dict(
            "x-amz-content-sha256" => content_hash,
            "x-amz-date" => datetime,
            "Content-MD5" => base64encode(content_digested),
        ),
    )

    if !isempty(creds.token)
        request.headers["x-amz-security-token"] = creds.token
    end

    # Sort and lowercase() Headers to produce canonical form...
    canonical_headers = join(
        sort!(["$(lowercase(k)):$(strip(v))" for (k, v) in request.headers]), "\n"
    )
    signed_headers = join(sort!([lowercase(k) for k in keys(request.headers)]), ";")

    # Sort Query String...
    uri = HTTP.URI(request.url)
    query = HTTP.URIs.queryparams(uri.query)
    query = [k => query[k] for k in sort!(collect(keys(query)))]

    # Create hash of canonical request...
    canonical_form = string(
        request.request_method,
        "\n",
        request.service == "s3" ? uri.path : HTTP.escapepath(uri.path),
        "\n",
        HTTP.escapeuri(query),
        "\n",
        canonical_headers,
        "\n\n",
        signed_headers,
        "\n",
        content_hash,
    )

    canonical_hash = bytes2hex(digest(MD_SHA256, canonical_form))

    # Create and sign "String to Sign"...
    string_to_sign = "AWS4-HMAC-SHA256\n$datetime\n$authentication_scope\n$canonical_hash"
    signature = bytes2hex(digest(MD_SHA256, string_to_sign, signing_key))

    # Append Authorization header...
    request.headers["Authorization"] = join(
        [
            "AWS4-HMAC-SHA256 Credential=$(creds.access_key_id)/$authentication_scope",
            "SignedHeaders=$signed_headers",
            "Signature=$signature",
        ],
        ", ",
    )

    return request
end
