/*
 * Copyright Amazon.com, Inc. or its affiliates, and Project Contributors.
 * All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Derived from https://github.com/acm19/aws-request-signing-apache-interceptor/blob/v2.0.1/src/main/java/io/github/acm19/aws/interceptor/http/AwsRequestSigningApacheInterceptor.java

package org.opensearch.kafka.connect.opensearch.sigv4;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.http.Header;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.signer.AwsSignerExecutionAttribute;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.signer.Signer;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;

public class AwsSigV4SigningInterceptor implements HttpRequestInterceptor {
    /**
     * The service that we're connecting to.
     */
    private final String service;

    /**
     * The particular signer implementation.
     */
    private final Signer signer;

    /**
     * The source of AWS credentials for signing.
     */
    private final AwsCredentialsProvider awsCredentialsProvider;

    /**
     * The signing region.
     */
    private final Region region;

    /**
     * Whether to skip signing the Content-Length headers and leave them as is
     */
    private boolean skipContentLengthSigning; 
         
    /**
     *
     * @param service service that we're connecting to
     * @param signer particular signer implementation
     * @param awsCredentialsProvider source of AWS credentials for signing
     * @param region signing region
     */
    public AwsSigV4SigningInterceptor(final String service,
                                      final Signer signer,
                                      final AwsCredentialsProvider awsCredentialsProvider,
                                      final Region region) {
        this.service = service;
        this.signer = signer;
        this.awsCredentialsProvider = awsCredentialsProvider;
        this.region = Objects.requireNonNull(region);
        this.skipContentLengthSigning = false;
    }

    /**
     *
     * @param service service that we're connecting to
     * @param signer particular signer implementation
     * @param awsCredentialsProvider source of AWS credentials for signing
     * @param region signing region
     */
    public AwsSigV4SigningInterceptor(final String service,
                                      final Signer signer,
                                      final AwsCredentialsProvider awsCredentialsProvider,
                                      final String region) {
        this(service, signer, awsCredentialsProvider, Region.of(region));
    }

    /**
     * Skip signing the Content-Length and pass the original headers
     */
    public void skipContentLengthSigning() { 
        this.skipContentLengthSigning = true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void process(final HttpRequest request, final HttpContext context)
            throws HttpException, IOException {
        final URIBuilder uriBuilder;
        try {
            uriBuilder = new URIBuilder(request.getRequestLine().getUri());
        } catch (final URISyntaxException e) {
            throw new IOException("Invalid URI", e);
        }

        // Copy Apache HttpRequest to AWS Request
        final SdkHttpFullRequest.Builder requestBuilder = SdkHttpFullRequest.builder()
            .method(SdkHttpMethod.fromValue(request.getRequestLine().getMethod()))
            .uri(buildUri(context, uriBuilder));

        if (request instanceof HttpEntityEnclosingRequest) {
            final HttpEntityEnclosingRequest httpEntityEnclosingRequest =
                (HttpEntityEnclosingRequest) request;
            if (httpEntityEnclosingRequest.getEntity() != null) {
                final InputStream content = httpEntityEnclosingRequest.getEntity().getContent();
                requestBuilder.contentStreamProvider(() -> content);
            }
        }
        requestBuilder.rawQueryParameters(nvpToMapParams(uriBuilder.getQueryParams()));
        requestBuilder.headers(headerArrayToMap(request.getAllHeaders(), skipContentLengthSigning));

        final ExecutionAttributes attributes = new ExecutionAttributes();
        attributes.putAttribute(AwsSignerExecutionAttribute.AWS_CREDENTIALS,
            awsCredentialsProvider.resolveCredentials());
        attributes.putAttribute(AwsSignerExecutionAttribute.SERVICE_SIGNING_NAME, service);
        attributes.putAttribute(AwsSignerExecutionAttribute.SIGNING_REGION, region);

        // Sign it
        final SdkHttpFullRequest signedRequest = signer.sign(requestBuilder.build(), attributes);

        // Now copy everything back
        if (!skipContentLengthSigning) {
            request.setHeaders(mapToHeaderArray(signedRequest.headers()));    
        } else {
            // But keep the content-length header from the original request
            final Header[] headers = request.getHeaders(HTTP.CONTENT_LEN);
            request.setHeaders(mapToHeaderArray(signedRequest.headers()));
            if (headers != null) {
                Arrays.stream(headers)
                    .filter(h -> !"0".equals(h.getValue()))
                    .forEach(h -> request.addHeader(h));
            }
        }
        
        if (request instanceof HttpEntityEnclosingRequest) {
            final HttpEntityEnclosingRequest httpEntityEnclosingRequest =
                (HttpEntityEnclosingRequest) request;
            if (httpEntityEnclosingRequest.getEntity() != null) {
                final BasicHttpEntity basicHttpEntity = new BasicHttpEntity();
                basicHttpEntity.setContent(signedRequest.contentStreamProvider()
                    .orElseThrow(() -> new IllegalStateException("There must be content"))
                    .newStream());
                httpEntityEnclosingRequest.setEntity(basicHttpEntity);
            }
        }
    }

    /**
     * Returns an URI from an HTTP context.
     *
     * @param context HTTP context
     * @param uriBuilder URI builder
     * @return URI
     * @throws IOException Invalid URI
     */
    private URI buildUri(final HttpContext context, final URIBuilder uriBuilder) throws IOException {
        try {
            final HttpHost host = (HttpHost) context.getAttribute(HttpCoreContext.HTTP_TARGET_HOST);

            if (host != null) {
                uriBuilder.setHost(host.getHostName());
                uriBuilder.setScheme(host.getSchemeName());
                uriBuilder.setPort(host.getPort());
            }

            return uriBuilder.build();
        } catch (final URISyntaxException e) {
            throw new IOException("Invalid URI", e);
        }
    }

    /**
     * @param params list of HTTP query params as NameValuePairs
     * @return multimap of HTTP query params
     */
    private static Map<String, List<String>> nvpToMapParams(final List<NameValuePair> params) {
        final Map<String, List<String>> parameterMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (final NameValuePair nvp : params) {
            final List<String> argsList =
                parameterMap.computeIfAbsent(nvp.getName(), k -> new ArrayList<>());
            argsList.add(nvp.getValue());
        }
        return parameterMap;
    }

    /**
     * @param headers modeled Header objects
     * @return a Map of header entries
     */
    private static Map<String, List<String>> headerArrayToMap(final Header[] headers,
                                                              final boolean skipContentLength) {
        final Map<String, List<String>> headersMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (final Header header : headers) {
            if (!skipHeader(header, skipContentLength)) {
                headersMap.put(header.getName(), headersMap
                    .getOrDefault(header.getName(),
                        new LinkedList<>(Collections.singletonList(header.getValue()))));
            }
        }
        return headersMap;
    }

    /**
     * @param header header line to check
     * @return true if the given header should be excluded when signing
     */
    private static boolean skipHeader(final Header header, final boolean skipContentLength) {
        return HTTP.CONTENT_LEN.equalsIgnoreCase(header.getName()) 
            && ("0".equals(header.getValue()) || skipContentLength)
            || HTTP.TARGET_HOST.equalsIgnoreCase(header.getName()); // Host comes from endpoint
    }

    /**
     * @param mapHeaders Map of header entries
     * @return modeled Header objects
     */
    private static Header[] mapToHeaderArray(final Map<String, List<String>> mapHeaders) {
        final Header[] headers = new Header[mapHeaders.size()];
        int i = 0;
        for (final Map.Entry<String, List<String>> headerEntry : mapHeaders.entrySet()) {
            for (final String value : headerEntry.getValue()) {
                headers[i++] = new BasicHeader(headerEntry.getKey(), value);
            }
        }
        return headers;
    }
}
