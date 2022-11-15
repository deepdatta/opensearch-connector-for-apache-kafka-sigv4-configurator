package org.opensearch.kafka.connect.opensearch.sigv4;

import java.util.Objects;

import org.apache.kafka.common.config.ConfigDef;
import org.apache.kafka.common.config.ConfigDef.Importance;
import org.apache.kafka.common.config.ConfigDef.Type;
import org.apache.kafka.common.config.ConfigDef.Width;

import io.aiven.kafka.connect.opensearch.spi.ConfigDefContributor;
import io.aiven.kafka.connect.opensearch.spi.OpensearchClientConfigurator;
import io.aiven.kafka.connect.opensearch.OpensearchSinkConnectorConfig;

import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4UnsignedPayloadSigner;

public class AwsSigV4SigningConfigurator implements OpensearchClientConfigurator, ConfigDefContributor {

    private static final Logger log = LoggerFactory.getLogger(AwsSigV4SigningConfigurator.class);

    protected static final String CONNECTION_AUTH_BASIC = "basic";
    protected static final String CONNECTION_AUTH_AWS_IAM = "aws.iam";

    public static final String CONNECTION_AUTH_TYPE_CONFIG = "connection.auth.type";
    public static final String CONNECTION_AUTH_TYPE_DOC =
            "The default is 'basic' and uses the connection.username and connection.password."
                    + " With 'aws.iam' it uses SigV4 signing requiring connection.region and optionally"
                    + " connection.service configs and looks for credentials in this order.\n"
                    + "1. Java System Properties - aws.accessKeyId and aws.secretAccessKey.\n"
                    + "2. Environment Variables - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.\n"
                    + "3. Web Identity Token credentials from system properties or environment variables.\n"
                    + "4. Credential profiles file at the default location (~/.aws/credentials) shared by all AWS SDKs"
                    + " and the AWS CLI.\n"
                    + "5. Credentials delivered through the Amazon EC2 container service if"
                    + " AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable is set and security manager"
                    + " has permission to access the variable.\n"
                    + "6. Instance profile credentials delivered through the Amazon EC2 metadata service.";
    public static final String CONNECTION_AUTH_AWS_REGION_CONFIG = "connection.auth.aws.iam.region";
    private static final String CONNECTION_AUTH_AWS_REGION_DOC =
            "Needed only when connection.auth.type == 'aws.iam' to specify the service region for"
                    + " SigV4 signing, e.g. 'us-east-1'.";
    public static final String CONNECTION_AUTH_AWS_SERVICE_CONFIG = "connection.auth.aws.iam.service";
    private static final String CONNECTION_AUTH_AWS_SERVICE_DOC =
        "Needed only when connection.auth.type == 'aws.iam' to specify the service name for"
                    + " SigV4 signing. The default is 'es'";

    @Override
    public void addConfig(final ConfigDef config) {
        config.define(
            CONNECTION_AUTH_TYPE_CONFIG,
            Type.STRING,
            CONNECTION_AUTH_BASIC,
            Importance.MEDIUM,
            CONNECTION_AUTH_TYPE_DOC,
            "AWS",
            0,
            Width.SHORT,
            "Connection Auth Type"
        ).define(
            CONNECTION_AUTH_AWS_REGION_CONFIG,
            Type.STRING,
            null,
            Importance.MEDIUM,
            CONNECTION_AUTH_AWS_REGION_DOC,
            "AWS",
            1,
            Width.SHORT,
            "Connection Region"
        ).define(
            CONNECTION_AUTH_AWS_SERVICE_CONFIG,
            Type.STRING,
            "es",
            Importance.MEDIUM,
            CONNECTION_AUTH_AWS_SERVICE_DOC,
            "AWS",
            2,
            Width.SHORT,
            "Connection Auth AWS Service"
        );
    }

    @Override
    public boolean apply(final OpensearchSinkConnectorConfig config, final HttpAsyncClientBuilder builder) {
        if (isIamAuthenticatedConnection(config)) {
            final AwsSigV4SigningInterceptor interceptor = new AwsSigV4SigningInterceptor(
                    connectionService(config),
                    Aws4UnsignedPayloadSigner.create(),
                    DefaultCredentialsProvider.create(),
                    connectionRegion(config));
            interceptor.skipContentLengthSigning();
            builder.addInterceptorLast(interceptor);

            log.info("Using AWS SigV4 Authentication");
            return true;
        }

        return false;
    }

    static String connectionAuthType(final OpensearchSinkConnectorConfig config) {
        return config.getString(CONNECTION_AUTH_TYPE_CONFIG);
    }
    
    static String connectionRegion(final OpensearchSinkConnectorConfig config) {
        return config.getString(CONNECTION_AUTH_AWS_REGION_CONFIG);
    }
    
    static String connectionService(final OpensearchSinkConnectorConfig config) {
        return config.getString(CONNECTION_AUTH_AWS_SERVICE_CONFIG);
    }

    static boolean isIamAuthenticatedConnection(final OpensearchSinkConnectorConfig config) {
        return connectionAuthType(config).equals(CONNECTION_AUTH_AWS_IAM) 
                && Objects.nonNull(connectionRegion(config));
    }

    public static void main(final String[] args) {
        final ConfigDef tempConfig = new ConfigDef();
        final AwsSigV4SigningConfigurator configurator = new AwsSigV4SigningConfigurator();
        configurator.addConfig(tempConfig);
        System.out.println("=========================================");
        System.out.println("AWS SigV4 Configuration Options");
        System.out.println("=========================================");
        System.out.println();
        System.out.println(tempConfig.toEnrichedRst());
    }
}
