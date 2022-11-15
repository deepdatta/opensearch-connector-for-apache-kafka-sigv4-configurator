# OpenSearch® Connector for Apache Kafka® SigV4 Configurator

This repository provides a Configurator plugin for [aiven/opensearch-connector-for-apache-kafka](https://github.com/aiven/opensearch-connector-for-apache-kafka) to add [SigV4 Signing](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) capability. This would allow connections to OpenSearch Clusters that use IAM authentication.

## Documentation
* [OpenSearch® Sink Connector Configuration Options for SigV4](docs/config-options.rst)
* [Kafka Connect Documentation](https://kafka.apache.org/documentation/#connect)
* [Kafka Connect Quickstart](https://kafka.apache.org/quickstart#quickstart_kafkaconnect)

## Installation
Unpack the content of the `opensearch-connector-for-apache-kafka-sigv4-<VERSION>.tar` or `.zip` archive into the same plugin folder containing the jars for `aiven/opensearch-connector-for-apache-kafka`

## License

The project is licensed under the [Apache 2 license](https://www.apache.org/licenses/LICENSE-2.0).
See [LICENSE](LICENSE).