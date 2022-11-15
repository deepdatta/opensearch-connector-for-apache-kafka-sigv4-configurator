=========================================
AWS SigV4 Configuration Options
=========================================

AWS
^^^

``connection.auth.type``
  The default is 'basic' and uses the connection.username and connection.password. With 'aws.iam' it uses SigV4 signing requiring connection.region and optionally connection.service configs and looks for credentials in this order.

  1. Java System Properties - aws.accessKeyId and aws.secretAccessKey.

  2. Environment Variables - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.

  3. Web Identity Token credentials from system properties or environment variables.

  4. Credential profiles file at the default location (~/.aws/credentials) shared by all AWS SDKs and the AWS CLI.

  5. Credentials delivered through the Amazon EC2 container service if AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable is set and security manager has permission to access the variable.

  6. Instance profile credentials delivered through the Amazon EC2 metadata service.

  * Type: string
  * Default: basic
  * Importance: medium

``connection.auth.aws.iam.region``
  Needed only when connection.auth.type == 'aws.iam' to specify the service region for SigV4 signing, e.g. 'us-east-1'.

  * Type: string
  * Default: null
  * Importance: medium

``connection.auth.aws.iam.service``
  Needed only when connection.auth.type == 'aws.iam' to specify the service name for SigV4 signing. The default is 'es'

  * Type: string
  * Default: es
  * Importance: medium


