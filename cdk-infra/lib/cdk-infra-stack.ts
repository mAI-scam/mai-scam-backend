import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { ManagedPolicy } from 'aws-cdk-lib/aws-iam';

export class CdkInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Function to handle the API requests.
    const apiFunction = new lambda.DockerImageFunction(this, 'ApiFunc', {
      code: lambda.DockerImageCode.fromImageAsset('..', {
        exclude: ['cdk-infra', '.git', '.gitignore', 'venv', '__pycache__', '*.pyc', '.DS_Store']
      }),
      memorySize: 2048,
      timeout: cdk.Duration.seconds(300),
      architecture: lambda.Architecture.ARM_64,
      environment: {
        APP_ENV: 'production',
        SEA_LION_API_KEY: process.env.SEA_LION_API_KEY || '',
        VALIDATION_API_KEY: process.env.VALIDATION_API_KEY || '',
        SAGEMAKER_ENDPOINT_NAME: process.env.SAGEMAKER_ENDPOINT_NAME || '',
        SMTP_USERNAME: process.env.SMTP_USERNAME || '',
        SMTP_PASSWORD: process.env.SMTP_PASSWORD || '',
        SMTP_HOST: process.env.SMTP_HOST || '',
        SMTP_PORT: process.env.SMTP_PORT || '',
        SMTP_USE_TLS: process.env.SMTP_USE_TLS || '',
        SMTP_SENDER_NAME: process.env.SMTP_SENDER_NAME || '',
        REPORT_EMAIL: process.env.REPORT_EMAIL || '',
      },
    });

    // Public URL for the API function.
    const functionUrl = apiFunction.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
    });

    // Grant permissions for all resources to work together.
    apiFunction.role?.addManagedPolicy(
      ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
    );
    apiFunction.role?.addManagedPolicy(
      ManagedPolicy.fromAwsManagedPolicyName('AmazonSageMakerFullAccess')
    );
    apiFunction.role?.addManagedPolicy(
      ManagedPolicy.fromAwsManagedPolicyName('AmazonDynamoDBFullAccess')
    );
    apiFunction.role?.addManagedPolicy(
      ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess')
    );

    // Output the URL for the API function.
    new cdk.CfnOutput(this, 'FunctionUrl', {
      value: functionUrl.url,
    });
  }
}
