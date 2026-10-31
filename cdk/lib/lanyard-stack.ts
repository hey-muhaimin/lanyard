import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as cloudfront_origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';

export class LanyardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // VPC (use default)
    const vpc = ec2.Vpc.fromLookup(this, 'DefaultVPC', { isDefault: true });

    // ECR repository for controlplane image
    const repo = new ecr.Repository(this, 'LanyardRepo', {
      repositoryName: 'lanyard-controlplane',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      lifecycleRules: [{ maxImageCount: 10 }],
    });

    // Secrets for DB URL and token signing key (placeholders)
    const dbSecret = new secretsmanager.Secret(this, 'DbSecret', {
      secretName: 'lanyard-db-url',
      description: 'Postgres connection URL for Lanyard',
      generateSecretString: { secretStringTemplate: JSON.stringify({}), generateStringKey: 'url' },
    });
    const tokenSecret = new secretsmanager.Secret(this, 'TokenSecret', {
      secretName: 'lanyard-token-key',
      description: 'Ed25519 private key for token signing',
    });

    // ECS Cluster & Task Definition (Fargate)
    const cluster = new ecs.Cluster(this, 'LanyardCluster', { vpc });
    const taskDef = new ecs.FargateTaskDefinition(this, 'LanyardTask', {
      cpu: 512,
      memoryLimitMiB: 1024,
    });
    const container = taskDef.addContainer('ControlPlane', {
      image: ecs.ContainerImage.fromEcrRepository(repo, 'latest'),
      logging: ecs.LogDriver.awsLogs({ streamPrefix: 'Lanyard', logGroup: new logs.LogGroup(this, 'LanyardLogGroup') }),
      environment: {
        // Required env vars – values are pulled from Secrets below
        DATABASE_SECRET_ARN: dbSecret.secretArn,
        TOKEN_PRIVATE_KEY_SECRET_ARN: tokenSecret.secretArn,
        ALLOW_INSECURE_DEMO: 'false',
        // generate a UUID for tenant (you can replace with real)
        TENANT_ID: '00000000-0000-0000-0000-000000000001',
        PUBLIC_BASE_URL: 'https://example.com', // will be replaced by CloudFront domain later
      },
    });
    // Grant task to read the secrets
    dbSecret.grantRead(taskDef.taskRole);
    tokenSecret.grantRead(taskDef.taskRole);

    // ALB fronting the ECS service (required for CloudFront custom origin)
    const lb = new elbv2.ApplicationLoadBalancer(this, 'LanyardLB', {
      vpc,
      internetFacing: true,
      loadBalancerName: 'lanyard-alb',
    });
    const listener = lb.addListener('HttpListener', { port: 80, open: true });
    const service = new ecs.FargateService(this, 'LanyardService', {
      cluster,
      taskDefinition: taskDef,
      assignPublicIp: true,
      desiredCount: 1,
      securityGroups: [new ec2.SecurityGroup(this, 'LanyardSG', { vpc, allowAllOutbound: true })],
    });
    listener.addTargets('EcsTargets', {
      port: 8080,
      targets: [service],
      healthCheck: { path: '/healthz', interval: cdk.Duration.seconds(30) },
    });

    // S3 bucket for static assets (console + ops)
    const bucket = new s3.Bucket(this, 'LanyardStatic', {
      bucketName: 'lanyard-static-assets',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });
    // Deploy console static files
    new s3deploy.BucketDeployment(this, 'DeployConsole', {
      sources: [s3deploy.Source.asset('web/console/out')],
      destinationBucket: bucket,
      destinationKeyPrefix: 'console/',
    });
    // Deploy ops static files
    new s3deploy.BucketDeployment(this, 'DeployOps', {
      sources: [s3deploy.Source.asset('web/ops/out')],
      destinationBucket: bucket,
      destinationKeyPrefix: 'ops/',
    });

    // CloudFront OAI for secure S3 access
    const oai = new cloudfront.OriginAccessIdentity(this, 'LanyardOAI');
    bucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: ['s3:GetObject'],
      resources: [bucket.arnForObjects('*')],
      principals: [new iam.CanonicalUserPrincipal(oai.cloudFrontOriginAccessIdentityS3CanonicalUserId)],
    }));

    // CloudFront distribution with two origins
    const distribution = new cloudfront.Distribution(this, 'LanyardDistribution', {
      defaultBehavior: {
        origin: new cloudfront_origins.S3Origin(bucket, { originPath: '/console', originAccessIdentity: oai }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      },
      additionalBehaviors: {
        // API routes go to the ALB
        '/ops/*': {
          origin: new cloudfront_origins.LoadBalancerV2Origin(lb, { protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY }),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        },
        // Ops static assets (if you ever need a separate prefix)
        '/ops/': {
          origin: new cloudfront_origins.S3Origin(bucket, { originPath: '/ops', originAccessIdentity: oai }),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
          cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        },
      },
    });

    // Output values for CI/CD
    new cdk.CfnOutput(this, 'DistributionDomain', { value: distribution.distributionDomainName });
    new cdk.CfnOutput(this, 'EcrRepositoryUri', { value: repo.repositoryUri });
    new cdk.CfnOutput(this, 'StaticBucketName', { value: bucket.bucketName });
  }
}
