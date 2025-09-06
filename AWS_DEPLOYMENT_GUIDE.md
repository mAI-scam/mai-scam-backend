# AWS Deployment Guide for MAI Scam Detection Backend

This guide explains how to set up persistent AWS credentials for your deployed backend on Render.

## Problem
The current error occurs because you're using temporary AWS SSO credentials that expire:
```
ExpiredTokenException: The security token included in the request is expired
```

## Solution: Use IAM User with Permanent Access Keys

### Step 1: Create IAM User

1. **Go to AWS Console > IAM > Users**
2. **Click "Create User"**
   - User name: `mai-scam-backend-render`
   - Select "Provide user access to the AWS Management Console": **NO** (this is for programmatic access only)

3. **Set Permissions**
   - Choose "Attach policies directly"
   - Add these policies:
     - `AmazonDynamoDBFullAccess`
     - `AmazonS3FullAccess`
   - Or create a custom policy with minimal permissions:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Action": [
             "dynamodb:PutItem",
             "dynamodb:GetItem",
             "dynamodb:Query",
             "dynamodb:Scan",
             "dynamodb:UpdateItem"
           ],
           "Resource": "arn:aws:dynamodb:us-east-1:*:table/mai-scam-detection-results"
         },
         {
           "Effect": "Allow",
           "Action": [
             "s3:PutObject",
             "s3:GetObject",
             "s3:DeleteObject"
           ],
           "Resource": "arn:aws:s3:::mai-scam-detected-images/*"
         }
       ]
     }
     ```

4. **Review and Create User**

### Step 2: Generate Access Keys

1. **Click on the created user**
2. **Go to "Security credentials" tab**
3. **Click "Create access key"**
4. **Select use case: "Application running outside AWS"**
5. **Add description tag**: "Render deployment keys for mai-scam-backend"
6. **Create access key**
7. **IMPORTANT**: Download the CSV file or copy both:
   - Access Key ID (starts with `AKIA...`)
   - Secret Access Key (long random string)

### Step 3: Update Render Environment Variables

In your Render dashboard:

1. **Go to your service settings**
2. **Environment tab**
3. **Update/Add these variables**:
   ```
   AWS_ACCESS_KEY_ID=AKIA...your_access_key_id
   AWS_SECRET_ACCESS_KEY=your_secret_access_key_here
   AWS_REGION=us-east-1
   ```
4. **REMOVE or COMMENT OUT**:
   ```
   AWS_SESSION_TOKEN=  # Remove this completely
   ```

### Step 4: Redeploy

1. **Trigger a new deployment** in Render
2. **Check logs** to ensure no more `ExpiredTokenException` errors

## Alternative: Environment-Based Credential Management

Your updated code now handles both scenarios:
- **Development**: Uses SSO credentials with `AWS_SESSION_TOKEN`
- **Production**: Uses IAM user credentials without session token

## Security Best Practices

1. **Principle of Least Privilege**: Only grant necessary permissions
2. **Rotate Keys**: Regularly rotate access keys (every 90 days)
3. **Monitor Usage**: Enable CloudTrail to monitor API usage
4. **Environment Separation**: Use different IAM users for dev/staging/prod

## Troubleshooting

### Error: "The security token included in the request is expired"
- **Cause**: Using temporary SSO credentials
- **Solution**: Switch to IAM user access keys

### Error: "Unable to locate credentials"
- **Cause**: Missing AWS environment variables
- **Solution**: Ensure `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set

### Error: "Access Denied"
- **Cause**: Insufficient IAM permissions
- **Solution**: Add required DynamoDB and S3 policies to the IAM user

## Cost Monitoring

Monitor your AWS usage to avoid unexpected charges:
1. **Set up billing alerts** in AWS Console
2. **Enable Cost Explorer**
3. **Set DynamoDB and S3 usage limits** if needed

## Local Development

For local development, you can continue using SSO:
```bash
# Configure SSO (one-time setup)
aws configure sso
# SSO start URL: https://d-906633d9d4.awsapps.com/start/#
# SSO Region: us-east-1

# Login before development
aws sso login --profile your-profile-name
```

The updated code will automatically handle both credential types.