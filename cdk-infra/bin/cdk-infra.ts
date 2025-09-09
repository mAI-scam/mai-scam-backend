#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { CdkInfraStack } from '../lib/cdk-infra-stack';

const app = new cdk.App();
new CdkInfraStack(app, 'MaiScamApiStack', {
  env: { account: '975063318763', region: 'us-east-1' },
});