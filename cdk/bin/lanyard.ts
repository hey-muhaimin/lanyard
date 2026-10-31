#!/usr/bin/env node
import 'source-map-support/register';
import { App } from 'aws-cdk-lib';
import { LanyardStack } from '../lib/lanyard-stack';

const app = new App();
new LanyardStack(app, 'LanyardStack', {
  // You can pass context or env here if needed
});
app.synth();
