prowler_v3_checks_map = {
   "accessanalyzer_enabled": {
      "prowler_check_desc": "Check if IAM Access Analyzer is enabled",
      "aws_service": "accessanalyzer",
      "impact": "low",
      "scf_controls": [
         "IAC-17"
      ],
      "gdpr_articles": []
   },
   "accessanalyzer_enabled_without_findings": {
      "prowler_check_desc": "Check if IAM Access Analyzer is enabled without findings",
      "aws_service": "accessanalyzer",
      "impact": "low",
      "scf_controls": [
         "IAC-17"
      ],
      "gdpr_articles": []
   },
   "account_maintain_current_contact_details": {
      "prowler_check_desc": "Maintain current contact details.",
      "aws_service": "account",
      "impact": "medium",
      "scf_controls": [
         "GOV-06",
         "IAC-2.3"
      ],
      "gdpr_articles": [
         "Art 31",
         "Art 36.1",
         "Art 36.2",
         "Art 36.3",
         "Art 37.7",
         "Art 40.1",
         "Art 41.1",
         "Art 42.2",
         "Art 50"
      ]
   },
   "account_security_contact_information_is_registered": {
      "prowler_check_desc": "Ensure security contact information is registered.",
      "aws_service": "account",
      "impact": "medium",
      "scf_controls": [
         "IRO-14",
         "IAC-2.3"
      ],
      "gdpr_articles": [
         "Art 31"
      ]
   },
   "account_security_questions_are_registered_in_the_aws_account": {
      "prowler_check_desc": "Ensure security questions are registered in the AWS account.",
      "aws_service": "account",
      "impact": "medium",
      "scf_controls": [
         "IAC-01",
         "IAC-13"
      ],
      "gdpr_articles": [
         "Art 32.1",
         "Art 32.2"
      ]
   },
   "acm_certificates_expiration_check": {
      "prowler_check_desc": "Check if ACM Certificates are about to expire in specific days or less",
      "aws_service": "acm",
      "impact": "high",
      "scf_controls": [
         "IAC-10.2"
      ],
      "gdpr_articles": []
   },
   "acm_certificates_transparency_logs_enabled": {
      "prowler_check_desc": "Check if ACM certificates have Certificate Transparency logging enabled",
      "aws_service": "acm",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.2"
      ],
      "gdpr_articles": []
   },
   "apigateway_authorizers_enabled": {
      "prowler_check_desc": "Check if API Gateway has configured authorizers.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "WEB-03",
         "IAC-15"
      ],
      "gdpr_articles": []
   },
   "apigateway_client_certificate_enabled": {
      "prowler_check_desc": "Check if API Gateway Stage has client certificate enabled to access your backend endpoint.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "IAC-15"
      ],
      "gdpr_articles": []
   },
   "apigateway_endpoint_public": {
      "prowler_check_desc": "Check if API Gateway endpoint is public or private.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "apigateway_logging_enabled": {
      "prowler_check_desc": "Check if API Gateway Stage has logging enabled.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "MON-03.4"
      ],
      "gdpr_articles": []
   },
   "apigateway_waf_acl_attached": {
      "prowler_check_desc": "Check if API Gateway Stage has a WAF ACL attached.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "WEB-03",
         "NET-03.1"
      ],
      "gdpr_articles": []
   },
   "apigatewayv2_access_logging_enabled": {
      "prowler_check_desc": "Ensure API Gateway V2 has Access Logging enabled.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "MON-03.4"
      ],
      "gdpr_articles": []
   },
   "apigatewayv2_authorizers_enabled": {
      "prowler_check_desc": "Checks if API Gateway V2 has Access Logging enabled.",
      "aws_service": "apigateway",
      "impact": "medium",
      "scf_controls": [
         "MON-03.4"
      ],
      "gdpr_articles": []
   },
   "appstream_fleet_default_internet_access_disabled": {
      "prowler_check_desc": "Ensure default Internet Access from your Amazon AppStream fleet streaming instances should remain unchecked.",
      "aws_service": "appstream",
      "impact": "medium",
      "scf_controls": [
         "NET-03.2"
      ],
      "gdpr_articles": []
   },
   "appstream_fleet_maximum_session_duration": {
      "prowler_check_desc": "Ensure user maximum session duration is no longer than 10 hours.",
      "aws_service": "appstream",
      "impact": "medium",
      "scf_controls": [
         "NET-07"
      ],
      "gdpr_articles": []
   },
   "appstream_fleet_session_disconnect_timeout": {
      "prowler_check_desc": "Ensure session disconnect timeout is set to 5 minutes or less.",
      "aws_service": "appstream",
      "impact": "medium",
      "scf_controls": [
         "IAC-25"
      ],
      "gdpr_articles": []
   },
   "appstream_fleet_session_idle_disconnect_timeout": {
      "prowler_check_desc": "Ensure session idle disconnect timeout is set to 10 minutes or less.",
      "aws_service": "appstream",
      "impact": "medium",
      "scf_controls": [
         "IAC-25"
      ],
      "gdpr_articles": []
   },
   "autoscaling_find_secrets_ec2_launch_configuration": {
      "prowler_check_desc": "Find secrets in EC2 Auto Scaling Launch Configuration",
      "aws_service": "autoscaling",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled": {
      "prowler_check_desc": "Check if Lambda functions invoke API operations are being recorded by CloudTrail.",
      "aws_service": "lambda",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "awslambda_function_no_secrets_in_code": {
      "prowler_check_desc": "Find secrets in Lambda functions code.",
      "aws_service": "lambda",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "awslambda_function_no_secrets_in_variables": {
      "prowler_check_desc": "Find secrets in Lambda functions variables.",
      "aws_service": "lambda",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "awslambda_function_not_publicly_accessible": {
      "prowler_check_desc": "Check if Lambda functions have resource-based policy set as Public.",
      "aws_service": "lambda",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "awslambda_function_url_cors_policy": {
      "prowler_check_desc": "Check Lambda Function URL CORS configuration.",
      "aws_service": "lambda",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "awslambda_function_url_public": {
      "prowler_check_desc": "Check Public Lambda Function URL.",
      "aws_service": "lambda",
      "impact": "high",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "awslambda_function_using_supported_runtimes": {
      "prowler_check_desc": "Find obsolete Lambda runtimes.",
      "aws_service": "lambda",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "backup_plans_exist": {
      "prowler_check_desc": "Ensure that there is at least one AWS Backup plan",
      "aws_service": "backup",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "backup_reportplans_exist": {
      "prowler_check_desc": "Ensure that there is at least one AWS Backup report plan",
      "aws_service": "backup",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "backup_vaults_encrypted": {
      "prowler_check_desc": "Ensure that AWS Backup vaults are encrypted with AWS KMS",
      "aws_service": "backup",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "backup_vaults_exist": {
      "prowler_check_desc": "Esure AWS Backup vaults exist",
      "aws_service": "backup",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudformation_stack_outputs_find_secrets": {
      "prowler_check_desc": "Find secrets in CloudFormation outputs",
      "aws_service": "cloudformation",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudformation_stacks_termination_protection_enabled": {
      "prowler_check_desc": "Enable termination protection for Cloudformation Stacks",
      "aws_service": "cloudformation",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudfront_distributions_field_level_encryption_enabled": {
      "prowler_check_desc": "Check if CloudFront distributions have Field Level Encryption enabled.",
      "aws_service": "cloudfront",
      "impact": "low",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "cloudfront_distributions_geo_restrictions_enabled": {
      "prowler_check_desc": "Check if Geo restrictions are enabled in CloudFront distributions.",
      "aws_service": "cloudfront",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudfront_distributions_https_enabled": {
      "prowler_check_desc": "Check if CloudFront distributions are set to HTTPS.",
      "aws_service": "cloudfront",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudfront_distributions_logging_enabled": {
      "prowler_check_desc": "Check if CloudFront distributions have logging enabled.",
      "aws_service": "cloudfront",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudfront_distributions_using_deprecated_ssl_protocols": {
      "prowler_check_desc": "Check if CloudFront distributions are using deprecated SSL protocols.",
      "aws_service": "cloudfront",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudfront_distributions_using_waf": {
      "prowler_check_desc": "Check if CloudFront distributions are using WAF.",
      "aws_service": "cloudfront",
      "impact": "medium",
      "scf_controls": [
         "WEB-03",
         "NET-03.1"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_bucket_requires_mfa_delete": {
      "prowler_check_desc": "Ensure the S3 bucket CloudTrail bucket requires MFA delete",
      "aws_service": "cloudtrail",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudtrail_cloudwatch_logging_enabled": {
      "prowler_check_desc": "Ensure CloudTrail trails are integrated with CloudWatch Logs",
      "aws_service": "cloudtrail",
      "impact": "low",
      "scf_controls": [
         "VPM-06.5"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_insights_exist": {
      "prowler_check_desc": "Ensure CloudTrail Insight is enabled",
      "aws_service": "cloudtrail",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudtrail_kms_encryption_enabled": {
      "prowler_check_desc": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
      "aws_service": "cloudtrail",
      "impact": "medium",
      "scf_controls": [
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_log_file_validation_enabled": {
      "prowler_check_desc": "Ensure CloudTrail log file validation is enabled",
      "aws_service": "cloudtrail",
      "impact": "medium",
      "scf_controls": [
         "VPM-06.5"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_logs_s3_bucket_access_logging_enabled": {
      "prowler_check_desc": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
      "aws_service": "cloudtrail",
      "impact": "medium",
      "scf_controls": [
         "VPM-06.5"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_logs_s3_bucket_is_not_publicly_accessible": {
      "prowler_check_desc": "Ensure the S3 bucket CloudTrail logs is not publicly accessible",
      "aws_service": "cloudtrail",
      "impact": "critical",
      "scf_controls": [
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_multi_region_enabled": {
      "prowler_check_desc": "Ensure CloudTrail is enabled in all regions",
      "aws_service": "cloudtrail",
      "impact": "high",
      "scf_controls": [
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "cloudtrail_s3_dataevents_read_enabled": {
      "prowler_check_desc": "Check if S3 buckets have Object-level logging for read events is enabled in CloudTrail.",
      "aws_service": "cloudtrail",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudtrail_s3_dataevents_write_enabled": {
      "prowler_check_desc": "Check if S3 buckets have Object-level logging for write events is enabled in CloudTrail.",
      "aws_service": "cloudtrail",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudwatch_changes_to_network_acls_alarm_configured": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL).",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_changes_to_network_gateways_alarm_configured": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for changes to network gateways.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_changes_to_network_route_tables_alarm_configured": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for route table changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_changes_to_vpcs_alarm_configured": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for VPC changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_cross_account_sharing_disabled": {
      "prowler_check_desc": "Check if CloudWatch has allowed cross-account sharing.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudwatch_log_group_kms_encryption_enabled": {
      "prowler_check_desc": "Check if CloudWatch log groups are protected by AWS KMS.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudwatch_log_group_no_secrets_in_logs": {
      "prowler_check_desc": "Check if secrets exists in CloudWatch logs.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudwatch_log_group_retention_policy_specific_days_enabled": {
      "prowler_check_desc": "Check if CloudWatch Log Groups have a retention policy of specific days.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for AWS Config configuration changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for CloudTrail configuration changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_authentication_failures": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_aws_organizations_changes": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for AWS Organizations changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created KMS CMKs.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for S3 bucket policy changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_policy_changes": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for IAM policy changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_root_usage": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for usage of root account.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_security_group_changes": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for security group changes.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_sign_in_without_mfa": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "cloudwatch_log_metric_filter_unauthorized_api_calls": {
      "prowler_check_desc": "Ensure a log metric filter and alarm exist for unauthorized API calls.",
      "aws_service": "cloudwatch",
      "impact": "medium",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "codeartifact_packages_external_public_publishing_disabled": {
      "prowler_check_desc": "Ensure CodeArtifact internal packages do not allow external public source publishing.",
      "aws_service": "codeartifact",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "codebuild_project_older_90_days": {
      "prowler_check_desc": "Ensure CodeBuild Project has been invoked in the last 90 days",
      "aws_service": "codebuild",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "codebuild_project_user_controlled_buildspec": {
      "prowler_check_desc": "Ensure CodeBuild Project uses a controlled buildspec",
      "aws_service": "codebuild",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "config_recorder_all_regions_enabled": {
      "prowler_check_desc": "Ensure AWS Config is enabled in all regions.",
      "aws_service": "config",
      "impact": "medium",
      "scf_controls": [
         "AST-15",
         "CHG-02",
         "CHG-04"
      ],
      "gdpr_articles": []
   },
   "directoryservice_directory_log_forwarding_enabled": {
      "prowler_check_desc": "Directory Service monitoring with CloudWatch logs.",
      "aws_service": "directoryservice",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "directoryservice_directory_monitor_notifications": {
      "prowler_check_desc": "Directory Service has SNS Notifications enabled.",
      "aws_service": "directoryservice",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "directoryservice_directory_snapshots_limit": {
      "prowler_check_desc": "Directory Service Manual Snapshots limit reached.",
      "aws_service": "directoryservice",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "directoryservice_ldap_certificate_expiration": {
      "prowler_check_desc": "Directory Service LDAP Certificates expiration.",
      "aws_service": "directoryservice",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "directoryservice_radius_server_security_protocol": {
      "prowler_check_desc": "Ensure Radius server in DS is using the recommended security protocol.",
      "aws_service": "directoryservice",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "directoryservice_supported_mfa_radius_enabled": {
      "prowler_check_desc": "Ensure Multi-Factor Authentication (MFA) using Radius Server is enabled in DS.",
      "aws_service": "directoryservice",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "drs_job_exist": {
      "prowler_check_desc": "Ensure DRS is enabled with jobs.",
      "aws_service": "drs",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "dynamodb_accelerator_cluster_encryption_enabled": {
      "prowler_check_desc": "Check if DynamoDB DAX Clusters are encrypted at rest.",
      "aws_service": "dynamodb",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "dynamodb_tables_kms_cmk_encryption_enabled": {
      "prowler_check_desc": "Check if DynamoDB table has encryption at rest enabled using CMK KMS.",
      "aws_service": "dynamodb",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "dynamodb_tables_pitr_enabled": {
      "prowler_check_desc": "Check if DynamoDB tables point-in-time recovery (PITR) is enabled.",
      "aws_service": "dynamodb",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_ami_public": {
      "prowler_check_desc": "Ensure there are no EC2 AMIs set as Public.",
      "aws_service": "ec2",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "ec2_ebs_default_encryption": {
      "prowler_check_desc": "Check if EBS Default Encryption is activated.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "ec2_ebs_public_snapshot": {
      "prowler_check_desc": "Ensure there are no EBS Snapshots set as Public.",
      "aws_service": "ec2",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "ec2_ebs_snapshots_encrypted": {
      "prowler_check_desc": "Check if EBS snapshots are encrypted.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_ebs_volume_encryption": {
      "prowler_check_desc": "Ensure there are no EBS Volumes unencrypted.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_elastic_ip_shodan": {
      "prowler_check_desc": "Check if any of the Elastic or Public IP are in Shodan (requires Shodan API KEY).",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "ec2_elastic_ip_unassgined": {
      "prowler_check_desc": "Check if there is any unassigned Elastic IP.",
      "aws_service": "ec2",
      "impact": "low",
      "scf_controls": [
         "NET-03"
      ],
      "gdpr_articles": []
   },
   "ec2_instance_imdsv2_enabled": {
      "prowler_check_desc": "Check if EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_instance_internet_facing_with_instance_profile": {
      "prowler_check_desc": "Check for internet facing EC2 instances with Instance Profiles attached.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_instance_managed_by_ssm": {
      "prowler_check_desc": "Check if EC2 instances are managed by Systems Manager.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "VPM-04.1"
      ],
      "gdpr_articles": []
   },
   "ec2_instance_older_than_specific_days": {
      "prowler_check_desc": "Check EC2 Instances older than specific days.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_instance_profile_attached": {
      "prowler_check_desc": "Ensure IAM instance roles are used for AWS resource access from instances",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.5"
      ],
      "gdpr_articles": []
   },
   "ec2_instance_public_ip": {
      "prowler_check_desc": "Check for EC2 Instances with Public IP.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "NET-03.3"
      ],
      "gdpr_articles": []
   },
   "ec2_instance_secrets_user_data": {
      "prowler_check_desc": "Find secrets in EC2 User Data.",
      "aws_service": "ec2",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_networkacl_allow_ingress_any_port": {
      "prowler_check_desc": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to any port.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_networkacl_allow_ingress_tcp_port_22": {
      "prowler_check_desc": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to SSH port 22",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_networkacl_allow_ingress_tcp_port_3389": {
      "prowler_check_desc": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to Microsoft RDP port 3389",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_any_port": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to any port.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to MongoDB ports 27017 and 27018.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to FTP ports 20 or 21.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to SSH port 22.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-03"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 3389.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-03"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Cassandra ports 7199 or 9160 or 8888.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Elasticsearch/Kibana ports.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Kafka port 9092.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Memcached port 11211.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to MySQL port 3306.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Oracle ports 1521 or 2483.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Postgres port 5432.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Redis port 6379.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Windows SQL Server ports 1433 or 1434.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23": {
      "prowler_check_desc": "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Telnet port 23.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_allow_wide_open_public_ipv4": {
      "prowler_check_desc": "Ensure no security groups allow ingress from wide-open non-RFC1918 address.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_default_restrict_traffic": {
      "prowler_check_desc": "Ensure the default security group of every VPC restricts all traffic.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-03"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_from_launch_wizard": {
      "prowler_check_desc": "Security Groups created by EC2 Launch Wizard.",
      "aws_service": "ec2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ec2_securitygroup_not_used": {
      "prowler_check_desc": "Ensure there are no Security Groups not being used.",
      "aws_service": "ec2",
      "impact": "low",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "ec2_securitygroup_with_many_ingress_egress_rules": {
      "prowler_check_desc": "Find security groups with more than 50 ingress or egress rules.",
      "aws_service": "ec2",
      "impact": "high",
      "scf_controls": [
         "NET-04.1"
      ],
      "gdpr_articles": []
   },
   "ecr_registry_scan_images_on_push_enabled": {
      "prowler_check_desc": "Check if ECR Registry has scan on push enabled",
      "aws_service": "ecr",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ecr_repositories_lifecycle_policy_enabled": {
      "prowler_check_desc": "Check if ECR repositories have lifecycle policies enabled",
      "aws_service": "ecr",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ecr_repositories_not_publicly_accessible": {
      "prowler_check_desc": "Ensure there are no ECR repositories set as Public",
      "aws_service": "ecr",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "ecr_repositories_scan_images_on_push_enabled": {
      "prowler_check_desc": "DEPRECATED",
      "aws_service": "Check if ECR image scan on push is enabled",
      "impact": "ecr",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ecr_repositories_scan_vulnerabilities_in_latest_image": {
      "prowler_check_desc": "Check if ECR image scan found vulnerabilities in the newest image version",
      "aws_service": "ecr",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ecs_task_definitions_no_environment_secrets": {
      "prowler_check_desc": "Check if secrets exists in ECS task definitions environment variables",
      "aws_service": "ecs",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "efs_encryption_at_rest_enabled": {
      "prowler_check_desc": "Check if EFS protects sensitive data with encryption at rest",
      "aws_service": "efs",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "efs_have_backup_enabled": {
      "prowler_check_desc": "Check if EFS File systems have backup enabled",
      "aws_service": "efs",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "efs_not_publicly_accessible": {
      "prowler_check_desc": "Check if EFS have policies which allow access to everyone",
      "aws_service": "efs",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "eks_cluster_kms_cmk_encryption_in_secrets_enabled": {
      "prowler_check_desc": "Ensure Kubernetes Secrets are encrypted using Customer Master Keys (CMKs)",
      "aws_service": "eks",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "eks_control_plane_endpoint_access_restricted": {
      "prowler_check_desc": "Restrict Access to the EKS Control Plane Endpoint",
      "aws_service": "eks",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "eks_control_plane_logging_all_types_enabled": {
      "prowler_check_desc": "Ensure EKS Control Plane Audit Logging is enabled for all log types",
      "aws_service": "eks",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "eks_endpoints_not_publicly_accessible": {
      "prowler_check_desc": "Ensure EKS Clusters are created with Private Endpoint Enabled and Public Access Disabled",
      "aws_service": "eks",
      "impact": "high",
      "scf_controls": [
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "elb_insecure_ssl_ciphers": {
      "prowler_check_desc": "Check if Elastic Load Balancers have insecure SSL ciphers.",
      "aws_service": "elb",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elb_internet_facing": {
      "prowler_check_desc": "Check for internet facing Elastic Load Balancers.",
      "aws_service": "elb",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elb_logging_enabled": {
      "prowler_check_desc": "Check if Elastic Load Balancers have logging enabled.",
      "aws_service": "elb",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elb_ssl_listeners": {
      "prowler_check_desc": "Check if Elastic Load Balancers have SSL listeners.",
      "aws_service": "elb",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_deletion_protection": {
      "prowler_check_desc": "Check if Elastic Load Balancers have deletion protection enabled.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_desync_mitigation_mode": {
      "prowler_check_desc": "Check whether the Application Load Balancer is configured with defensive or strictest desync mitigation mode",
      "aws_service": "if not check if at least is configured with the drop_invalid_header_fields attribute",
      "impact": "elbv2",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_insecure_ssl_ciphers": {
      "prowler_check_desc": "Check if Elastic Load Balancers have insecure SSL ciphers.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_internet_facing": {
      "prowler_check_desc": "Check for internet facing Elastic Load Balancers.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "elbv2_listeners_underneath": {
      "prowler_check_desc": "Check if ELBV2 has listeners underneath.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_logging_enabled": {
      "prowler_check_desc": "Check if Elastic Load Balancers have logging enabled.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_ssl_listeners": {
      "prowler_check_desc": "Check if Elastic Load Balancers have SSL listeners.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "elbv2_waf_acl_attached": {
      "prowler_check_desc": "Check if Application Load Balancer has a WAF ACL attached.",
      "aws_service": "elbv2",
      "impact": "medium",
      "scf_controls": [
         "WEB-03",
         "NET-03.1"
      ],
      "gdpr_articles": []
   },
   "emr_cluster_account_public_block_enabled": {
      "prowler_check_desc": "EMR Account Public Access Block enabled.",
      "aws_service": "emr",
      "impact": "high",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "emr_cluster_master_nodes_no_public_ip": {
      "prowler_check_desc": "EMR Cluster without Public IP.",
      "aws_service": "emr",
      "impact": "medium",
      "scf_controls": [
         "NET-04"
      ],
      "gdpr_articles": []
   },
   "emr_cluster_publicly_accesible": {
      "prowler_check_desc": "Publicly accessible EMR Cluster.",
      "aws_service": "emr",
      "impact": "medium",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "glacier_vaults_policy_public_access": {
      "prowler_check_desc": "Check if S3 Glacier vaults have policies which allow access to everyone.",
      "aws_service": "glacier",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "glue_data_catalogs_connection_passwords_encryption_enabled": {
      "prowler_check_desc": "Check if Glue data catalog settings have encrypt connection password enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "DCH-01"
      ],
      "gdpr_articles": [
         "Art 5.1",
         "Art 32.1",
         "Art 32.2"
      ]
   },
   "glue_data_catalogs_metadata_encryption_enabled": {
      "prowler_check_desc": "Check if Glue data catalog settings have metadata encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "glue_database_connections_ssl_enabled": {
      "prowler_check_desc": "Check if Glue database connection has SSL connection enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "DCH-01"
      ],
      "gdpr_articles": [
         "Art 5.1",
         "Art 32.1",
         "Art 32.2"
      ]
   },
   "glue_development_endpoints_cloudwatch_logs_encryption_enabled": {
      "prowler_check_desc": "Check if Glue development endpoints have CloudWatch logs encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "glue_development_endpoints_job_bookmark_encryption_enabled": {
      "prowler_check_desc": "Check if Glue development endpoints have Job bookmark encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "glue_development_endpoints_s3_encryption_enabled": {
      "prowler_check_desc": "Check if Glue development endpoints have S3 encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "glue_etl_jobs_amazon_s3_encryption_enabled": {
      "prowler_check_desc": "Check if Glue ETL Jobs have S3 encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "glue_etl_jobs_cloudwatch_logs_encryption_enabled": {
      "prowler_check_desc": "Check if Glue ETL Jobs have CloudWatch Logs encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "glue_etl_jobs_job_bookmark_encryption_enabled": {
      "prowler_check_desc": "Check if Glue ETL Jobs have Job bookmark encryption enabled.",
      "aws_service": "glue",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "guardduty_centrally_managed": {
      "prowler_check_desc": "GuardDuty is centrally managed",
      "aws_service": "guardduty",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "guardduty_is_enabled": {
      "prowler_check_desc": "Check if GuardDuty is enabled",
      "aws_service": "guardduty",
      "impact": "medium",
      "scf_controls": [
         "THR-03"
      ],
      "gdpr_articles": []
   },
   "guardduty_no_high_severity_findings": {
      "prowler_check_desc": "There are High severity GuardDuty findings ",
      "aws_service": "guardduty",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_administrator_access_with_mfa": {
      "prowler_check_desc": "Ensure users of groups with AdministratorAccess policy have MFA tokens enabled",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [
         "IAC-06.1"
      ],
      "gdpr_articles": []
   },
   "iam_avoid_root_usage": {
      "prowler_check_desc": "Avoid the use of the root accounts",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_aws_attached_policy_no_administrative_privileges": {
      "prowler_check_desc": "Ensure IAM AWS-Managed policies that allow full \"*:*\" administrative privileges are not attached",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_check_saml_providers_sts": {
      "prowler_check_desc": "Check if there are SAML Providers then STS can be used",
      "aws_service": "iam",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_customer_attached_policy_no_administrative_privileges": {
      "prowler_check_desc": "Ensure IAM Customer-Managed policies that allow full \"*:*\" administrative privileges are not attached",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_customer_unattached_policy_no_administrative_privileges": {
      "prowler_check_desc": "Ensure IAM policies that allow full \"*:*\" administrative privileges are not created",
      "aws_service": "iam",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_disable_30_days_credentials": {
      "prowler_check_desc": "Ensure credentials unused for 30 days or greater are disabled",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_disable_45_days_credentials": {
      "prowler_check_desc": "Ensure credentials unused for 45 days or greater are disabled",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_disable_90_days_credentials": {
      "prowler_check_desc": "Ensure credentials unused for 90 days or greater are disabled",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10"
      ],
      "gdpr_articles": []
   },
   "iam_no_custom_policy_permissive_role_assumption": {
      "prowler_check_desc": "Ensure that no custom IAM policies exist which allow permissive role assumption (e.g. sts:AssumeRole on *)",
      "aws_service": "iam",
      "impact": "critical",
      "scf_controls": [
         "IAC-21.4"
      ],
      "gdpr_articles": []
   },
   "iam_no_expired_server_certificates_stored": {
      "prowler_check_desc": "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed.",
      "aws_service": "iam",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_no_root_access_key": {
      "prowler_check_desc": "Ensure no root account access key exists",
      "aws_service": "iam",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_password_policy_expires_passwords_within_90_days_or_less": {
      "prowler_check_desc": "Ensure IAM password policy expires passwords within 90 days or less",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10"
      ],
      "gdpr_articles": []
   },
   "iam_password_policy_lowercase": {
      "prowler_check_desc": "Ensure IAM password policy require at least one lowercase letter",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.1"
      ],
      "gdpr_articles": []
   },
   "iam_password_policy_minimum_length_14": {
      "prowler_check_desc": "Ensure IAM password policy requires minimum length of 14 or greater",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.1"
      ],
      "gdpr_articles": []
   },
   "iam_password_policy_number": {
      "prowler_check_desc": "Ensure IAM password policy require at least one number",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.1"
      ],
      "gdpr_articles": []
   },
   "iam_password_policy_reuse_24": {
      "prowler_check_desc": "Ensure IAM password policy prevents password reuse: 24 or greater",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.1"
      ],
      "gdpr_articles": []
   },
   "iam_password_policy_symbol": {
      "prowler_check_desc": "Ensure IAM password policy require at least one symbol",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.1"
      ],
      "gdpr_articles": []
   },
   "iam_password_policy_uppercase": {
      "prowler_check_desc": "Ensure IAM password policy requires at least one uppercase letter",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.1"
      ],
      "gdpr_articles": []
   },
   "iam_policy_allows_privilege_escalation": {
      "prowler_check_desc": "Ensure no Customer Managed IAM policies allow actions that may lead into Privilege Escalation",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_policy_attached_only_to_group_or_roles": {
      "prowler_check_desc": "Ensure IAM policies are attached only to groups or roles",
      "aws_service": "iam",
      "impact": "low",
      "scf_controls": [
         "IAC-08"
      ],
      "gdpr_articles": []
   },
   "iam_policy_no_full_access_to_cloudtrail": {
      "prowler_check_desc": "Ensure IAM policies that allow full \"cloudtrail:*\" privileges are not created",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_policy_no_full_access_to_kms": {
      "prowler_check_desc": "Ensure IAM policies that allow full \"kms:*\" privileges are not created",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_role_cross_service_confused_deputy_prevention": {
      "prowler_check_desc": "Ensure IAM Service Roles prevents against a cross-service confused deputy attack",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_root_hardware_mfa_enabled": {
      "prowler_check_desc": "Ensure only hardware MFA is enabled for the root account",
      "aws_service": "iam",
      "impact": "critical",
      "scf_controls": [
         "IAC-06"
      ],
      "gdpr_articles": []
   },
   "iam_root_mfa_enabled": {
      "prowler_check_desc": "Ensure MFA is enabled for the root account",
      "aws_service": "iam",
      "impact": "critical",
      "scf_controls": [
         "IAC-06",
         "IAC-10.7"
      ],
      "gdpr_articles": []
   },
   "iam_rotate_access_key_90_days": {
      "prowler_check_desc": "Ensure access keys are rotated every 90 days or less",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.5"
      ],
      "gdpr_articles": []
   },
   "iam_securityaudit_role_created": {
      "prowler_check_desc": "Ensure a Security Audit role has been created to conduct security audits",
      "aws_service": "iam",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_support_role_created": {
      "prowler_check_desc": "Ensure a support role has been created to manage incidents with AWS Support",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IRO-01"
      ],
      "gdpr_articles": [
         "Art 32.1",
         "Art 32.2"
      ]
   },
   "iam_user_hardware_mfa_enabled": {
      "prowler_check_desc": "Check if IAM users have Hardware MFA enabled.",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "iam_user_mfa_enabled_console_access": {
      "prowler_check_desc": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password.",
      "aws_service": "iam",
      "impact": "high",
      "scf_controls": [
         "IAC-06"
      ],
      "gdpr_articles": []
   },
   "iam_user_no_setup_initial_access_key": {
      "prowler_check_desc": "Do not setup access keys during initial user setup for all IAM users that have a console password",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [
         "IAC-10.6"
      ],
      "gdpr_articles": []
   },
   "iam_user_two_active_access_key": {
      "prowler_check_desc": "Check if IAM users have two active access keys",
      "aws_service": "iam",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "inspector2_findings_exist": {
      "prowler_check_desc": "Check if Inspector2 findings exist",
      "aws_service": "inspector2",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "kms_cmk_are_used": {
      "prowler_check_desc": "Check if there are CMK KMS keys not used.",
      "aws_service": "kms",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "kms_cmk_rotation_enabled": {
      "prowler_check_desc": "Ensure rotation for customer created KMS CMKs is enabled.",
      "aws_service": "kms",
      "impact": "medium",
      "scf_controls": [
         "CRY-01"
      ],
      "gdpr_articles": [
         "Art 5.1",
         "Art 32.1",
         "Art 32.2"
      ]
   },
   "kms_key_not_publicly_accessible": {
      "prowler_check_desc": "Check exposed KMS keys",
      "aws_service": "kms",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "macie_is_enabled": {
      "prowler_check_desc": "Check if Amazon Macie is enabled.",
      "aws_service": "macie",
      "impact": "low",
      "scf_controls": [
         "MON-03.1"
      ],
      "gdpr_articles": []
   },
   "opensearch_service_domains_audit_logging_enabled": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have audit logging enabled",
      "aws_service": "opensearch",
      "impact": "low",
      "scf_controls": [
         "MON-01.9"
      ],
      "gdpr_articles": []
   },
   "opensearch_service_domains_cloudwatch_logging_enabled": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have logging enabled",
      "aws_service": "opensearch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "opensearch_service_domains_encryption_at_rest_enabled": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have encryption at-rest enabled",
      "aws_service": "opensearch",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "opensearch_service_domains_https_communications_enforced": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have enforce HTTPS enabled",
      "aws_service": "opensearch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "opensearch_service_domains_internal_user_database_enabled": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have internal user database enabled",
      "aws_service": "opensearch",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "opensearch_service_domains_node_to_node_encryption_enabled": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have node-to-node encryption enabled",
      "aws_service": "opensearch",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "opensearch_service_domains_not_publicly_accessible": {
      "prowler_check_desc": "Check if Amazon Opensearch/Elasticsearch domains are set as Public or if it has open policy access",
      "aws_service": "opensearch",
      "impact": "critical",
      "scf_controls": [
         "DCH-15",
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "opensearch_service_domains_updated_to_the_latest_service_software_version": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains have updates available",
      "aws_service": "opensearch",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "opensearch_service_domains_use_cognito_authentication_for_kibana": {
      "prowler_check_desc": "Check if Amazon Elasticsearch/Opensearch Service domains has Amazon Cognito authentication for Kibana enabled",
      "aws_service": "opensearch",
      "impact": "high",
      "scf_controls": [
         "WEB-06"
      ],
      "gdpr_articles": []
   },
   "organizations_account_part_of_organizations": {
      "prowler_check_desc": "Check if account is part of an AWS Organizations",
      "aws_service": "organizations",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "organizations_delegated_administrators": {
      "prowler_check_desc": "Check if AWS Organizations delegated administrators are trusted",
      "aws_service": "organizations",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "organizations_scp_check_deny_regions": {
      "prowler_check_desc": "Check if AWS Regions are restricted with SCP policies",
      "aws_service": "organizations",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_backup_enabled": {
      "prowler_check_desc": "Check if RDS instances have backup enabled.",
      "aws_service": "rds",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_deletion_protection": {
      "prowler_check_desc": "Check if RDS instances have deletion protection enabled.",
      "aws_service": "rds",
      "impact": "medium",
      "scf_controls": [
         "DCH-01"
      ],
      "gdpr_articles": [
         "Art 5.1",
         "Art 32.1",
         "Art 32.2"
      ]
   },
   "rds_instance_enhanced_monitoring_enabled": {
      "prowler_check_desc": "Check if RDS instances has enhanced monitoring enabled.",
      "aws_service": "rds",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_integration_cloudwatch_logs": {
      "prowler_check_desc": "Check if RDS instances is integrated with CloudWatch Logs.",
      "aws_service": "rds",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_minor_version_upgrade_enabled": {
      "prowler_check_desc": "Ensure RDS instances have minor version upgrade enabled.",
      "aws_service": "rds",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_multi_az": {
      "prowler_check_desc": "Check if RDS instances have multi-AZ enabled.",
      "aws_service": "rds",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_no_public_access": {
      "prowler_check_desc": "Ensure there are no Public Accessible RDS instances.",
      "aws_service": "rds",
      "impact": "critical",
      "scf_controls": [
         "AST-06"
      ],
      "gdpr_articles": []
   },
   "rds_instance_storage_encrypted": {
      "prowler_check_desc": "Check if RDS instances storage is encrypted.",
      "aws_service": "rds",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_instance_transport_encrypted": {
      "prowler_check_desc": "Check if RDS instances client connections are encrypted (Microsoft SQL Server and PostgreSQL).",
      "aws_service": "rds",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "rds_snapshots_public_access": {
      "prowler_check_desc": "Check if RDS Snapshots and Cluster Snapshots are public.",
      "aws_service": "rds",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "redshift_cluster_audit_logging": {
      "prowler_check_desc": "Check if Redshift cluster has audit logging enabled",
      "aws_service": "redshift",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "redshift_cluster_automated_snapshot": {
      "prowler_check_desc": "Check if Redshift Clusters have automated snapshots enabled",
      "aws_service": "redshift",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "redshift_cluster_automatic_upgrades": {
      "prowler_check_desc": "Check for Redshift Automatic Version Upgrade",
      "aws_service": "redshift",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "redshift_cluster_public_access": {
      "prowler_check_desc": "Check for Publicly Accessible Redshift Clusters",
      "aws_service": "redshift",
      "impact": "high",
      "scf_controls": [
         "NET-03"
      ],
      "gdpr_articles": []
   },
   "resourceexplorer2_indexes_found": {
      "prowler_check_desc": "Resource Explorer Indexes Found",
      "aws_service": "resourceexplorer2",
      "impact": "low",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "route53_domains_privacy_protection_enabled": {
      "prowler_check_desc": "Enable Privacy Protection for for a Route53 Domain.",
      "aws_service": "route53",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "route53_domains_transferlock_enabled": {
      "prowler_check_desc": "Enable Transfer Lock for a Route53 Domain.",
      "aws_service": "route53",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "route53_public_hosted_zones_cloudwatch_logging_enabled": {
      "prowler_check_desc": "Check if Route53 public hosted zones are logging queries to CloudWatch Logs.",
      "aws_service": "route53",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_account_level_public_access_blocks": {
      "prowler_check_desc": "Check S3 Account Level Public Access Block.",
      "aws_service": "s3",
      "impact": "high",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "s3_bucket_acl_prohibited": {
      "prowler_check_desc": "Check if S3 buckets have ACLs enabled",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_bucket_default_encryption": {
      "prowler_check_desc": "Check if S3 buckets have default encryption (SSE) enabled or use a bucket policy to enforce it.",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "s3_bucket_level_public_access_block": {
      "prowler_check_desc": "Check S3 Bucket Level Public Access Block.",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_bucket_no_mfa_delete": {
      "prowler_check_desc": "Check if S3 bucket MFA Delete is not enabled.",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_bucket_object_versioning": {
      "prowler_check_desc": "Check if S3 buckets have object versioning enabled",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_bucket_policy_public_write_access": {
      "prowler_check_desc": "Check if S3 buckets have policies which allow WRITE access.",
      "aws_service": "s3",
      "impact": "critical",
      "scf_controls": [
         "MON-11"
      ],
      "gdpr_articles": []
   },
   "s3_bucket_public_access": {
      "prowler_check_desc": "Ensure there are no S3 buckets open to Everyone or Any AWS user.",
      "aws_service": "s3",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_bucket_secure_transport_policy": {
      "prowler_check_desc": "Check if S3 buckets have secure transport policy.",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "s3_bucket_server_access_logging_enabled": {
      "prowler_check_desc": "Check if S3 buckets have server access logging enabled",
      "aws_service": "s3",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "sagemaker_models_network_isolation_enabled": {
      "prowler_check_desc": "Check if Amazon SageMaker Models have network isolation enabled",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "NET-06"
      ],
      "gdpr_articles": []
   },
   "sagemaker_models_vpc_settings_configured": {
      "prowler_check_desc": "Check if Amazon SageMaker Models have VPC settings configured",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "NET-06"
      ],
      "gdpr_articles": []
   },
   "sagemaker_notebook_instance_encryption_enabled": {
      "prowler_check_desc": "Check if Amazon SageMaker Notebook instances have data encryption enabled",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "CRY-05.1"
      ],
      "gdpr_articles": []
   },
   "sagemaker_notebook_instance_root_access_disabled": {
      "prowler_check_desc": "Check if Amazon SageMaker Notebook instances have root access disabled",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "IAC-16"
      ],
      "gdpr_articles": []
   },
   "sagemaker_notebook_instance_vpc_settings_configured": {
      "prowler_check_desc": "Check if Amazon SageMaker Notebook instances have VPC settings configured",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "NET-06"
      ],
      "gdpr_articles": []
   },
   "sagemaker_notebook_instance_without_direct_internet_access_configured": {
      "prowler_check_desc": "Check if Amazon SageMaker Notebook instances have direct internet access",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "NET-06"
      ],
      "gdpr_articles": []
   },
   "sagemaker_training_jobs_intercontainer_encryption_enabled": {
      "prowler_check_desc": "Check if Amazon SageMaker Training jobs have intercontainer encryption enabled",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "CRY-05.1"
      ],
      "gdpr_articles": []
   },
   "sagemaker_training_jobs_network_isolation_enabled": {
      "prowler_check_desc": "Check if Amazon SageMaker Training jobs have network isolation enabled",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "NET-03"
      ],
      "gdpr_articles": []
   },
   "sagemaker_training_jobs_volume_and_output_encryption_enabled": {
      "prowler_check_desc": "Check if Amazon SageMaker Training jobs have volume and output with KMS encryption enabled",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "CRY-05.1"
      ],
      "gdpr_articles": []
   },
   "sagemaker_training_jobs_vpc_settings_configured": {
      "prowler_check_desc": "Check if Amazon SageMaker Training job have VPC settings configured.",
      "aws_service": "sagemaker",
      "impact": "medium",
      "scf_controls": [
         "NET-06"
      ],
      "gdpr_articles": []
   },
   "secretsmanager_automatic_rotation_enabled": {
      "prowler_check_desc": "Check if Secrets Manager secret rotation is enabled.",
      "aws_service": "secretsmanager",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "securityhub_enabled": {
      "prowler_check_desc": "Check if Security Hub is enabled and its standard subscriptions.",
      "aws_service": "securityhub",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "shield_advanced_protection_in_associated_elastic_ips": {
      "prowler_check_desc": "Check if Elastic IP addresses with associations are protected by AWS Shield Advanced.",
      "aws_service": "shield",
      "impact": "medium",
      "scf_controls": [
         "NET-02.1"
      ],
      "gdpr_articles": []
   },
   "shield_advanced_protection_in_classic_load_balancers": {
      "prowler_check_desc": "Check if Classic Load Balancers are protected by AWS Shield Advanced.",
      "aws_service": "shield",
      "impact": "medium",
      "scf_controls": [
         "NET-02.1"
      ],
      "gdpr_articles": []
   },
   "shield_advanced_protection_in_cloudfront_distributions": {
      "prowler_check_desc": "Check if Cloudfront distributions are protected by AWS Shield Advanced.",
      "aws_service": "shield",
      "impact": "medium",
      "scf_controls": [
         "NET-02.1"
      ],
      "gdpr_articles": []
   },
   "shield_advanced_protection_in_global_accelerators": {
      "prowler_check_desc": "Check if Global Accelerators are protected by AWS Shield Advanced.",
      "aws_service": "shield",
      "impact": "medium",
      "scf_controls": [
         "NET-02.1"
      ],
      "gdpr_articles": []
   },
   "shield_advanced_protection_in_internet_facing_load_balancers": {
      "prowler_check_desc": "Check if internet-facing Application Load Balancers are protected by AWS Shield Advanced.",
      "aws_service": "shield",
      "impact": "medium",
      "scf_controls": [
         "NET-02.1"
      ],
      "gdpr_articles": []
   },
   "shield_advanced_protection_in_route53_hosted_zones": {
      "prowler_check_desc": "Check if Route53 hosted zones are protected by AWS Shield Advanced.",
      "aws_service": "shield",
      "impact": "medium",
      "scf_controls": [
         "NET-02.1"
      ],
      "gdpr_articles": []
   },
   "sns_topics_kms_encryption_at_rest_enabled": {
      "prowler_check_desc": "Ensure there are no SNS Topics unencrypted",
      "aws_service": "sns",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "sns_topics_not_publicly_accessible": {
      "prowler_check_desc": "Check if SNS topics have policy set as Public",
      "aws_service": "sns",
      "impact": "high",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "sqs_queues_not_publicly_accessible": {
      "prowler_check_desc": "Check if SQS queues have policy set as Public",
      "aws_service": "sqs",
      "impact": "critical",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "sqs_queues_server_side_encryption_enabled": {
      "prowler_check_desc": "Check if SQS queues have Server Side Encryption enabled",
      "aws_service": "sqs",
      "impact": "medium",
      "scf_controls": [
         "CRY-05"
      ],
      "gdpr_articles": [
         "Art 5.1"
      ]
   },
   "ssm_document_secrets": {
      "prowler_check_desc": "Find secrets in SSM Documents.",
      "aws_service": "ssm",
      "impact": "critical",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "ssm_documents_set_as_public": {
      "prowler_check_desc": "Check if there are SSM Documents set as public.",
      "aws_service": "ssm",
      "impact": "high",
      "scf_controls": [
         "DCH-15"
      ],
      "gdpr_articles": []
   },
   "ssm_managed_compliant_patching": {
      "prowler_check_desc": "Check if EC2 instances managed by Systems Manager are compliant with patching requirements.",
      "aws_service": "ssm",
      "impact": "high",
      "scf_controls": [
         "VPM-05"
      ],
      "gdpr_articles": []
   },
   "ssmincidents_enabled_with_plans": {
      "prowler_check_desc": "Ensure SSM Incidents is enabled with response plans.",
      "aws_service": "ssm",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "trustedadvisor_errors_and_warnings": {
      "prowler_check_desc": "Check Trusted Advisor for errors and warnings.",
      "aws_service": "trustedadvisor",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "vpc_different_regions": {
      "prowler_check_desc": "Ensure there are vpcs in more than one region",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "vpc_endpoint_connections_trust_boundaries": {
      "prowler_check_desc": "Find trust boundaries in VPC endpoint connections.",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "vpc_endpoint_services_allowed_principals_trust_boundaries": {
      "prowler_check_desc": "Find trust boundaries in VPC endpoint services allowlisted principles.",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "vpc_flow_logs_enabled": {
      "prowler_check_desc": "Ensure VPC Flow Logging is Enabled in all VPCs.",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [
         "VPM-06.5"
      ],
      "gdpr_articles": []
   },
   "vpc_peering_routing_tables_with_least_privilege": {
      "prowler_check_desc": "Ensure routing tables for VPC peering are least access.",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [
         "NET-06"
      ],
      "gdpr_articles": []
   },
   "vpc_subnet_different_az": {
      "prowler_check_desc": "Ensure all vpc has subnets in more than one availability zone",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "vpc_subnet_separate_private_public": {
      "prowler_check_desc": "Ensure all vpc has public and private subnets defined",
      "aws_service": "vpc",
      "impact": "medium",
      "scf_controls": [],
      "gdpr_articles": []
   },
   "workspaces_volume_encryption_enabled": {
      "prowler_check_desc": "Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements",
      "aws_service": "workspaces",
      "impact": "high",
      "scf_controls": [],
      "gdpr_articles": []
   }
}
