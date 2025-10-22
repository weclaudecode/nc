
#!/usr/bin/env python3
"""
Simple Email Service for EC2 Scheduler Reports

This script provides a simple wrapper around SNSNotifier.send_smtp_email
to send report files via email. It keeps things simple by:
- Loading configuration from a YAML file
- Supporting multiple file attachments
- Minimal error handling (fail fast with clear messages)
- No SNS, GitLab, or cost calculation integration

Usage:
    python send_report_email.py report1.json report2.html
    python send_report_email.py --config custom_config.yaml report1.json report2.html
"""

import os
import sys
import yaml
import argparse
from sns_notifier import SNSNotifier


def load_config(config_path):
    """
    Load SMTP configuration from YAML file.

    Args:
        config_path (str): Path to YAML configuration file

    Returns:
        dict: Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    return config


def validate_config(config):
    """
    Validate that configuration has all required fields.

    Args:
        config (dict): Configuration dictionary

    Raises:
        ValueError: If required fields are missing or invalid
    """
    # Check top-level sections
    if 'smtp' not in config:
        raise ValueError("Configuration missing 'smtp' section")
    if 'email' not in config:
        raise ValueError("Configuration missing 'email' section")

    smtp = config['smtp']
    email = config['email']

    # Required SMTP fields
    required_smtp = ['enabled', 'server', 'port', 'sender', 'recipients', 'use_tls']
    for field in required_smtp:
        if field not in smtp:
            raise ValueError(f"SMTP configuration missing required field: {field}")

    # Validate types
    if not isinstance(smtp['enabled'], bool):
        raise ValueError("smtp.enabled must be a boolean")
    if not isinstance(smtp['port'], int):
        raise ValueError("smtp.port must be an integer")
    if not isinstance(smtp['recipients'], list) or len(smtp['recipients']) == 0:
        raise ValueError("smtp.recipients must be a non-empty list")
    if not isinstance(smtp['use_tls'], bool):
        raise ValueError("smtp.use_tls must be a boolean")

    # Required email fields
    if 'subject' not in email:
        raise ValueError("Email configuration missing required field: subject")
    if 'message' not in email:
        raise ValueError("Email configuration missing required field: message")

    # Check if SMTP is enabled
    if not smtp['enabled']:
        raise ValueError("SMTP is disabled in configuration (smtp.enabled: false)")


def send_reports(config, report_files):
    """
    Send report files via email using SNSNotifier.

    Args:
        config (dict): Configuration dictionary
        report_files (list): List of file paths to attach

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    smtp_config = config['smtp']
    email_config = config['email']

    # Build subject with optional prefix and expand environment variables
    subject = os.path.expandvars(email_config['subject'])
    if 'subject_prefix' in smtp_config and smtp_config['subject_prefix']:
        subject_prefix = os.path.expandvars(smtp_config['subject_prefix'])
        subject = f"{subject_prefix} {subject}"

    # Get message and expand environment variables
    message = os.path.expandvars(email_config['message'])

    # Initialize SNSNotifier with minimal configuration
    # - topic_arn=None: We're not using SNS notifications
    # - region='us-east-1': Default region, not critical for SMTP
    # - smtp_config: Our SMTP configuration
    # - gitlab_config=None: We're not using GitLab integration
    notifier = SNSNotifier(
        topic_arn=None,
        region='us-east-1',
        smtp_config=smtp_config,
        gitlab_config=None
    )

    # Send email with attachments
    # The send_smtp_email method handles:
    # - File validation (checks if files exist)
    # - SMTP connection and authentication
    # - MIME encoding for attachments
    # - Error logging
    success = notifier.send_smtp_email(
        subject=subject,
        message=message,
        recipients=None,  # Use recipients from config
        attachments=report_files if report_files else None
    )

    return success


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Send EC2 Scheduler report files via email',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send two report files using default config
  python send_report_email.py reports/execution.json reports/execution.html

  # Send reports using custom config file
  python send_report_email.py --config custom_smtp.yaml report1.json report2.html

  # Send single report file
  python send_report_email.py reports/execution.json
        """
    )

    parser.add_argument(
        '--config',
        default='config/smtp_config.yaml',
        help='Path to SMTP configuration file (default: config/smtp_config.yaml)'
    )

    parser.add_argument(
        'report_files',
        nargs='+',
        help='Report files to attach to the email'
    )

    args = parser.parse_args()

    # Load and validate configuration
    try:
        print(f"Loading configuration from: {args.config}")
        config = load_config(args.config)
        validate_config(config)
        print("✅ Configuration loaded and validated successfully")
    except Exception as e:
        print(f"❌ Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Send email
    try:
        print(f"Sending email with {len(args.report_files)} attachment(s):")
        for report in args.report_files:
            print(f"  - {report}")

        success = send_reports(config, args.report_files)

        if success:
            print("✅ Email sent successfully!")
            sys.exit(0)
        else:
            print("❌ Failed to send email (check logs for details)", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        print(f"❌ Error sending email: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
