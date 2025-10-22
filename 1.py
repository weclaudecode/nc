#!/usr/bin/env python3
"""
AWS Resource Discovery Notifier

Discovers AWS resources (EC2, RDS, EKS) affected by scheduled stop actions
and generates Markdown and CSV reports for team notification.

Usage:
    python resource-discovery-notifier.py --config config/pipeline-configs.yml --config-name dev-stop --output reports/

Author: DevOps Team
Version: 2.0.0
"""

import boto3
import yaml
import csv
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

# Configuration
DEFAULT_REGION = 'ap-southeast-2'  # Sydney


@dataclass
class DiscoveredResource:
    """Represents a discovered AWS resource"""
    resource_type: str
    resource_id: str
    name: str
    state: str
    instance_type_or_engine: str
    additional_info: str


class ConfigParser:
    """Parse and validate pipeline-configs.yml"""

    def __init__(self, config_file: str):
        """Initialize config parser with YAML file path"""
        if not os.path.exists(config_file):
            print(f"ERROR: Config file not found: {config_file}")
            sys.exit(1)

        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"ERROR: Failed to parse YAML config: {e}")
            sys.exit(1)

        if not self.config or 'configurations' not in self.config:
            print("ERROR: Invalid config structure - missing 'configurations' key")
            sys.exit(1)

    def get_configurations(self) -> Dict:
        """Return all configurations from the config file"""
        return self.config.get('configurations', {})

    @staticmethod
    def extract_environment(config_name: str) -> str:
        """
        Extract environment name from config name.
        Convention: {env}-{action} (e.g., 'dev-stop' -> 'dev')
        """
        return config_name.split('-')[0] if '-' in config_name else config_name

    @staticmethod
    def is_stop_action(service: str, action: str) -> bool:
        """
        Check if the action is a stop action for the given service.

        Stop actions:
            - EC2: 'stop'
            - RDS: 'stop'
            - EKS: 'scale-down'
        """
        stop_actions = {
            'ec2': ['stop'],
            'rds': ['stop'],
            'eks': ['scale-down']
        }
        return action in stop_actions.get(service, [])


class AWSClientManager:
    """Manage AWS client creation using default IAM role credentials"""

    def __init__(self, region: str = DEFAULT_REGION):
        """Initialize AWS client manager with specified region"""
        self.region = region
        print(f"  → Using default IAM credentials for region: {region}")

    def get_client(self, service: str):
        """Create boto3 client with default IAM credentials"""
        try:
            return boto3.client(service, region_name=self.region)
        except Exception as e:
            print(f"ERROR: Failed to create {service} client: {e}")
            sys.exit(1)


class ResourceDiscoverer:
    """Discover AWS resources based on tags and configuration"""

    def __init__(self, aws_manager: AWSClientManager):
        """Initialize resource discoverer with AWS client manager"""
        self.aws_manager = aws_manager

    def discover_ec2(self, tag_key: str, tag_value: str) -> List[DiscoveredResource]:
        """
        Discover EC2 instances matching the specified tag.
        Returns list of DiscoveredResource objects.
        """
        try:
            print(f"  → Discovering EC2 instances with tag {tag_key}={tag_value}")
            ec2 = self.aws_manager.get_client('ec2')

            response = ec2.describe_instances(
                Filters=[
                    {'Name': f'tag:{tag_key}', 'Values': [tag_value]}
                ]
            )

            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    # Extract Name tag
                    name = next(
                        (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'),
                        'N/A'
                    )

                    # Build additional info
                    az = instance['Placement']['AvailabilityZone']
                    private_ip = instance.get('PrivateIpAddress', 'N/A')
                    additional_info = f"AZ={az}, IP={private_ip}"

                    instances.append(DiscoveredResource(
                        resource_type='EC2',
                        resource_id=instance['InstanceId'],
                        name=name,
                        state=instance['State']['Name'],
                        instance_type_or_engine=instance['InstanceType'],
                        additional_info=additional_info
                    ))

            print(f"    Found {len(instances)} EC2 instances")
            return instances

        except Exception as e:
            print(f"ERROR: Failed to discover EC2 instances: {e}")
            sys.exit(1)

    def discover_rds(self, tag_key: str, tag_value: str) -> List[DiscoveredResource]:
        """
        Discover RDS instances matching the specified tag.
        Uses describe_db_instances + list_tags_for_resource pattern.
        """
        try:
            print(f"  → Discovering RDS instances with tag {tag_key}={tag_value}")
            rds = self.aws_manager.get_client('rds')

            # Get all DB instances
            response = rds.describe_db_instances()

            instances = []
            for db_instance in response['DBInstances']:
                # Get tags for this instance
                arn = db_instance['DBInstanceArn']
                try:
                    tags_response = rds.list_tags_for_resource(ResourceName=arn)
                    tags_dict = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}

                    # Check if tag matches
                    if tags_dict.get(tag_key) == tag_value:
                        # Build additional info
                        engine_version = db_instance.get('EngineVersion', 'N/A')
                        instance_class = db_instance.get('DBInstanceClass', 'N/A')
                        multi_az = db_instance.get('MultiAZ', False)
                        additional_info = f"Version={engine_version}, Class={instance_class}, MultiAZ={multi_az}"

                        instances.append(DiscoveredResource(
                            resource_type='RDS',
                            resource_id=db_instance['DBInstanceIdentifier'],
                            name=db_instance['DBInstanceIdentifier'],
                            state=db_instance['DBInstanceStatus'],
                            instance_type_or_engine=db_instance['Engine'],
                            additional_info=additional_info
                        ))
                except Exception as e:
                    print(f"    WARNING: Failed to get tags for {arn}: {e}")
                    continue

            print(f"    Found {len(instances)} RDS instances")
            return instances

        except Exception as e:
            print(f"ERROR: Failed to discover RDS instances: {e}")
            sys.exit(1)

    def extract_eks_clusters(self, inputs: Dict) -> List[DiscoveredResource]:
        """
        Extract EKS cluster names directly from config (no AWS API call).
        Per requirement: EKS uses cluster names directly.
        """
        cluster_name = inputs.get('cluster_name', '')
        if cluster_name:
            print(f"  → Extracting EKS cluster from config: {cluster_name}")
            return [DiscoveredResource(
                resource_type='EKS',
                resource_id=cluster_name,
                name=cluster_name,
                state='from-config',
                instance_type_or_engine='N/A',
                additional_info='Source=pipeline-configs.yml'
            )]
        print(f"    No cluster_name found in inputs")
        return []


class ReportGenerator:
    """Generate Markdown and CSV reports"""

    def __init__(self, output_dir: str, region: str, config_name: str):
        """Initialize report generator"""
        self.output_dir = output_dir
        self.region = region
        self.config_name = config_name
        self.timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def generate_markdown(self, all_results: Dict):
        """Generate Markdown report for single configuration"""
        output_file = os.path.join(self.output_dir, f'{self.config_name}-impact-report.md')

        # Extract single configuration data
        config_name = self.config_name
        config_data = all_results[config_name]
        env = config_data['environment']
        resources = config_data['resources']

        with open(output_file, 'w') as f:
            # Header
            f.write(f"# AWS Scheduler Impact Report - {config_name}\n\n")
            f.write(f"**Configuration:** {config_name}  \n")
            f.write(f"**Environment:** {env}  \n")
            f.write(f"**Generated:** {self.timestamp}  \n")
            f.write(f"**Region:** {self.region}  \n\n")
            f.write("---\n\n")

            # Summary counts
            ec2_count = len(resources.get('ec2', {}).get('resources', []))
            rds_count = len(resources.get('rds', {}).get('resources', []))
            eks_count = len(resources.get('eks', {}).get('resources', []))
            total = ec2_count + rds_count + eks_count

            f.write("## Summary\n\n")
            f.write(f"**Total Affected Resources:** {total}  \n")
            f.write(f"- EC2 Instances: {ec2_count}  \n")
            f.write(f"- RDS Instances: {rds_count}  \n")
            f.write(f"- EKS Clusters: {eks_count}  \n\n")
            f.write("---\n\n")

            # Resource details
            f.write("## Resource Details\n\n")

            has_resources = False

            # EC2 Section
            if 'ec2' in resources:
                ec2_data = resources['ec2']
                ec2_resources = ec2_data.get('resources', [])

                if ec2_resources:
                    has_resources = True
                    f.write(f"### EC2 Instances ({len(ec2_resources)})\n\n")
                    f.write(f"**Action:** {ec2_data['action']}  \n")

                    filter_info = ec2_data.get('filter', {})
                    tag_key = filter_info.get('tag_key', 'N/A')
                    tag_value = filter_info.get('tag_value', 'N/A')
                    f.write(f"**Filter:** Tag `{tag_key}` = `{tag_value}`\n\n")

                    f.write("| Instance ID | Name | Instance Type | State | Additional Info |\n")
                    f.write("|-------------|------|--------------|-------|----------------|\n")

                    for resource in ec2_resources:
                        f.write(f"| {resource.resource_id} | {resource.name} | "
                               f"{resource.instance_type_or_engine} | {resource.state} | "
                               f"{resource.additional_info} |\n")
                    f.write("\n")

            # RDS Section
            if 'rds' in resources:
                rds_data = resources['rds']
                rds_resources = rds_data.get('resources', [])

                if rds_resources:
                    has_resources = True
                    f.write(f"### RDS Instances ({len(rds_resources)})\n\n")
                    f.write(f"**Action:** {rds_data['action']}  \n")

                    filter_info = rds_data.get('filter', {})
                    tag_key = filter_info.get('tag_key', 'N/A')
                    tag_value = filter_info.get('tag_value', 'N/A')
                    f.write(f"**Filter:** Tag `{tag_key}` = `{tag_value}`\n\n")

                    f.write("| DB Instance ID | Engine | State | Additional Info |\n")
                    f.write("|----------------|--------|-------|----------------|\n")

                    for resource in rds_resources:
                        f.write(f"| {resource.resource_id} | {resource.instance_type_or_engine} | "
                               f"{resource.state} | {resource.additional_info} |\n")
                    f.write("\n")

            # EKS Section
            if 'eks' in resources:
                eks_data = resources['eks']
                eks_resources = eks_data.get('resources', [])

                if eks_resources:
                    has_resources = True
                    f.write(f"### EKS Clusters ({len(eks_resources)})\n\n")
                    f.write(f"**Action:** {eks_data['action']}  \n\n")

                    f.write("| Cluster Name | Source |\n")
                    f.write("|--------------|--------|\n")

                    for resource in eks_resources:
                        f.write(f"| {resource.resource_id} | {resource.state} |\n")
                    f.write("\n")

            # No resources message
            if not has_resources:
                f.write("⚠️ **No resources found matching stop action criteria**\n\n")

            f.write("---\n\n")

        print(f"\n✅ Markdown report generated: {output_file}")

    def generate_csv(self, all_results: Dict):
        """Generate CSV report for single configuration"""
        output_file = os.path.join(self.output_dir, f'{self.config_name}-impact-report.csv')

        # Extract single configuration data
        config_name = self.config_name
        config_data = all_results[config_name]
        env = config_data['environment']
        resources = config_data['resources']

        with open(output_file, 'w', newline='') as f:
            fieldnames = [
                'Environment', 'Configuration', 'Service', 'Action',
                'Resource ID', 'Name', 'State', 'Instance Type/Engine', 'Additional Info'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            # Process each service
            for service_type in ['ec2', 'rds', 'eks']:
                if service_type in resources:
                    service_data = resources[service_type]
                    action = service_data.get('action', 'N/A')
                    discovered_resources = service_data.get('resources', [])

                    for resource in discovered_resources:
                        writer.writerow({
                            'Environment': env,
                            'Configuration': config_name,
                            'Service': resource.resource_type,
                            'Action': action,
                            'Resource ID': resource.resource_id,
                            'Name': resource.name,
                            'State': resource.state,
                            'Instance Type/Engine': resource.instance_type_or_engine,
                            'Additional Info': resource.additional_info
                        })

        print(f"✅ CSV report generated: {output_file}")


def main():
    """Main execution function"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Discover AWS resources affected by scheduler stop actions for a single configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python resource-discovery-notifier.py --config config/pipeline-configs.yml --config-name dev-stop
  python resource-discovery-notifier.py --config config/pipeline-configs.yml --config-name staging-stop --region us-east-1
  python resource-discovery-notifier.py --config config/pipeline-configs.yml --config-name uat-stop --output reports/
        """
    )

    parser.add_argument(
        '--config',
        required=True,
        help='Path to pipeline-configs.yml file'
    )
    parser.add_argument(
        '--config-name',
        required=True,
        help='Configuration name to process (e.g., dev-stop, staging-stop)'
    )
    parser.add_argument(
        '--output',
        default='reports/',
        help='Output directory for reports (default: reports/)'
    )
    parser.add_argument(
        '--region',
        default=DEFAULT_REGION,
        help=f'AWS region (default: {DEFAULT_REGION})'
    )

    args = parser.parse_args()

    print("=" * 80)
    print("AWS Scheduler Resource Discovery Notifier")
    print("=" * 80)
    print(f"Config: {args.config}")
    print(f"Output: {args.output}")
    print(f"Region: {args.region}")
    print("=" * 80)
    print()

    # Initialize components
    config_parser = ConfigParser(args.config)
    aws_manager = AWSClientManager(args.region)
    discoverer = ResourceDiscoverer(aws_manager)

    # Get single configuration by name
    config_name = args.config_name
    configurations = config_parser.get_configurations()

    # Validate configuration exists
    if config_name not in configurations:
        print(f"ERROR: Configuration '{config_name}' not found in {args.config}")
        print(f"Available configurations: {', '.join(configurations.keys())}")
        sys.exit(1)

    config_data = configurations[config_name]
    print(f"Processing configuration: {config_name}\n")

    # Extract environment from config name
    environment = config_parser.extract_environment(config_name)

    # Initialize results for this single configuration
    all_results = {
        config_name: {
            'environment': environment,
            'resources': {}
        }
    }

    # Process each service (ec2, rds, eks)
    for service in ['ec2', 'rds', 'eks']:
        if service not in config_data:
            continue

        service_config = config_data[service]

        # Check if service is enabled
        if not service_config.get('enabled', False):
            print(f"  ✗ {service.upper()}: disabled (skipped)")
            continue

        # Check if action is a stop action
        action = service_config.get('action', '')
        if not config_parser.is_stop_action(service, action):
            print(f"  ✗ {service.upper()}: action '{action}' is not a stop action (skipped)")
            continue

        print(f"  ✓ {service.upper()}: enabled with action '{action}'")

        # Extract inputs
        inputs = service_config.get('inputs', {})

        # Discover resources using default IAM credentials
        resources = []
        if service == 'ec2':
            tag_key = inputs.get('tag_key')
            tag_value = inputs.get('tag_value')
            # Convert to strings to handle YAML boolean values (AWS API requires strings)
            if tag_key is not None:
                tag_key = str(tag_key)
            if tag_value is not None:
                tag_value = str(tag_value)
            if tag_key and tag_value:
                resources = discoverer.discover_ec2(tag_key, tag_value)
            else:
                print(f"    WARNING: Missing tag_key or tag_value for EC2")

        elif service == 'rds':
            tag_key = inputs.get('tag_key')
            tag_value = inputs.get('tag_value')
            # Convert to strings to handle YAML boolean values (AWS API requires strings)
            if tag_key is not None:
                tag_key = str(tag_key)
            if tag_value is not None:
                tag_value = str(tag_value)
            if tag_key and tag_value:
                resources = discoverer.discover_rds(tag_key, tag_value)
            else:
                print(f"    WARNING: Missing tag_key or tag_value for RDS")

        elif service == 'eks':
            resources = discoverer.extract_eks_clusters(inputs)

        # Store results
        all_results[config_name]['resources'][service] = {
            'action': action,
            'filter': inputs,
            'resources': resources
        }

    print()

    # Generate reports
    print("=" * 80)
    print("Generating Reports")
    print("=" * 80)

    report_gen = ReportGenerator(args.output, args.region, config_name)
    report_gen.generate_markdown(all_results)
    report_gen.generate_csv(all_results)

    print()
    print("=" * 80)
    print("✅ Resource discovery completed successfully!")
    print("=" * 80)


if __name__ == '__main__':
    main()
