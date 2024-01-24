import boto3
import time
import traceback
import json

is_testing = False

VERBOSE = 1
isDryRun = False

def get_client(r_name, r_type):
    client = boto3.client(r_type, region_name=r_name)
    return client


def get_regions(client):
    """ Build a region list """

    reg_list = []
    regions = client.describe_regions()
    data_str = json.dumps(regions)
    resp = json.loads(data_str)
    region_str = json.dumps(resp['Regions'])
    region = json.loads(region_str)
    for reg in region:
        reg_list.append(reg['RegionName'])
    return reg_list


def delete_ec2_instances(c_session):
    print("Starting delete_ec2_instances")
    try:
        all_instances = c_session.describe_instances()
        for reservations in all_instances['Reservations']:
            for instance in reservations['Instances']:
                if instance['State']['Name'] != "terminated":
                    instance_id = instance['InstanceId']
                    print(f"Terminating instance - {instance_id}")
                    c_session.terminate_instances(InstanceIds=[instance_id], DryRun=isDryRun)
                    print(f"Terminated instance - {instance_id}")
    except:
        strError = traceback.format_exc()

        print(strError)
    finally:
        print("Stopping delete_ec2_instances")


def delete_ec2_amis(c_session):
    print("Starting delete_ec2_amis")
    try:
        aws_resources = c_session.describe_images(Owners=["357841589350"])
        for aws_resource in aws_resources['Images']:
            aws_resource_id = aws_resource['ImageId']
            print(f"Deleting AWS Resource: {aws_resource_id}")
            c_session.deregister_image(ImageId=aws_resource_id, DryRun=isDryRun)
            print(f"AWS Resource deleted - {aws_resource_id}")
    except:
        print(traceback.format_exc())
    print("Stopping delete_ec2_amis")


def delete_ec2_snapshots(c_session):
    print("Starting delete_ec2_snapshots")
    try:
        aws_resources = c_session.describe_snapshots(OwnerIds=["357841589350"], MaxResults=10, )
        for aws_resource in aws_resources['Snapshots']:
            snapshot_id = aws_resource['SnapshotId']
            print(f"Deleting AWS Resource: {snapshot_id}")
            c_session.delete_snapshot(SnapshotId=snapshot_id, DryRun=isDryRun)
            print(f"Resource deleted - {snapshot_id}")
    except:
        print(traceback.format_exc())
    print("Stopping delete_ec2_snapshots")


def delete_elbv2(c_session):
    print("Starting delete_elbv2")
    try:
        aws_resources = c_session.describe_load_balancers()
        for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
            print(f"Deleting aws resource: {aws_resource['LoadBalancerArn']}")
            if isDryRun:
                continue
            c_session.delete_load_balancer(LoadBalancerArn=aws_resource['LoadBalancerArn'])
            print(f"Deleted aws resource: {aws_resource['LoadBalancerArn']}")
    except:
        print(traceback.format_exc())
    print("Stopping delete_elbv2")


def delete_nat_gateways(c_session):
    print("Starting delete_nat_gateways")
    try:
        aws_resources = c_session.describe_nat_gateways()
        for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
            aws_resource_id = aws_resource['NatGatewayId']
            print(f"Deleting aws resource: {aws_resource_id}")
            c_session.delete_nat_gateway(NatGatewayId=aws_resource_id, DryRun=isDryRun)
            print(f"AWS Resource deleted - {aws_resource_id}")
    except:
        print(traceback.format_exc())
    print("Stopping delete_nat_gateways")


def delete_elastic_ips(c_session):
    print("Starting delete_elastic_ips")
    try:
        aws_resources = c_session.describe_addresses()
        for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
            print(aws_resource)
            print(f"Deleting aws resource")
            if 'AssociationId' in aws_resource.keys():
                c_session.disassociate_address(AssociationId=aws_resource['AssociationId'], DryRun=isDryRun)
            c_session.release_address(AllocationId=aws_resource['AllocationId'], DryRun=isDryRun)
            print(f"AWS Resource deleted - {aws_resource['AllocationId']}")
    except:
        print(traceback.format_exc())

    print("Stopping delete_elastic_ips")


def delete_asg(c_session):
    print("Starting delete_asg")
    try:
        aws_resources = c_session.describe_auto_scaling_groups()
        for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
            if isDryRun:
                continue

            #print(aws_resource)
            print(f"Deleting aws resource")
            r_id = aws_resource['AutoScalingGroupName']
            c_session.update_auto_scaling_group(AutoScalingGroupName=r_id,
                                                MinSize=0, MaxSize=0, DesiredCapacity=0)

            c_session.delete_auto_scaling_group(AutoScalingGroupName=aws_resource['AutoScalingGroupName'],
                                                ForceDelete=True)
            print(f"AWS Resource deleted - {aws_resource['AutoScalingGroupName']}")
    except:
        print(traceback.format_exc())

    print("Stopping delete_asg")


def get_default_vpcs(client):
    vpc_list = []
    vpcs = client.describe_vpcs(
        Filters=[
            {
                'Name': 'isDefault',
                'Values': [
                    'false',
                ],
            },
        ]
    )
    vpcs_str = json.dumps(vpcs)
    resp = json.loads(vpcs_str)
    data = json.dumps(resp['Vpcs'])
    vpcs = json.loads(data)

    for vpc in vpcs:
        vpc_list.append(vpc['VpcId'])

    return vpc_list


def del_igw(ec2, vpcid):
    """ Detach and delete the internet-gateway """
    vpc_resource = ec2.Vpc(vpcid)
    igws = vpc_resource.internet_gateways.all()
    if igws:
        for igw in igws:
            try:
                print("Detaching and Removing igw-id: ", igw.id) if (VERBOSE == 1) else ""
                igw.detach_from_vpc(
                    VpcId=vpcid,
                    DryRun=isDryRun
                )
                igw.delete(
                    DryRun = isDryRun
                )
            except boto3.exceptions.Boto3Error as e:
                print(e)


def del_sub(ec2, vpcid):
    """ Delete the subnets """
    vpc_resource = ec2.Vpc(vpcid)
    subnets = vpc_resource.subnets.all()
    default_subnets = [ec2.Subnet(subnet.id) for subnet in subnets if subnet.default_for_az]

    if default_subnets:
        try:
            for sub in default_subnets:
                print("Removing sub-id: ", sub.id) if (VERBOSE == 1) else ""
                sub.delete(
                    DryRun = isDryRun
                )
        except boto3.exceptions.Boto3Error as e:
            print(e)


def del_rtb(ec2, vpcid):
    """ Delete the route-tables """
    vpc_resource = ec2.Vpc(vpcid)
    rtbs = vpc_resource.route_tables.all()
    if rtbs:
        try:
            for rtb in rtbs:
                try:
                    assoc_attr = [rtb.associations_attribute for rtb in rtbs]
                    #if [rtb_ass[0]['RouteTableId'] for rtb_ass in assoc_attr if rtb_ass[0]['Main'] == True]:
                    #    print(rtb.id + " is the main route table, continue...")
                        #continue
                    print("Removing rtb-id: ", rtb.id) if (VERBOSE == 1) else ""
                    for ass_details in rtb.associations_attribute:
                        RouteTableAssociationId = ass_details['RouteTableAssociationId']
                        try:
                            ec2.disassociate_route_table(AssociationId=RouteTableAssociationId)
                        except:
                            pass


                    table = ec2.RouteTable(rtb.id)
                    table.delete(
                        DryRun = isDryRun
                    )
                except:
                    print(traceback.format_exc())

        except boto3.exceptions.Boto3Error as e:
            print(e)


def del_acl(ec2, vpcid):
    """ Delete the network-access-lists """

    vpc_resource = ec2.Vpc(vpcid)
    acls = vpc_resource.network_acls.all()

    if acls:
        try:
            for acl in acls:
                try:
                    if acl.is_default:
                        print(acl.id + " is the default NACL, continue...")
                        #continue
                    print("Removing acl-id: ", acl.id) if (VERBOSE == 1) else ""
                    acl.delete(
                        DryRun = isDryRun
                    )
                except:
                    print(traceback.format_exc())
        except boto3.exceptions.Boto3Error as e:
            print(e)


def del_sgp(ec2, vpcid):
    """ Delete any security-groups """
    vpc_resource = ec2.Vpc(vpcid)
    sgps = vpc_resource.security_groups.all()
    if sgps:
        try:
            for sg in sgps:
                try:
                    if sg.group_name == 'default':
                        print(sg.id + " is the default security group, continue...")
                        #continue
                    print("Removing sg-id: ", sg.id) if (VERBOSE == 1) else ""
                    sg.delete(
                        DryRun = isDryRun
                )
                except:
                    print(traceback.format_exc())
        except boto3.exceptions.Boto3Error as e:
            print(e)


def del_vpc(ec2, vpcid):
    """ Delete the VPC """
    vpc_resource = ec2.Vpc(vpcid)
    try:
        print("Removing vpc-id: ", vpc_resource.id)
        vpc_resource.delete(
            DryRun = isDryRun
        )
    except boto3.exceptions.Boto3Error as e:
        print(e)
        print("Please remove dependencies and delete VPC manually.")
    except:
        print(traceback.format_exc())
    # finally:
    #  return status


def detach_vpn_gateways(c_session):
    print("Starting detach_vpn_gateways")
    aws_resources = c_session.describe_vpn_gateways()
    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        try:
            for vpn_a in aws_resource['VpcAttachments']:
                if vpn_a['State'] != "detached":
                    print(f"AWS Resource Detaching - {vpn_a}")
                    c_session.detach_vpn_gateway(VpnGatewayId=aws_resource['VpnGatewayId'], VpcId=vpn_a['VpcId'], DryRun = isDryRun)
                    print(f"AWS Resource Detached - {aws_resource['VpnGatewayId']}, {vpn_a['VpcId']}")
        except:
            print(traceback.format_exc())
    print("Stopping detach_vpn_gateways")


def delete_vpn_gateways(c_session):
    print("Starting delete_vpn_gateways")
    aws_resources = c_session.describe_vpn_gateways()
    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        try:
            print(f"Deleting aws resource - {aws_resource}")
            c_session.delete_vpn_gateway(VpnGatewayId=aws_resource['VpnGatewayId'], DryRun = isDryRun)
            print(f"AWS Resource deleted - {aws_resource['VpnGatewayId']}")
        except:
            print(traceback.format_exc())

    print("Starting delete_vpn_gateways")


def delete_vpcs(ec2, c_session):
    print("Starting delete_vpcs")
    try:
        aws_resources = c_session.describe_vpcs()

        for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
            try:
                # print(f"aws resource - {aws_resource}")
                if aws_resource['IsDefault'] == False:
                    vpc_id = aws_resource['VpcId']
                    print(f"Deleting aws resource")
                    del_igw(ec2, vpc_id)
                    del_sub(ec2, vpc_id)
                    del_rtb(ec2, vpc_id)
                    del_acl(ec2, vpc_id)
                    del_sgp(ec2, vpc_id)
                    del_vpc(ec2, vpc_id)
                    print(f"AWS Resource deleted - {aws_resource['VpcId']}")
            except:
                print(traceback.format_exc())
    except:
        print(traceback.format_exc())

    print("Stopping delete_vpcs")


def delete_vpn_connections(c_session):
    print("Starting delete_vpn_connections")
    try:
        aws_resources = c_session.describe_vpn_connections()
        for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
            print(aws_resource)
            vpn_conn_id = aws_resource['VpnConnectionId']
            print(f"Deleting aws resource - {vpn_conn_id}")

            if aws_resource['State'] != "deleted":
                c_session.delete_vpn_connection(VpnConnectionId=vpn_conn_id, DryRun = isDryRun)

            print(f"AWS Resource deleted - {vpn_conn_id}")
    except:
        print(traceback.format_exc())

    print("Stopping delete_elastic_ips")


def delete_ec2_volumes(c_session):
    print("Starting delete_ec2_volumes")
    aws_resources = c_session.describe_volumes()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        if len(aws_resource['Attachments']) == 0:
            r_id = aws_resource['VolumeId']
            print(f"Deleting AWS Resource: {r_id}")
            c_session.delete_volume(VolumeId=r_id, DryRun = isDryRun)
            print(f"Resource deleted - {r_id}")

    print("Stopping delete_ec2_volumes")

def delete_ec2_snapshots(c_session):
    print("Starting delete_ec2_snapshots")
    aws_resources = c_session.describe_snapshots(OwnerIds=["357841589350"], MaxResults=10, )

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        try:
            r_id = aws_resource['SnapshotId']
            print(f"Deleting AWS Resource: {r_id}")
            c_session.delete_snapshot(SnapshotId=r_id, DryRun = isDryRun)
            print(f"Resource deleted - {r_id}")
        except:
            print(traceback.format_exc())

    print("Stopping delete_ec2_snapshots")

def delete_rds_clusters(c_session):
    print("Starting delete_rds_clusters")

    aws_resources = c_session.describe_db_clusters()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['DBClusterIdentifier']
        print(f"Deleting AWS Resource: {r_id}")
        c_session.delete_db_cluster(
            DBClusterIdentifier=r_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
            DryRun = isDryRun,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_rds_clusters")


def delete_rds_instances(c_session):
    print("Starting delete_rds_instances")

    aws_resources = c_session.describe_db_instances()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['DBInstanceIdentifier']
        print(f"Deleting AWS Resource: {r_id}")
        c_session.delete_db_instance(
            DBInstanceIdentifier=r_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
            DryRun=isDryRun,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_rds_instances")

def delete_s3_bucket(c_session):
    print("Starting delete_s3_bucket")

    aws_resources = c_session.list_buckets()

    for aws_resource in aws_resources['Buckets']:
        if isDryRun: continue

        r_id = aws_resource['Name']
        print(f"Deleting AWS Resource: {r_id}")

        s3 = boto3.resource("s3")
        bucket = s3.Bucket(r_id)
        bucket_versioning = s3.BucketVersioning(r_id)
        if bucket_versioning.status == 'Enabled':
            bucket.object_versions.delete()
        else:
            bucket.objects.all().delete()
        c_session.delete_bucket(
            Bucket=r_id,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_s3_bucket")


def delete_eks(c_session):
    print("Starting delete_eks")

    aws_resources = c_session.list_clusters()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        try:
            r_id = aws_resource['DBInstanceIdentifier']
            print(f"Deleting AWS Resource: {r_id}")
            c_session.delete_db_instance(
                DBInstanceIdentifier=r_id,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True,
                DryRun=isDryRun,
            )
            print(f"Resource deleted - {r_id}")
        except:
            print(traceback.format_exc())

    print("Stopping delete_eks")



def delete_cloudwatch_alarms(c_session):
    print("Starting delete_cloudwatch_alarms")

    aws_resources = c_session.describe_alarms()

    for aws_cw_alarm in list(aws_resources.keys()):
        if aws_cw_alarm not in ['CompositeAlarms', 'MetricAlarms']:
            continue

        for aws_resource in aws_resources[aws_cw_alarm]:
            r_id = aws_resource['AlarmName']
            print(f"Deleting AWS Resource: {r_id}")

            if isDryRun:
                continue

            c_session.delete_alarms(
                AlarmNames=[r_id],
            )
            print(f"Resource deleted - {r_id}")

    print("Stopping delete_cloudwatch_alarms")


def delete_sns_topics(c_session):
    print("Starting delete_sns_topics")

    aws_resources = c_session.list_topics()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['TopicArn']
        print(f"Deleting AWS Resource: {r_id}")

        if isDryRun:
            continue

        c_session.delete_topic(
            TopicArn=r_id,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_sns_topics")



def delete_sqs(c_session):
    print("Starting delete_sqs")

    aws_resources = c_session.list_queues()

    if 'QueueUrls' not in list(aws_resources.keys()):
        return

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        if aws_resource == "ResponseMetadata":
            continue

        r_id = aws_resource
        print(f"Deleting AWS Resource: {r_id}")

        if isDryRun:
            continue

        c_session.delete_queue(
            QueueUrl=r_id,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_sqs")


def delete_rds_cluster_snapshots(c_session):
    print("Starting delete_rds_cluster_snapshots")

    aws_resources = c_session.describe_db_cluster_snapshots()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['DBClusterSnapshotIdentifier']
        print(f"Deleting AWS Resource: {r_id}")

        if isDryRun:
            continue

        c_session.delete_db_cluster_snapshot(
            DBClusterSnapshotIdentifier=r_id,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_rds_cluster_snapshots")


def delete_rds_snapshots(c_session):
    print("Starting delete_rds_snapshots")

    aws_resources = c_session.describe_db_snapshots()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['DBSnapshotIdentifier']
        print(f"Deleting AWS Resource: {r_id}")

        if isDryRun:
            continue

        c_session.delete_db_cluster_snapshot(
            DBSnapshotIdentifier=r_id,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_rds_snapshots")


def delete_customer_gateways(c_session):
    print("Starting delete_customer_gateways")

    aws_resources = c_session.describe_customer_gateways()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        if aws_resource['State'] == "deleted":
            continue

        r_id = aws_resource['CustomerGatewayId']
        print(f"Deleting AWS Resource: {r_id}")

        if isDryRun:
            continue

        c_session.delete_customer_gateway(
            CustomerGatewayId=r_id,
            DryRun = isDryRun
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_customer_gateways")


def delete_ec2_target_groups(c_session):
    print("Starting delete_ec2_target_groups")

    aws_resources = c_session.describe_target_groups()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['TargetGroupArn']
        print(f"Deleting AWS Resource: {r_id}")

        if isDryRun:
            continue

        c_session.delete_target_group(
            TargetGroupArn=r_id,
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_ec2_target_groups")


def delete_security_groups(c_session):
    print("Starting delete_security_groups")

    aws_resources = c_session.describe_security_groups()

    for aws_resource in aws_resources[list(aws_resources.keys())[0]]:
        r_id = aws_resource['GroupName']

        if "default" in r_id.lower():
            continue

        print(f"Deleting AWS Resource: {r_id}")


        c_session.delete_security_group(
            GroupName=r_id, DryRun=isDryRun
        )
        print(f"Resource deleted - {r_id}")

    print("Stopping delete_security_groups")


if __name__ == "__main__" and not is_testing:
    ec2_client = boto3.client('ec2')
    all_regions = get_regions(ec2_client)
    print(f"------------------------------------------Dry Run: {isDryRun}")
    sure = "No"
    if not isDryRun:
        print("All the resources in all the regions will get deleted")
        sure = input("Are you sure to proceed? (Yes/ No): ")
        if sure != "Yes":
            exit()
    else:
        sure = "Yes"

    for r_name in all_regions:
        #if r_name != "us-east-1":
        #    continue

        if sure != "Yes":
            continue
        try:
            # time.sleep(1)
            print(f"----------------------Working with region: {r_name}")
            c_session = get_client(r_name, 'elbv2')
            delete_elbv2(c_session)

            c_session = get_client(r_name, 'autoscaling')
            delete_asg(c_session)

            c_session = get_client(r_name, 'ec2')
            delete_ec2_instances(c_session)
            delete_ec2_amis(c_session)
            delete_ec2_snapshots(c_session)

            c_session = get_client(r_name, 'ec2')
            delete_nat_gateways(c_session)
            delete_elastic_ips(c_session)
            delete_vpn_connections(c_session)
            detach_vpn_gateways(c_session)

            ec2 = boto3.resource('ec2', region_name=r_name)
            c_session = get_client(r_name, 'ec2')
            delete_vpcs(ec2, c_session)

            c_session = get_client(r_name, 'ec2')
            delete_ec2_volumes(c_session)

            c_session = get_client(r_name, 'rds')
            delete_rds_instances(c_session)
            delete_rds_clusters(c_session)

            c_session = get_client(r_name, 's3')
            delete_s3_bucket(c_session)

            c_session = get_client(r_name, 'cloudwatch')
            delete_cloudwatch_alarms(c_session)

            c_session = get_client(r_name, 'sns')
            delete_sns_topics(c_session)

            c_session = get_client(r_name, 'sqs')
            delete_sqs(c_session)

            c_session = get_client(r_name, 'ec2')
            delete_customer_gateways(c_session)

            c_session = get_client(r_name, 'elbv2')
            delete_ec2_target_groups(c_session)

            c_session = get_client(r_name, 'ec2')
            delete_security_groups(c_session)
        except:
            print(f"Error while working with region {r_name}")





if is_testing:
    #c_session = get_client('us-east-1', 'eks')
    #delete_eks(c_session)

    c_session = get_client("us-east-1", 'autoscaling')
    delete_asg(c_session)

    ec2 = boto3.resource('ec2', region_name="us-east-1")
    c_session = get_client("us-east-1", 'ec2')
    delete_vpcs(ec2, c_session)



