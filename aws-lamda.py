import boto3
import csv
from dotenv import load_dotenv
import os

#load environment variable
load_dotenv()

#access the environment variables
aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

#Boto3 lambda 
lambda_client = boto3.client(
    'lambda',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

#using Ec2 to get region region
ec2_client = boto3.client('ec2')
regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

#list to store the arn and role name-
vulnerable_functions = []

#list of all region
for region in regions:
    print(region)

    #lamda client current region
    lambda_client = boto3.client('lambda', region_name=region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    #list of all Lambda functions available in region
    response = lambda_client.list_functions()

    #using loop for printing all the response lamda fuction name
    for function in response['Functions']:
        function_name = function['FunctionName']
        print(function_name)

    #used to get iam role of each lamda func
        function_configuration = lambda_client.get_function_configuration(FunctionName=function_name)
        role_arn = function_configuration['Role']
        #spliting the last arn word
        role_name = role_arn.split('/')[-1]

        #printintg iam roles
        print(role_name)

        #boto3 client
        iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        #using list_attached_role_policies
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        attached_policies = response['AttachedPolicies']

        #checking if AdministratorAccess policy is attached to the role
        has_admin_access = any(policy['PolicyName'] == 'AdministratorAccess' for policy in attached_policies)
        print(has_admin_access)


        if has_admin_access:
            vulnerable_functions.append((function['FunctionArn'], role_name))

#static csv file created by python
csv_file = 'custom_filename.csv'

#appending the lamda arn and role name in csv
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Function ARN', 'Role Name'])
    for function_arn, role_name in vulnerable_functions:
        writer.writerow([function_arn, role_name])

print(f"CSV file '{csv_file}' generated successfully.")




    
