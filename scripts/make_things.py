import boto3
from botocore.exceptions import ClientError
import click
import json
import os
import requests

POLICY_TEMPLATE = """
{{
    "Version": "2012-10-17",
    "Statement": [
        {{
            "Effect": "Allow",
            "Action": [
                "iot:Connect"
            ],
            "Resource": "arn:aws:iot:{region}:{account_id}:client/{thing_name}"
        }},
        {{
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                "arn:aws:iot:{region}:{account_id}:topicfilter/$aws/things/{thing_name}/shadow/name/{shadow_name}/update/documents"
            ]
        }},
        {{
            "Effect": "Allow",
            "Action": "iot:Receive",
            "Resource": [
                "arn:aws:iot:{region}:{account_id}:topic/$aws/things/{thing_name}/shadow/name/{shadow_name}/update/documents"
            ]
        }},
        {{
            "Effect": "Allow",
            "Action": "iot:Publish",
            "Resource": [
                "arn:aws:iot:{region}:{account_id}:topic/$aws/things/{thing_name}/shadow/name/{shadow_name}/update"
            ]
        }},
        {{
            "Effect": "Allow",
            "Action": [
                "iot:Publish",
                "iot:Receive",
                "iot:RetainPublish"
            ],
            "Resource": [
                "arn:aws:iot:{region}:{account_id}:topic/ros2_mock_telemetry_topic",
                "arn:aws:iot:{region}:{account_id}:topic/cmd_vel",
                "arn:aws:iot:{region}:{account_id}:topic/$aws/rules/*"
            ]
        }},
        {{
            "Effect": "Allow",
            "Action": [
                "iot:Subscribe"
            ],
            "Resource": [
                "arn:aws:iot:{region}:{account_id}:topicfilter/ros2_mock_telemetry_topic",
                "arn:aws:iot:{region}:{account_id}:topicfilter/cmd_vel"
            ]
        }}
    ]
}}
"""
ROOT_CA_NAME = "rootCA.crt"


def get_account_id():
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    account_id = response['Account']
    return account_id


def get_iot_endpoint(iot_client):
    response = iot_client.describe_endpoint(endpointType='iot:Data-ATS')
    return response['endpointAddress']


def download_root_ca(download_path):
    ca_url = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
    ca_file_path = os.path.join(download_path, ROOT_CA_NAME)

    if not os.path.exists(ca_file_path):
        response = requests.get(ca_url)
        response.raise_for_status()
        with open(ca_file_path, 'wb') as ca_file:
            ca_file.write(response.content)
        print(f"Root CA certificate downloaded to {ca_file_path}")
    else:
        print("Root CA certificate already exists.")



def check_thing_exists(iot_client, thing_name):
    try:
        iot_client.describe_thing(thingName=thing_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
        else:
            raise e


def check_policy_exists(iot_client, policy_name):
    try:
        iot_client.get_policy(policyName=policy_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return False
        else:
            raise e


def create_thing(iot_client, iot_data_client, thing_name, shadow_name):
    if not check_thing_exists(iot_client, thing_name):
        iot_client.create_thing(thingName=thing_name)
        print(f"Thing {thing_name} created.")
    else:
        print(f"Thing {thing_name} already exists.")
        return

    # Create an initial shadow state for the named shadow
    shadow_state = {
        "state": {
            "desired": {},
            "reported": {}
        }
    }
    iot_data_client.update_thing_shadow(
        thingName=thing_name,
        shadowName=shadow_name,
        payload=json.dumps(shadow_state)
    )
    print(f"Named shadow {shadow_name} for thing {thing_name} created with initial state.")


def create_certificate_and_keys(iot_client, name, path):
    response = iot_client.create_keys_and_certificate(setAsActive=True)
    certificate_arn = response['certificateArn']
    certificate_id = response['certificateId']
    certificate_pem = response['certificatePem']
    key_pair = response['keyPair']
    private_key = key_pair['PrivateKey']
    public_key = key_pair['PublicKey']

    # Save the certificate and keys to the specified path
    os.makedirs(path, exist_ok=True)
    cert_path = os.path.join(path, f'{name}.cert.pem')
    priv_path = os.path.join(path, f'{name}.private.key')
    pub_path = os.path.join(path, f'{name}.public.key')
    with open(cert_path, 'w') as cert_file:
        cert_file.write(certificate_pem)
    with open(priv_path, 'w') as private_key_file:
        private_key_file.write(private_key)
    with open(pub_path, 'w') as public_key_file:
        public_key_file.write(public_key)

    print(f"Certificate and keys saved to {path} for certificate ID: {certificate_id} with name: {name}")
    return certificate_arn, cert_path, priv_path, pub_path


def create_policy(iot_client, policy_name, policy_document):
    if not check_policy_exists(iot_client, policy_name):
        iot_client.create_policy(
            policyName=policy_name,
            policyDocument=policy_document
        )
        print(f"Policy {policy_name} created.")
    else:
        print(f"Policy {policy_name} already exists.")


def attach_policy_to_certificate(iot_client, policy_name, certificate_arn):
    iot_client.attach_policy(
        policyName=policy_name,
        target=certificate_arn
    )
    print(f"Policy {policy_name} attached to certificate {certificate_arn}.")


def attach_thing_to_certificate(iot_client, thing_name, certificate_arn):
    iot_client.attach_thing_principal(
        thingName=thing_name,
        principal=certificate_arn
    )
    print(f"Thing {thing_name} attached to certificate {certificate_arn}.")


@click.command()
@click.argument("names", nargs=-1)
def main(names):

    root_path = os.path.abspath(os.path.dirname(__file__) + "/..")

    region = os.getenv("AWS_REGION", "us-west-2")
    print("Region is:", region)
    certs_path = os.getenv(
        "CERT_FOLDER_LOCATION",
        root_path + "/iot_certs_and_config/"
    )
    print("Certs path is:", certs_path)

    config_template_path = root_path + "/templates/iot_config_template.json"
    with open(config_template_path) as f:
        config_template = f.read()

    account_id = get_account_id()

    download_root_ca(certs_path)

    iot_client = boto3.client("iot", region)
    iot_data_client = boto3.client("iot-data", region)
    iot_endpoint = get_iot_endpoint(iot_client)
    print("IoT Endpoint:", iot_endpoint)
    for name in names:
        shadow_name = "{}-shadow".format(name)
        policy_name = "{}-policy".format(name)
        create_thing(iot_client, iot_data_client, name, shadow_name)
        cert_arn, cert_path, priv_path, _pub_path = create_certificate_and_keys(iot_client, name, certs_path)
        policy_document = POLICY_TEMPLATE.format(
            region=region,
            account_id=account_id,
            thing_name=name,
            shadow_name=shadow_name,
        )
        # Sanity check that JSON is valid, and strip spaces
        policy_document = json.dumps(json.loads(policy_document))

        create_policy(iot_client, policy_name, policy_document)
        attach_policy_to_certificate(iot_client, policy_name, cert_arn)
        attach_thing_to_certificate(iot_client, name, cert_arn)

        config = (
            config_template
                .replace("ENDPOINT", iot_endpoint)
                .replace("ROOTCA", os.path.join(certs_path, ROOT_CA_NAME))
                .replace("CERTPATH", cert_path)
                .replace("PRIVATEKEY", priv_path)
                .replace("PORT", "8883")
                .replace("CLIENT", name)
                .replace("REGION", region)
        )
        config_path = os.path.join(certs_path, f"iot_config_{name}.json")
        with open(config_path, "w") as f:
            f.write(config)
        print("Config written to", config_path)
        print(f"Setup complete for {name}.")

    print("Setup complete.")


if __name__ == '__main__':
    main()
