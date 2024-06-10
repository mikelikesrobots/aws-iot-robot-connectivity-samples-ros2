import boto3
from botocore.exceptions import ClientError
import click
import os


def delete_thing_and_related_resources(thing_name, iot_client, certs_path):
    def get_principals(thing_name):
        try:
            response = iot_client.list_thing_principals(thingName=thing_name)
            return response.get('principals', [])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"Thing {thing_name} not found.")
                return []
            else:
                raise e

    def list_policies(certificate_arn):
        try:
            response = iot_client.list_attached_policies(target=certificate_arn)
            return [policy['policyName'] for policy in response.get('policies', [])]
        except ClientError as e:
            raise e

    def detach_and_delete_policies(certificate_arn):
        policies = list_policies(certificate_arn)
        for policy_name in policies:
            try:
                iot_client.detach_policy(policyName=policy_name, target=certificate_arn)
                print(f"Detached policy {policy_name} from certificate {certificate_arn}.")
                iot_client.delete_policy(policyName=policy_name)
                print(f"Deleted policy {policy_name}.")
            except ClientError as e:
                print(f"Error detaching policy {policy_name} from certificate {certificate_arn}: {e}")

    def detach_and_delete_certificates(thing_name):
        principals = get_principals(thing_name)
        for certificate_arn in principals:
            certificate_id = certificate_arn.split('/')[-1]
            
            # Detach policies
            detach_and_delete_policies(certificate_arn)
            
            # Detach the certificate from the thing
            try:
                iot_client.detach_thing_principal(thingName=thing_name, principal=certificate_arn)
                print(f"Detached certificate {certificate_arn} from thing {thing_name}.")
            except ClientError as e:
                print(f"Error detaching certificate {certificate_arn} from thing {thing_name}: {e}")
            
            # Update the certificate status to INACTIVE
            try:
                iot_client.update_certificate(certificateId=certificate_id, newStatus='INACTIVE')
                print(f"Updated certificate {certificate_id} status to INACTIVE.")
            except ClientError as e:
                print(f"Error updating certificate {certificate_id} status to INACTIVE: {e}")
            
            # Delete the certificate
            try:
                iot_client.delete_certificate(certificateId=certificate_id, forceDelete=True)
                print(f"Deleted certificate {certificate_id}.")
            except ClientError as e:
                print(f"Error deleting certificate {certificate_id}: {e}")

    def delete_thing(thing_name):
        try:
            iot_client.delete_thing(thingName=thing_name)
            print(f"Deleted thing {thing_name}.")
        except ClientError as e:
            print(f"Error deleting thing {thing_name}: {e}")

    def remove_files(thing_name, certs_path):
        cert_path = os.path.join(certs_path, f"{thing_name}.cert.pem")
        priv_path = os.path.join(certs_path, f"{thing_name}.private.key")
        pub_path = os.path.join(certs_path, f"{thing_name}.public.key")

        for _file in (cert_path, priv_path, pub_path):
            print("Deleting file:", _file)
            os.remove(_file)

    # Process to delete the Thing and its related resources
    detach_and_delete_certificates(thing_name)
    delete_thing(thing_name)
    remove_files(thing_name, certs_path)


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

    iot_client = boto3.client("iot", region)
    for name in names:
        delete_thing_and_related_resources(name, iot_client, certs_path)


if __name__ == '__main__':
    main()
