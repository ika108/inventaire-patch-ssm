import boto3
import time
from datetime import datetime, timezone
import sys
import pprint
import re
import json
from termcolor import colored
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_result, before_sleep_log

## Patch Managment Acceptancy critera : KPI (%) = 100 - ((nb_instance_with_old_pending_patches / nb_instances) * 100 )
## old_pending_patches = pending more than 30 Days

instances_state = {}

debug = False

# ThereMIGHT be a slight TZ issue with this. Windows systeminfo command doesn't provide any TZ information
def convert_windows_to_epoch(date_str):
    stripped_date_str = re.search(r'\d+/\d+/\d+, \d+:\d+:\d+ (AM|PM)',date_str)
    # Define the expected date format from systeminfo output

    date_format = "%m/%d/%Y, %I:%M:%S %p"  # Adjust the format if necessary
    # Convert the date string to a datetime object
    try:
        datetime_obj = datetime.strptime(stripped_date_str.group(), date_format)
        # Convert datetime object to Unix epoch time
        epoch_time = int(datetime_obj.timestamp())
        return epoch_time
    except ValueError as e:
        print(f"Date format error: {e}")
        return None


def convert_unix_to_epoch(date_str):
    date_format = "%Y-%m-%d %H:%M:%S"
    datetime_obj = datetime.strptime(date_str.strip('\n'), date_format)
    return int(datetime_obj.timestamp())


def send_command(instance_id, document_name):
    """
    Sends a command to an AWS instance without retries.
    """
    ssm_client = boto3.client('ssm')
    response = ssm_client.send_command(
        DocumentName=document_name,
        InstanceIds=[instance_id],
        Parameters={'commands': ['']},
        Comment=document_name
    )
    command_id = response['Command']['CommandId']
    print(f"Commande {document_name} executée, ID est {command_id}.")
    return command_id

# Helper function to define what we consider a retry condition
def is_empty_or_failed_result(result):
    return result is None or result == '' or 'failed' in result.lower()


def before_retry(retry_state):
    """Function to execute before each retry, logs the attempt number and reason."""
    print(f"Retrying fetching results... Attempt {retry_state.attempt_number}")


@retry(retry=retry_if_result(is_empty_or_failed_result), stop=stop_after_attempt(5), wait=wait_fixed(10), before_sleep=before_retry)
def fetch_command_result(command_id, instance_id):
    """
    Fetches the result of a command execution with retries for empty or failed results.
    """
    ssm_client = boto3.client('ssm')
    output = ssm_client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id
    )
    if output['Status'] == 'Success' and output['StandardOutputContent']:
        return output['StandardOutputContent']
    else:
        return ""  # Returning an empty string if not successful or if the output is empty


def run_document(instance_id, document_name, delay):
    """
    Wrapper function to handle command execution and process the output with separate retry logic for fetching results.
    """
    print(f"Exécution sur l'instance {instance_id} ({document_name})")

    try:
        command_id = send_command(instance_id, document_name)
        time.sleep(delay)  # Wait for the command to likely complete execution
        result = fetch_command_result(command_id, instance_id)
        if result:
            if debug:
                print(f"Resultat : |{result}|")
            return result
        else:
            print(f"Erreur ou absence de sortie de l'exécution de la commande {document_name} sur l'instance {instance_id}")
            return ""
    except Exception as e:
        print(f"Une erreur inattendue est survenue lors de la tentative d'exécution de la commande: {str(e)}")


def fetch_instance_ids():
    # Create a boto3 EC2 resource object
    ec2 = boto3.resource('ec2')

    # Initialize a list to hold the instance IDs
    instance_ids = []

    # Retrieve all instances
    for instance in ec2.instances.all():
        # Add each instance's ID to the list
        instance_ids.append(instance.id)

    return instance_ids


def get_instance_os_type(instance_id):
    ec2 = boto3.client('ec2')

    response = ec2.describe_instances(InstanceIds=[instance_id])

    instances_state[instance_id] = {}

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if 'Platform' in instance:
                if instance['Platform'] == 'windows':
                    instances_state[instance_id]['os_type'] = 'Windows'
                    return 'Windows'
            # If 'Platform' key is not present, it's likely a Linux instance
            else:
                instances_state[instance_id]['os_type'] = 'Linux'
                return 'Linux'


def get_instance_tags(instance_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    tags = instance.get('Tags', [])
        
    # Convert tags list to a dictionary
    tags_dict = {tag['Key']: tag['Value'] for tag in tags}
    return tags_dict


def get_os_info(instance_id):
    os_type = get_instance_os_type(instance_id)
    if os_type == "Windows":
        return __get_windows_os_info__(instance_id)
    elif os_type == "Linux": 
        return __get_linux_os_info__(instance_id)
    else: 
        print(f"Erreur lors de la recuperation du type d'instance")
    return None


def __get_linux_os_info__(instance_id):  
    os_info = run_document(instance_id, "LinuxGetOsCmd",10)
    launchtime = run_document(instance_id, "LinuxGetUptimeCmd",10)
    # os_info = send_command(instance_id, LINUX_GET_OS_CMD)
    # launchtime = send_command(instance_id, LINUX_GET_UPTIME_CMD)
    # Parse /etc/os-release
    parsed_os_info = {}
    lines = (os_info.split("\n"))
    for line in lines: 
        if line:
            keyvalue = line.split("=")
            if len(keyvalue) == 2: parsed_os_info[keyvalue[0]] = keyvalue[1].strip('\"')
            else: parsed_os_info[keyvalue[0]] = ""
    parsed_os_info['launch_time'] = convert_unix_to_epoch(launchtime)     
    return parsed_os_info


def __get_windows_os_info__(instance_id):
    os_info = run_document(instance_id, "WindowsGetOsCmd", 20)
    # os_info = send_command(instance_id, WINDOWS_GET_OS_CMD)
    parsed_os_info = {}
    lines = (os_info.split("\n"))
    for line in lines: 
        if line:
            keyvalue = line.split("=")
            if len(keyvalue) == 2: parsed_os_info[keyvalue[0]] = keyvalue[1].strip('\"')
            else: parsed_os_info[keyvalue[0]] = ""
    win_time = convert_windows_to_epoch(parsed_os_info['launch_time'])
    parsed_os_info['launch_time'] = win_time
    return parsed_os_info


def get_pending_ssm_patches(instance_id):
    ssm_client = boto3.client('ssm')
    try:
        response = ssm_client.describe_instance_patches(InstanceId=instance_id, Filters=[
            {'Key': 'State', 'Values': ['Missing', 'Failed','InstalledRejected']},
            {'Key': 'Classification', 'Values': ['null','Updates', 'CriticalUpdates' ]}
        ])
        return response.get('Patches', [])
    except Exception as e:
        print(f"Error retrieving pending patches: {e}")

def get_pending_security_ssm_patches(instance_id):
    ssm_client = boto3.client('ssm')
    try:
        response = ssm_client.describe_instance_patches(InstanceId=instance_id, Filters=[
            {'Key': 'State', 'Values': ['Missing', 'Failed', 'InstalledRejected']},
            {'Key': 'Classification', 'Values': ['SecurityUpdates']}
        ])
        return response.get('Patches', [])
    except Exception as e:
        print(f"Error retrieving pending security patches: {e}")

def get_reboot_pending_ssm_patches(instance_id):
    ssm_client = boto3.client('ssm')
    try:
        response = ssm_client.describe_instance_patches(InstanceId=instance_id, Filters=[
            {'Key': 'State', 'Values': ['InstalledPendingReboot']}

        ])
        return response.get('Patches', [])
    except Exception as e:
        print(f"Error retrieving pending patches: {e}")
    

def get_installed_ssm_patches(instance_id):
    ssm_client = boto3.client('ssm')
    try:
        response = ssm_client.describe_instance_patches(InstanceId=instance_id, Filters=[
            {'Key': 'State', 'Values':['Installed','InstalledOther']}
        ])
        return response.get('Patches', [])
    except Exception as e:
        print(f"Error retrieving applied patches: {e}")


def get_pending_system_updates(instance_id):
    if instances_state[instance_id]['os_type'] == 'Windows':
        return __get_pending_windows_system_updates__(instance_id)
    else:
        return __get_pending_linux_system_updates__(instance_id)
    
    
def get_installed_system_updates(instance_id):
    if instances_state[instance_id]['os_type'] == 'Windows':
        return __get_installed_windows_system_updates__(instance_id)
    else:
        return __get_installed_linux_system_updates__(instance_id)


def __get_pending_windows_system_updates__(instance_id):
    updates_raw = run_document(instance_id, "WindowsGetPendingUpdatesCmd", 20)
    if not updates_raw: return []
    lines = (updates_raw.split("\n"))
    current_update = {'Title': "TBD"}
    parsed_updates = []
    for line in lines:
        if line:
            keyvalue = line.split(":")
            if len(keyvalue) == 2:
                keyvalue[0] = keyvalue[0].strip()
                keyvalue[1] = keyvalue[1].strip()
                # print(f"found |{keyvalue[0]}| => |{keyvalue[1]}|")
                if keyvalue[0] == "Title":
                    print(colored(f"****************************************** found a pending update : |{keyvalue[1]}| ****************************************** ", 'red'))
                    if keyvalue[1] != current_update['Title']:
                        print(f"This is a new title : |{keyvalue[1]}| != |{current_update['Title']}|")
                        if current_update['Title'] != "TBD": parsed_updates.append(current_update)
                        current_update = {'Title': keyvalue[1]}
                    else:
                        #print(f"Still pushing for title |{current_update['Title']}| : |{keyvalue[0]}| => |{keyvalue[1]}|")
                        current_update[keyvalue[0]] = keyvalue[1]
                else:
                    current_update[keyvalue[0]] = keyvalue[1]
    parsed_updates.append(current_update)
    return parsed_updates


def __get_installed_windows_system_updates__(instance_id):
    updates_raw = run_document(instance_id, "WindowsGetInstalledUpdatesCmd", 20)
    if not updates_raw: return []
    lines = (updates_raw.split("\n"))
    current_update = {'Title': "TBD"}
    parsed_updates = []
    for line in lines:
        if line:
            keyvalue = line.split(":")
            if len(keyvalue) == 2:
                keyvalue[0] = keyvalue[0].strip()
                keyvalue[1] = keyvalue[1].strip()
                if keyvalue[0] == "Title":
                    print(colored(f"****************************************** found an installed update : |{keyvalue[1]}| ****************************************** ", 'red'))
                    if keyvalue[1] != current_update['Title']:
                        if current_update['Title'] != "TBD": parsed_updates.append(current_update)
                        current_update = {'Title': keyvalue[1]}
                    else:
                        current_update[keyvalue[0]] = keyvalue[1]
                else:
                    current_update[keyvalue[0]] = keyvalue[1]
    parsed_updates.append(current_update)
    return parsed_updates
    
    
def __get_pending_linux_system_updates__(instance_id):
    pprint.pp(instance_id)
    if "CentOS Linux 7" in instances_state[instance_id]['os_info']['NAME']:
        command_name = "YumGetPendingPkg"    
    elif "CentOS Linux 8" in instances_state[instance_id]['os_info']['NAME']:
        command_name = "DnfGetPendingPkg"
    elif "Amazon Linux" in instances_state[instance_id]['os_info']['NAME']:
        command_name = "DnfGetPendingPkg"        
    elif "Ubuntu" in instances_state[instance_id]['os_info']['NAME']:
        command_name = "AptGetPendingPkg"
    elif "Debian" in instances_state[instance_id]['os_info']['NAME']:
        command_name = "AptGetPendingPkg"
    else:
        print(f"Can't recognize distribution : {instances_state[instance_id]['os_info']['NAME']}", )
        return []
    updates = run_document(instance_id, command_name,10)
    print(f"Debug pending updates : |{updates}|")
    return updates


def __get_installed_linux_system_updates__(instance_id):
    return []
    
    
def get_instance_ami(instance_id):
    ec2 = boto3.client('ec2')
    
    try:
        # Fetch the instance information
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        ami_id = instance_info['Reservations'][0]['Instances'][0]['ImageId']
        print(f"AMI ID for instance {instance_id}: {ami_id}")

        # Fetch AMI details using the AMI ID
        ami_info = ec2.describe_images(ImageIds=[ami_id])
        ami_name = ami_info['Images'][0]['Name']
        creation_time = ami_info['Images'][0]['CreationDate']
        return {
            'AMI ID': ami_id,
            'AMI Name': ami_name,
            'Creation Time': creation_time
        }
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

## Patch Managment Acceptancy critera : KPI (%) = 100 - ((nb_instance_with_old_pending_patches / nb_instances) * 100 )
## old_pending_patches = pending more than 30 Days

def get_sla_patch_os_1():
    nb_instance_with_old_pending_patch = 0
    now = datetime.now(timezone.utc)
    for instance in instances_state:
        for pending_patche in instances_state[instance]['pending_patches']:
            patch_age = (now - pending_patche['ReleaseDate']).days
            if patch_age >= 30:
                nb_instance_with_old_pending_patch += 1
        for pending_patche in instances_state[instance]['reboot_pending_patches']:
            patch_age = (now - pending_patche['ReleaseDate']).days
            if patch_age >= 30:
                nb_instance_with_old_pending_patch += 1
    return 100 - ( (nb_instance_with_old_pending_patch / len(instances_state) ) * 100)
    
def get_sla_patch_os_2():
    nb_instance_with_old_security_pending_patch = 0
    now = datetime.now(timezone.utc)
    for instance in instances_state:
        for pending_patche in instances_state[instance]['security_pending_patches']:
            patch_age = (now - pending_patche['ReleaseDate']).days
            if patch_age >= 30:
                nb_instance_with_old_security_pending_patch += 1
    return 100 - ( (nb_instance_with_old_security_pending_patch / len(instances_state) ) * 100)

def main(instance_ids):
    for instance_id in instance_ids:
        print(f"Fetching instance ",colored(instance_id, 'green'))
        instances_state[instance_id]['os_info'] = get_os_info(instance_id)
        instances_state[instance_id]['instance_tags'] = get_instance_tags(instance_id)
        # instances_state[instance_id]['pending_updates'] = get_pending_system_updates(instance_id)
        # instances_state[instance_id]['installed_updates'] = get_installed_system_updates(instance_id)
        instances_state[instance_id]['pending_patches'] = get_pending_ssm_patches(instance_id)
        instances_state[instance_id]['reboot_pending_patches'] = get_reboot_pending_ssm_patches(instance_id)
        instances_state[instance_id]['security_pending_patches'] = get_pending_security_ssm_patches(instance_id)
        # instances_state[instance_id]['installed_patches'] = get_installed_ssm_patches(instance_id)
        instances_state[instance_id]['running_ami'] = get_instance_ami(instance_id)
        # instances_state[instance_id]['oldest_pending_patch'] = get_older_pending_ssm_patch_age(instance_id)
        instances_state[instance_id]['last_fetch'] = time.asctime()
    print(colored(f"SLA Patch OS 1 : {int(get_sla_patch_os_1())}%", 'yellow'))
    print(colored(f"SLA Patch OS 2 : {int(get_sla_patch_os_2())}%", 'yellow'))
    parsed_data = json.dumps(instances_state, sort_keys=True, default=str)
    if debug: print(parsed_data)

if __name__ == "__main__":
    # Exemple d'utilisation: python3 script.py [i-1234567890abcdef0] [i-abcdef1234567890]
    if len(sys.argv) > 1:
        instance_ids = sys.argv[1:]  # Les ID des instances sont passés via ARGV
    else:
        instance_ids = fetch_instance_ids() # Si aucune instance n'est spécifiée, on fetch les instances du compte courant
    main(instance_ids)
