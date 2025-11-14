# Python Standard Library
import os
import random
import re
import warnings

from datetime import date
from time import sleep

# 3rd Party Imports
import requests

from pycti import OpenCTIApiClient
from stix2 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED


# Custom Imports

warnings.filterwarnings('ignore')

ipv4_regex = "^(\d{3}\.?){4}$"
ipv6_regex = "^([a-fA-f0-9]{0,4}:?){8}$"

def add_c2tracker_ips(opencti_labels, current_c2_tracker_ips, c2_ip_count, ip_count, inserted_ips, SELECTED_TLP):    
    for item in current_c2_tracker_ips:
        for c2, ips in item.items():
            print(f"Adding IPs for {c2}:")
            created_labels = []
            if c2 == "Cobalt Strike C2":
                labels = ["Cobalt Strike", "C2"]
            elif c2 == "Brute Ratel C4":
                labels = ["Brute Ratel"]
            elif c2 == "Hak5 Cloud C2":
                labels = ["Hak5 Cloud", "C2"]
            elif c2 == "Gh0st RAT Trojan":
                labels = ["Gh0st RAT", "Trojan"]
            elif c2 == "Browser Exploitation Framework (BeEF)":
                labels = ["Browser Exploitation Framework", "BeEF"]
            elif c2 == "Metasploit Framework C2":
                labels = ["Metasploit Framework", "C2"]
            else:
                labels = c2.split()
            labels.insert(0,"c2-tracker")
            # Checks to see if label already exists in opencti and creates if not exist
            # Create list of labels from C2 names as well as default c2-tracker
            for l in labels:
                l = l.lower()
                matches = [item_label for item_label in opencti_labels if l in item_label.values()]
                if len(matches) == 0:
                    #print(f"Creating new label for {l}")
                    random_color = generate_random_color()
                    label = opencti_api_client.label.create(
                        value=l,
                        color=random_color,
                        )
                    created_labels.append(label)
                else:
                    #print("Label already exists.")
                    label = matches[0]
                    created_labels.append(label)
            for ip in ips:
                #print(f"\tAdding {ip}")
                pair = {ip:c2}
                if pair in inserted_ips:
                    #print(f"\t{ip}:{c2} was already inserted into opencti.  Moving on.")
                    pass
                else:
                    if re.search(ipv6_regex, ip):
                        # Create IPv6 indicator
                        observable = opencti_api_client.stix_cyber_observable.create(
                            observableData={
                                "type": "IPv6-Addr",
                                "value": f"{ip}",
                                "x_opencti_description": f"This IP was recently seen hosting {c2}",
                                "x_opencti_score": 100,
                                "x_opencti_create_indicator":True
                                }, objectMarking=[SELECTED_TLP["id"]]
                            )
                        # Get the observable ID to add labels
                        observable_id = observable['id']
                        #print(f"Observable ID: {observable_id}")
                        # Get the indicator ID to add labels
                        indicator_id = observable['indicatorsIds'][0]
                        #print(f"Indicator ID: {indicator_id}")
                        
                        for label in created_labels:
                            # Add label to indicator
                            #print(f"Label: {label}")
                            opencti_api_client.stix_domain_object.add_label(id=indicator_id, label_id=label["id"])
                            opencti_api_client.stix_cyber_observable.add_label(id=observable_id, label_id=label["id"])
                        # Keeps track of the C2:IP Combos that have already been inserted to pick back up if there is a time out
                        inserted = {ip:c2}
                        inserted_ips.append(inserted)
                        ip_count += 1
                    else:# re.search(ipv4_regex, ip):
                        # Create IPv4 indicator
                        observable = opencti_api_client.stix_cyber_observable.create(
                            observableData={
                                "type": "IPv4-Addr",
                                "value": f"{ip}",
                                "x_opencti_description": f"This IP was recently seen hosting {c2}",
                                "x_opencti_score": 100,
                                "x_opencti_create_indicator":True
                                }, objectMarking=[SELECTED_TLP["id"]]
                            )
                        # Get the observable ID to add labels
                        observable_id = observable['id']
                        #print(f"Observable ID: {observable_id}")
                        # Get the indicator ID to add labels
                        indicator_id = observable['indicatorsIds'][0]
                        #print(f"Indicator ID: {indicator_id}")
                        
                        for label in created_labels:
                            # Add label to indicator
                            #print(f"Labe: {label}")
                            opencti_api_client.stix_domain_object.add_label(id=indicator_id, label_id=label["id"])
                            opencti_api_client.stix_cyber_observable.add_label(id=observable_id, label_id=label["id"])
                        # Keeps track of the C2:IP Combos that have already been inserted to pick back up if there is a time out
                        inserted = {ip:c2}
                        inserted_ips.append(inserted)
                        ip_count += 1
                    #else:
                       # print(f"IP did not match a regex:\t{ip}") 

def create_relationships(SELECTED_TLP, indicators, tools):
    # Create the tag (if not exists)
    label = opencti_api_client.label.create(
        value="c2-tracker",
        color="#ffa500",
    )

    mapping = {
        # MITRE: C2Tracker Label
        "Mythic": "mythic",
        "Cobalt Strike": "cobalt strike",
        "NanoCore": "nanocore",
        "njRAT": "njrat",
        "ShadowPad": "shadowpad",
        "DarkComet": "darkcomet",
        "AsyncRAT": "asyncrat",
        "Brute Ratel C4": "brute ratel",
        "Empire": "empire",
        "Sliver": "sliver",
        "Remcos": "remcos"
    }

    tool_names = set()
    for t in tools:
        tool_names.add(str(t["name"]))

    for i in indicators:
        labels = i['objectLabel']
        for m in mapping:
            for label in labels:
                if mapping[m] == label['value']:
                    for t in tools:
                        if t["name"] == m:
                            print(f"Creating relationsship between {label['value']} and {m}")

                            relationship = opencti_api_client.stix_core_relationship.create(
                                fromType=str(i["entity_type"]),
                                fromId=str(i["id"]),
                                toType=str(t["entity_type"]),
                                toId=str(t["id"]),
                                relationship_type="indicates",
                                first_seen=str(date.today().strftime("%Y-%m-%dT%H:%M:%SZ")),
                                last_seen=str(date.today().strftime("%Y-%m-%dT%H:%M:%SZ")),
                                description="This is a server hosting the tool",
                                markingDefinitions=[SELECTED_TLP["id"]]
                            )
                            # Add label to relationship
                            opencti_api_client.stix_core_relationship.add_label(id=relationship["id"], label_id=label["id"])
def check_mitre():
    mitre = False
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"] and mitre == False:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.malware.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        for malware in data["entities"]:
            if str(malware["createdBy"]["name"]) == "The MITRE Corporation":
                mitre = True
                print("MITRE is enabled")
                break
    return mitre

def generate_random_color():
    return '#{:06x}'.format(random.randint(0, 0xFFFFFF))

def get_current_c2_tracker_ips():
    print("[+] Getting Current IOCs...")
    # Decalres a list to hold all the dictionaries with the tool name as the key and a list of the associated
    # IPs as the value
    all_ips = []
    # Declares a dictionary to hold eacth tool name as the key and a lst of its associated ips
    tool_ips = {}
    # declares a list to hold all the IPs of a tool before being placed into the dictionary
    ips = set()
    tool_regex = "^(.*) IPs$"
    url = "https://github.com/montysecurity/C2-Tracker/tree/main/data"
    request = requests.get(url)
    tools = list(set(re.findall("\"[\w|\s|\d|\.]+IPs\.txt\"", request.text)))
    i = 0
    for tool in tools:
        tools[i] = str(tool).strip('"')
        i += 1
    for tool in tools:
        url = str("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/" + str(tool).replace(" ", "%20"))
        request = requests.get(url)
        if tool.endswith('.txt'):
            tool = tool.split(".")[0]
            if tool == "all":
                pass
            else:
                match = re.search(tool_regex, tool)
                if match:
                    tool = match.group(1)
        #print(f"\t[+] Looking at {tool}")
        ips = str(request.text).split("\n")
        # Remote empty newline
        ips.pop()
        ips = list(set(ips))
        tool_ips = {tool: ips}
        all_ips.append(tool_ips)
    
    return all_ips

def get_current_indicators():
    final_indicators = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.indicator.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_indicators += data["entities"]

    for indicator in final_indicators:
        for i in range(int(len(indicator["objectLabel"]))):
            if str(indicator["objectLabel"][i]["value"]) == "c2-tracker":
                print(indicator["name"] + " --- " + indicator["id"])
    print("Finished gathering current indicators")
    return final_indicators


def get_labels():
    final_labels = []
    max_retries = 3
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing labels after " + after)
        data = opencti_api_client.label.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_labels += data["entities"]
    
    return final_labels

def get_malware():
    final_malware = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.malware.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_malware += data["entities"]
    
    return final_malware

def get_tools():
    final_tools = []
    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        if after:
            print("Listing indicators after " + after)
        data = opencti_api_client.tool.list(
            first=50,
            after=after,
            withPagination=True,
            orderBy="created_at",
            orderMode="asc",
        )
        final_tools += data["entities"]
    
    return final_tools

def loop(opencti_labels, current_c2_tracker_ips, c2_ip_count, ip_count, inserted_ips, SELECTED_TLP):
    try:
        add_c2tracker_ips(opencti_labels, current_c2_tracker_ips, c2_ip_count, ip_count, inserted_ips, SELECTED_TLP)
    except Exception as e:
        print("[+] Main Loop Failed. Restarting in 10 seconds.")
        print(e)
        sleep(20)
        loop(opencti_labels, current_c2_tracker_ips, c2_ip_count, ip_count, inserted_ips, SELECTED_TLP)

if __name__ == "__main__":
    api_url = os.getenv("OPENCTI_BASE_URL") + "/graphql"
    api_token = os.getenv("CONNECTOR_IMPORT_C2_TRACKER")
    opencti_api_client = OpenCTIApiClient(api_url, api_token)
    # Get TLP ID's
    TLP_WHITE_CTI = opencti_api_client.marking_definition.read(id=TLP_WHITE["id"])
    SELECTED_TLP = TLP_WHITE_CTI

    #TLP_GREEN_CTI = opencti_api_client.marking_definition.read(id=TLP_GREEN["id"])
    #SELECTED_TLP = TLP_GREEN_CTI

    #TLP_AMBER_CTI = opencti_api_client.marking_definition.read(id=TLP_AMBER["id"])
    #SELECTED_TLP = TLP_AMBER_CTI

    #TLP_RED_CTI = opencti_api_client.marking_definition.read(id=TLP_RED["id"])
    #SELECTED_TLP = TLP_RED_CTI

    opencti_labels = get_labels()
    current_c2_tracker_ips = get_current_c2_tracker_ips()
    # get count of C2's in order to find place if connection is reset
    c2_ip_count = 0
    ip_count = 0
    for item in current_c2_tracker_ips:
        for c2, ips in item.items():
            for ip in ips:
                c2_ip_count += 1
    # Empty list to hold IPS that have been inserted
    inserted_ips = []
    while len(inserted_ips) < c2_ip_count:
        loop(opencti_labels, current_c2_tracker_ips, c2_ip_count, ip_count, inserted_ips, SELECTED_TLP)

    mitre = check_mitre()
    if mitre:
        indicators = get_current_indicators()
        tools = get_tools()
        create_relationships(SELECTED_TLP, indicators, tools)
        malware = get_malware()
        create_relationships(SELECTED_TLP, indicators, tools=malware)
