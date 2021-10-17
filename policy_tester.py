import yaml

stream = open("policiesDB.yaml", 'r')
policies_list = yaml.safe_load(stream)
for policy in policies_list:
    if policy.get("ip") == "10.0.2.2" and policy.get("port") == 48 and policy.get("protocol") == "TCP":
        for user in policy.get("allowed_users"):
            print(user.get("method") + ": " + user.get("user")) 