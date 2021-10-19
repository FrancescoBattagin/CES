import yaml
import inotify.adapters
import time
import threading


#check if policy has been modified
def mod_detecter():
    while True:
        i = inotify.adapters.Inotify()
        i.add_watch("policiesDB.yaml")

        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event

            if "IN_CLOSE_WRITE" in event[1]: #type_names is a list
                print("[!] POLICYDB MODIFIED")

            #log:
            #print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, type_names))


detector = threading.Thread(target = mod_detecter)
detector.start()

#look for a specific policy
while True:
    stream = open("policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)
    for policy in policies_list:
        if policy.get("ip") == "10.0.2.2" and policy.get("port") == 48 and policy.get("protocol") == "TCP":
            for user in policy.get("allowed_users"):
                print(user.get("method") + ": " + user.get("user"))
    time.sleep(10)