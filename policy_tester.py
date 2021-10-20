import yaml
import inotify.adapters
import time
import threading


policies_list = []

#check if policy has been modified
def mod_detecter():
    while True:
        i = inotify.adapters.Inotify()
        i.add_watch("policiesDB.yaml")

        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event

            if "IN_CLOSE_WRITE" in event[1]: #type_names is a list
                print("[!] POLICYDB MODIFIED")
                mod_manager()
            #log:
            #print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, type_names))


#find out specific modifications per policy
#[!] TOADD: function that manages specific modifications \w switch table
def mod_manager():
    global policies_list
    tmp = policies_list
    getPolicies()
    
    found = False

    for policy in policies_list:
        print(policy)

        for policy_tmp in tmp:
            if policy.get("serviceName") == policy_tmp.get("serviceName"):
                found = True
                print("[!] Service found: " + "--> " + policy.get("serviceName"))
            
                if policy.get("ip") != policy_tmp.get("ip"):
                    print("[!] IP_MODIFICATIONS")
        
                if policy.get("port") != policy_tmp.get("port"):
                    print("[!] PORT_MODIFICATIONS")

                if policy.get("protocol") != policy_tmp.get("protocol"):
                    print("[!] PROTOCOL_MODIFICATIONS")

                for ue in policy.get("allowed_users"):
                    ue_mod = False
                    if ue not in policy_tmp.get("allowed_users"):
                        ue_mod = True
                        print("[!] UE_MODIFICATIONS")
                        print("ue_mod:")
                        print(ue_mod)

                if policy.get("tee") != policy_tmp.get("tee"):
                    print("[!] TEE_MODIFICATIONS")

                if policy.get("fs_encr") != policy_tmp.get("fs_encr"):
                    print("[!] FS_ENCR_MODIFICATIONS")

                if policy.get("net_encr") != policy_tmp.get("net_encr"):
                    print("[!] NET_ENCR_MODIFICATIONS")

                if policy.get("sec_boot") != policy_tmp.get("sec_boot"):
                    print("[!] SEC_BOOT_MODIFICATIONS")
                
                break

            if not found:
                print("[!] Service not found")                              

#getPolicies from policyDB     
def getPolicies():
    global policies_list
    stream = open("policiesDB.yaml", 'r')
    policies_list = yaml.safe_load(stream)


def main():
    global policies_list
    getPolicies()
    while True:
        stream = open("policiesDB.yaml", 'r')
        policies_list = yaml.safe_load(stream)
        print("policy_list opened")
        #print(policies_list)
        print("\n\n\n\n\n\n")
        
        #how to get a specific policy
        #for policy in policies_list:
        #    if policy.get("ip") == "10.0.2.2" and policy.get("port") == 48 and policy.get("protocol") == "TCP":
        #        for user in policy.get("allowed_users"):
        #            print(user.get("method") + ": " + user.get("user"))

        time.sleep(10)


detector = threading.Thread(target = mod_detecter)
detector.start()
main()