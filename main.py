#!/usr/bin/env python3
from fabricstudio.fabricstudio_api import *
from fabricstudio.auth import *

# Dummy credentials and host address
client_id = "unlnDPjmRLG1syWcGn3cBSTsCXFDuwdP0YQe2Kw9"
client_secret = "8g9aEnFwN4VMT2FuYRTimsMRVyXiOHE0SwPB9pUZViJkqo0sbUYdx7hMGgroCgwGKUsE3ptQg2REzvgI4V1u7N271Dzyk6ctkLsHYYihyIF9vAqh3s30Q2bHlknggmLf"
fabric_host = "fs1.fortipoc.io"


def main():
    token = get_access_token(client_id, client_secret, fabric_host)
    if token:
        #query_hostname(fabric_host, token)
        #change_hostname(fabric_host, token)
        guest_id = get_userId(fabric_host, token, "guest")
        print(f"Guest id: {guest_id}")
        change_password(fabric_host,token, guest_id, "Fortinet#1234")
        reset_fabric(fabric_host,token)
        batch_delete(fabric_host, token)
        refresh_repositories(fabric_host, token)
        template_id1 = get_template(fabric_host, token, "FortiWeb Machine Learning", "fortinet", "2.5.9")
        #template_id2 = get_template(fabric_host, token, "FortiWeb Machine Learning", "appsec","2.5.8")
        print(template_id1)
        #print(template_id2)
        #download_template(fabric_host, token, template_id1)
        #download_template(fabric_host, token, template_id2)
        create_fabric(fabric_host, token, template_id1,"FortiWeb Machine Learning", "2.5.9")
        install_fabric(fabric_host, token, "FortiWeb Machine Learning", "2.5.9")


if __name__ == "__main__":
    main()