---
title: Configuring the Forseti Cloud SQL Instance with password
order: 5
---
{::options auto_ids="false" /}

1. Follow the instruction [here](https://cloud.google.com/sql/docs/mysql/create-manage-users#changing_a_user_password) 
to add/change password of MySQL user `root`.

1. ssh to the Forseti server VM.

1. run command `sudo vi /lib/systemd/system/forseti.service` and you should see the following:

    ```
    [Unit]
    Description=Forseti API Server
    [Service]
    User=ubuntu
    Restart=always
    RestartSec=3
    ExecStart=/usr/local/bin/forseti_server --endpoint '[::]:50051' --forseti_db mysql://root@127.0.0.1:3306/forseti_security --config_file_path /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml --services explain inventory model scanner notifier
    [Install]
    WantedBy=multi-user.target
    Wants=cloudsqlproxy.service
    ```

1. Update the `forseti_db` flag to the following:

    <pre><code>
    [Unit]
    Description=Forseti API Server
    [Service]
    User=ubuntu
    Restart=always
    RestartSec=3
    ExecStart=/usr/local/bin/forseti_server --endpoint '[::]:50051' --forseti_db mysql://<b>root:YOUR_PASSWORD</b>@127.0.0.1:3306/forseti_security --config_file_path /home/ubuntu/forseti-security/configs/forseti_conf_server.yaml --services explain inventory model scanner notifier
    [Install]
    WantedBy=multi-user.target
    Wants=cloudsqlproxy.service
    </code></pre>

1. Save and exit, run command `sudo systemctl restart forseti` to restart the forseti service and you should now be able to connect to the database with the password.
