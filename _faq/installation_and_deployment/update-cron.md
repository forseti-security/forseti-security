---
title: How to update the cron job?
order: 9
---
{::options auto_ids="false" /}

Forseti is installed with the `ubuntu` account on the server VM. To update the
cron job you need to SSH into the server VM and switch to the `ubuntu` user to
update the cron job. 
```
ssh to server VM 
sudo su - ubuntu
crontab -e
```