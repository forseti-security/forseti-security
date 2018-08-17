---
title: How to update the Cron Job?
order: 8
---
{::options auto_ids="false" /}

Forseti is installed in the `ubuntu` account. To update the cron job you need to SSH into the server VM and switch to 
the `ubuntu` user to update the cron job. 
```
ssh to server VM 
sudo su - ubuntu
crontab -e
```