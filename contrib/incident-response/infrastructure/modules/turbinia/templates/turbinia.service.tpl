# This file should be in /etc/systemd/system/turbinia@.service.
# The @ symbol in the filename is important, which marks the file
# a systemd template unit file.
#
# Systemd supports service instantiations from a single template file.
# This service file will serve as a template from which two units will
# be instantiated as server and psqworker.
#
# Systemd naming convention for an instantiated service unit:
# <service_name>@<argument>.service
#
# <argument> is passed to systemd and then assigned to %i.
#
# To manage services for Turbinia:
# sudo systemctl enable turbinia@server
# sudo systemctl enable turbinia@psqworker
# sudo systemctl status turbinia@server
# sudo systemctl status turbinia@psqworker
# sudo systemctl start turbinia@server
# sudo systemctl start turbinia@psqworker
# sudo systemctl stop turbinia@server
# sudo systemctl stop turbinia@psqworker
# sudo systemctl daemon-reload


[Unit]
Description=Turbinia %i Daemon
Documentation=https://github.com/google/turbinia
Before=multi-user.target
After=network.target
After=remote-fs.target


[Service]
Type=simple
PIDFile=/var/run/turbinia-%i.pid
User=turbinia
Group=turbinia
Restart=always
RestartSec=10
# Run ExecStartPre as root
PermissionsStartOnly=true
ExecStartPre=-/bin/mkdir /mnt/turbinia/
ExecStartPre=-/bin/mkdir /var/lib/turbinia/
ExecStartPre=-/bin/mkdir /var/lib/turbinia/
ExecStartPre=/bin/chown -R turbinia:turbinia /mnt/turbinia/
ExecStartPre=/bin/chown -R turbinia:turbinia /var/lib/turbinia/
ExecStartPre=/bin/chown -R turbinia:turbinia /var/lib/turbinia/
# Run the server as the turbinia user
ExecStart=/bin/sh -c '/usr/local/bin/turbiniactl -L /var/log/turbinia/turbinia-%i.log -S -o /var/lib/turbinia %i 2>> /var/log/turbinia/turbinia-%i.stdout.log'
KillMode=control-group
KillSignal=SIGINT


[Install]
WantedBy=multi-user.target