# MISPHunter
Uses searches on 3rd party services and MISP to track actor infrastructure as it's built

## Installing as a service

This needs to be installed on the MISP server in order to monitor MISPHunter searches.

Make sure everything lives in /opt/MISPHunter/

To install the service do the following as root:

cp /opt/MISPHunter/misphunter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now misphunter
systemctl start misphunter
systemctl status misphunter
