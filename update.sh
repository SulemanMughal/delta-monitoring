#!/bin/bash

# Echo
echo "Updating..."

echo "----------------------------------------------"
echo "daemon-reload"

sudo systemctl daemon-reload

sleep 3

echo "----------------------------------------------"
echo "gunicorn"
sudo systemctl restart gunicorn

sleep 3

command_output=$(sudo systemctl status gunicorn.service)

echo "$command_output"

echo "----------------------------------------------"
echo "nginx"
sudo nginx -t && sudo systemctl restart nginx

sleep 3

command_output=$(sudo systemctl status nginx.service)

echo "$command_output"

echo "----------------------------------------------"
echo "daphne"
sudo systemctl restart daphne.service

sleep 3

command_output=$(sudo systemctl status daphne.service)

echo "$command_output"
echo "----------------------------------------------"



# echo "----------------------------------------------"
# echo "capture service"
# sudo systemctl restart capture_script.service

# sleep 3

# command_output=$(sudo systemctl status capture_script.service)

# echo "$command_output"
# echo "----------------------------------------------"



# echo "----------------------------------------------"
# echo "live_script.service service"
# sudo systemctl restart live_script.service

# sleep 3

# command_output=$(sudo systemctl status live_script.service)

# echo "$command_output"
# echo "----------------------------------------------"



# echo "----------------------------------------------"
# echo "fortinet_logs logs service"
# sudo systemctl restart fortinet_logs.service

# sleep 3

# command_output=$(sudo systemctl status fortinet_logs.service)

# echo "$command_output"
# echo "----------------------------------------------"
