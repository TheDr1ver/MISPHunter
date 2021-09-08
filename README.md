# MISPHunter
Uses searches on 3rd party services and MISP to track actor infrastructure as it's built

## Installing as a service

This needs to be installed on the MISP server in order to monitor MISPHunter searches.

Make sure everything lives in /opt/MISPHunter/

To install the service do the following as root:
```
cp /opt/MISPHunter/misphunter.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now misphunter
systemctl start misphunter
systemctl status misphunter
```

## How to use it

First, make sure the service is running properly as detailed above. Then, add the custom objects and custom taxonomies included into your MISP instance.

Finally, create a new event with a `misphunter-seed` object containing a search for a specified service.

![image](https://user-images.githubusercontent.com/6147794/132043882-29fa1293-e201-4a1a-bec6-760a422a9d3c.png)

Once the MISPHunter service runs in the background, it will find all enabled seeds and run them based on their selected run frequency (defaults to 24 hours).

### Example seed after running

![image](https://user-images.githubusercontent.com/6147794/132044208-8c859fab-7219-4311-8d75-54ad5d0f435e.png)

### Example host object after running

![image](https://user-images.githubusercontent.com/6147794/132044399-3ac74c72-3c7b-4837-bc55-172b34d36565.png)

### Example certificate object after running

![image](https://user-images.githubusercontent.com/6147794/132556830-fbe63a36-4a76-4f2a-b4bc-912599783bf2.png)

### Example graph after running

![image](https://user-images.githubusercontent.com/6147794/132046748-aa067f15-5dc6-4333-ae86-85072f1665f6.png)


