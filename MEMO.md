To configure vCenter to send system logs to Kiwi Syslog Server, you need to perform the following steps:
1.	Log in to the vSphere Web Client or vSphere Client.
2.	Click on the vCenter Server instance in the inventory.
3.	Click on the Configure tab.
4.	Under the Settings section, click on General.
5.	Click on Edit.
6.	Scroll down to the Syslog.global.logHost option and enter the IP address or hostname of the Kiwi Syslog Server in the value field.
7.	Click on Save to save the changes.
Once this is done, vCenter will start sending system logs to the Kiwi Syslog Server. You can then configure Kiwi Syslog Server to capture and store these logs as needed.





To configure vCenter to send system logs to Kiwi Syslog Server, you will need to do the following:

1. Install and configure Kiwi Syslog Server.
2. Configure vCenter to send logs to Kiwi Syslog Server.
3. Verify that vCenter is sending logs to Kiwi Syslog Server.

Here are the steps in more detail:

1. Install and configure Kiwi Syslog Server.

Kiwi Syslog Server is a free and open-source syslog server that can be used to collect and store log messages from a variety of sources, including vCenter. To install Kiwi Syslog Server, follow the instructions on the Kiwi Syslog Server website.

Once Kiwi Syslog Server is installed, you will need to configure it to receive log messages from vCenter. To do this, open the Kiwi Syslog Server configuration file and add the following lines:

```
source vcenter {
  address = 192.168.1.100
  port = 514
  protocol = udp
}
```

This will configure Kiwi Syslog Server to listen for log messages from vCenter on port 514 using the UDP protocol.

2. Configure vCenter to send logs to Kiwi Syslog Server.

To configure vCenter to send logs to Kiwi Syslog Server, you will need to edit the vCenter Server Appliance configuration file. To do this, open the vCenter Server Appliance Management Interface and navigate to Configuration > System > Advanced Settings. In the Advanced Settings window, scroll down to the Syslog section and enter the following values:

```
syslog.server = 192.168.1.100
syslog.port = 514
syslog.protocol = udp
```

This will configure vCenter to send logs to Kiwi Syslog Server on port 514 using the UDP protocol.

3. Verify that vCenter is sending logs to Kiwi Syslog Server.

To verify that vCenter is sending logs to Kiwi Syslog Server, open the Kiwi Syslog Server web interface and navigate to the Log Viewer page. You should see log messages from vCenter appearing in the list of logs.

If you are not seeing log messages from vCenter, check the following:

* Make sure that vCenter is configured to send logs to Kiwi Syslog Server.
* Make sure that Kiwi Syslog Server is listening for log messages on the correct port.
* Make sure that the network connection between vCenter and Kiwi Syslog Server is working properly.




















pip install pytz requests reportlab pandas pyshark

This will install the pytz, requests, reportlab, pandas, and pyshark libraries and their dependencies, allowing you to run the script.




This script extracts login, logout, user add, user change, and user delete information from the Kiwi Syslog Server logs for yesterday, generates a report, and saves the report as a PDF file in the `D
--------------------------------

import pandas as pd
from datetime import datetime, timedelta
import pyshark
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


# Configuration variables
syslog_ip = '192.168.1.1'
vcenter_ip = '192.168.1.2'
start_time = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d 00:00:00')
end_time = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d 23:59:59')
pdf_path = r'D:\vcenterinfo\vcenter_' + datetime.now().strftime('%Y-%m-%d') + '.pdf'


# Define function to get login/logout events from pcap file
def get_login_logout_events(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter='(vmware-sts-id OR vmware-session-id) && tcp.port == 443')
    events = []
    for packet in capture:
        try:
            event = {
                'time': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': packet['samlp:StatusCode']['Value'],
                'user': packet['saml:NameID'],
                'client_ip': packet['saml:AuthnStatement']['AuthnContext']['saml:AuthenticatingAuthority'],
                'server_ip': packet.ip.dst
            }
            events.append(event)
        except:
            pass
    capture.close()
    return events


# Get login/logout events from pcap file
pcap_file = f'{vcenter_ip}_443_{start_time.replace(" ", "_")}_to_{end_time.replace(" ", "_")}.pcap'
events = get_login_logout_events(pcap_file)

# Get user add/change/delete events from syslog
syslog_file = f'{syslog_ip}_{start_time.replace(" ", "_")}_to_{end_time.replace(" ", "_")}.log'
df = pd.read_csv(syslog_file, delimiter='\t')
df = df[df['Message'].str.contains('UserAccount', na=False)]
user_events = df.to_dict('records')

# Create PDF report
c = canvas.Canvas(pdf_path, pagesize=letter)
textobject = c.beginText()
textobject.setTextOrigin(50, 750)
textobject.setFont('Helvetica', 12)
textobject.textLine(f'Login/Logout Events for {start_time.split(" ")[0]}')
textobject.textLine('')
textobject.setFont('Helvetica', 10)
for event in events:
    textobject.textLine(f"Time: {event['time']}, Event Type: {event['event_type']}, User: {event['user']}, Client IP: {event['client_ip']}, Server IP: {event['server_ip']}")
textobject.textLine('')
textobject.setFont('Helvetica', 12)
textobject.textLine(f'User Add/Change/Delete Events for {start_time.split(" ")[0]}')
textobject.textLine('')
textobject.setFont('Helvetica', 10)
for event in user_events:
    textobject.textLine(f"Time: {event['Received At']}, Message: {event['Message']}")
c.drawText(textobject)
c.showPage()
c.save()








To schedule the script to run daily at 3 AM, you can use the Windows Task Scheduler. Here's how you can do it:
1.	Open the Task Scheduler by searching for "Task Scheduler" in the Start menu.
2.	Click on "Create Task" in the right-hand pane.
3.	Give the task a name and description.
4.	Go to the "Triggers" tab and click "New".
5.	Select "Daily" and set the time to 3:00 AM.
6.	Under "Actions", click "New" and select "Start a program".
7.	In the "Program/script" field, enter the path to your Python executable (e.g., "C:\Python39\python.exe").
8.	In the "Add arguments" field, enter the path to your Python script (e.g., "C:\path\to\your\script.py").
9.	Click "OK" to save the task.
Make sure to update the paths to your Python executable and script as needed. You can also set up additional options, such as running the task with elevated privileges or running the task even if the user is not logged on.



