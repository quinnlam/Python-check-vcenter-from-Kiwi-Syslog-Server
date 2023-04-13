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
