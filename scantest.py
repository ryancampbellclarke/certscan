import ssl, socket

hostname = 'yukon.ca'
ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
    s.connect((hostname, 443))
    cert = s.getpeercert()

print(dict(cert))

subject = dict(x[0] for x in cert['subject'])
issued_to = subject['commonName']
issuer = dict(x[0] for x in cert['issuer'])
issued_by = issuer['commonName']