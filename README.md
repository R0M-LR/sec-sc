## Prerequisite
```bash
apt update && apt-get install python python-pip nmap gem git seclists -yy
```

#### Impacket
```bash
git clone https://github.com/SecureAuthCorp/impacket.git
pip install --upgrade pip
pip install pycrypto cryptography pyasn1 pyOpenSSL ldapdomaindump jinja2 tox
cd impacket
python setup.py install
```

## Utilisation
All scan : 
```bash
s&c.sh 10.10.10.10
```
