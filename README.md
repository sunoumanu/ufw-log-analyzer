# ufw-log-analyzer
Show who is probing your machine. Demo site [HTTP service](http://85.198.110.146:8080)

Requirements: Linux machine with UFW enabled

Build release:
```
cargo build --release --verbose --jobs 4
```

Sample systemd for Ubuntu:
```
[Unit]
Description=UFW Log Analyzer Service
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
User=ufwlogger
Group=ufwlogger
RuntimeDirectory=/opt/ufwlogger
RuntimeDirectoryMode=0755
WorkingDirectory=/opt/ufwlogger
ExecStart=/opt/ufwlogger/ufw-log-analyzer
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ufw-log-analyzer

# Security settings
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Setup folder:
```
mkdir /opt/ufwlogger
cp ufw-log-analyzer /opt/ufwlogger
```


User config:
```
useradd ufwlogger
sudo usermod -a -G systemd-journal ufwlogger
chown -R ufwlogger:ufwlogger /opt/ufwlogger
```

Enable systemd:
```
systemctl daemon-reload
systemctl enable ufw-log-analyzer.service
systemctl restart ufw-log-analyzer.service
```
