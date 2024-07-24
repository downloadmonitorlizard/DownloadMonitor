# DownloadMonitor
Linux tool for monitoring a directory of your choice, the monitor also deletes any malicious files found.
Open a terminal and run: git clone https://github.com/downloadmonitorlizard/DownloadMonitor.git
You can now cd into "DownloadMonitor" run: cd DownloadMonitor
Run: pip install -r requirements.txt
Make the files exacutable run: chmod +x start_ml.sh & chmod +x ml.py
Create the download_monitor.desktop file in the appropriate location: cp download_monitor.desktop ~/.local/share/applications/
chmod +x ~/.local/share/applications/download_monitor.desktop
You can now run the application with ./start_ml.sh
