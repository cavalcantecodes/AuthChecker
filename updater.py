import requests
import os
import sys
import zipfile

class Updater:
    GITHUB_RELEASES_URL = "https://api.github.com/repos/cavalcantecodes/AuthChecker/releases/latest"
    CURRENT_VERSION = '0.3.0'

    @staticmethod
    def get_latest_version_tag():
        response = requests.get(Updater.GITHUB_RELEASES_URL)
        if response.status_code == 200:
            return response.json()["tag_name"]
        return None

    @staticmethod
    def download_latest_version():
        latest_version = Updater.get_latest_version_tag()
        if latest_version:
            download_url = f"https://github.com/cavalcantecodes/AuthChecker/archive/refs/tags/{latest_version}.zip"
            response = requests.get(download_url, stream=True)
            if response.status_code == 200:
                with open("update.zip", "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        file.write(chunk)
                return True
        return False

    @staticmethod
    def unpack_and_replace():
        with zipfile.ZipFile("update.zip", 'r') as zip_ref:
            zip_ref.extractall("./updated_version/")
        # Here you'd move the new files to replace the old ones.

    @staticmethod
    def check_for_updates():
        if Updater.get_latest_version_tag() != Updater.CURRENT_VERSION:
            print("[INFO] 🚀 New update available!")
            if Updater.download_latest_version():
                print("[INFO] 📦 Update downloaded. Installing...")
                Updater.unpack_and_replace()
                print("[INFO] 🎉 Update installed! Restarting...")
                Updater.restart()
            else:
                print("[ERROR] 🚫 Failed to download update.")
        else:
            print("[INFO] 📦 You're already running the latest version.")

    @staticmethod
    def restart():
        os.execv(sys.executable, ['python'] + sys.argv)
        sys.exit(0)

        