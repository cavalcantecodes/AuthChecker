import os
import sys
import threading
import datetime
from datetime import datetime
import time
import requests
from bs4 import BeautifulSoup
import re
import math
import pickle
from collections import Counter
import zipfile

from updater import Updater
from logger import Logger
from dashboard import PrettyTableDashboard, HTMLDashboard

current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def get_input(self, message, color="purple"):
    return input(self.color(f"➜ {message}", color))


class AuthChecker:
    
    def __init__(self):
        self.url = None
        self.username = None
        self.password = None
        self.session = requests.Session()    
        # Start the background logger
        log_thread = threading.Thread(target=self.background_logger)
        log_thread.daemon = True  # This makes sure the thread will die when the main program dies
        log_thread.start()
        self.log_data = []
        


    def initialize_session(self):
        data = self.load_session()
        if data:
            self.clear()
            print(self.color("🌟 [SESSION] New Session Found!", "cyan"))
            choice = input(self.color("Would you like to continue, view & continue or start over? (continue/view & continue/new): ", "red"))
            if choice == "continue":
                self.url = data["url"]
                self.username = data["username"]
                self.password = data["password"]
                self.clear()
                self.menu()
            elif choice == "new":
                self.clear()
                self.banner
                self.initialize_inputs()
            elif choice == "view & continue":
                self.url = data["url"]
                self.username = data["username"]
                self.password = data["password"]
                print("\n")
                self.display_session_info()
                # exit to main menu in 5 seconds
                print(self.color("\n[INFO] Returning to main menu in 5 seconds...", "blue"))
                time.sleep(5)
                self.clear()
                self.menu()
        else:
            self.clear()
            self.banner()
            self.initialize_inputs()
            self.clear()
            self.menu()


    def save_scan(self, scan_type, result, url):
        # Check if logs directory exists, if not create one
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Get current date
        current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # The name of the log file can be based on the current date for daily logs or the target URL for URL specific logs
        log_file_name = os.path.join('logs', datetime.now().strftime('%Y-%m-%d') + '.txt')
        
        # Append scan data to the log file
        with open(log_file_name, 'a') as f:
            f.write(f"{current_date} | Type: {scan_type} | Result: {result} | URL: {url}\n")


#--------------------------------------------

    def background_logger(self):
        while True:
            if not self.url:  # Check if self.url is None or an empty string
                time.sleep(60)  # If self.url is not set, sleep for a minute and check again.
                continue

            # Generate filename based on URL and current date
            date_string = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            log_filename = f"{self.url.replace('http://', '').replace('https://', '').replace('/', '_')}-{date_string}.txt"
            
            # Save current state/data to the log file
            with open(log_filename, 'a') as log_file:
                # Example data to save. You can customize this based on what you want to log.
                log_file.write(f"Timestamp: {datetime.datetime.now()}\n")
                log_file.write(f"URL: {self.url}\n")
                log_file.write(f"Username: {self.username}\n")
        print(self.color(f"[INFO] Logged data to {log_filename}", "blue"))

    def save_session(self):
        data = {
            "url": self.url,
            "username": self.username,
            "password": self.password
        }
        with open('session.pkl', 'wb') as f:
            pickle.dump(data, f)

    def load_session(self):
        try:
            with open('session.pkl', 'rb') as f:
                data = pickle.load(f)
                return data
        except (FileNotFoundError, EOFError):
            return None

    def display_session_info(self):
        print(self.color("\n[INFO] 📌 Current Session Info:", "blue"))
        print(self.color(f"URL: {self.url}", "yellow"))
        print(self.color(f"Username: {self.username}", "yellow"))
        print(self.color(f"Password: {self.password}\n", "yellow"))
 


    def initialize_inputs(self):
        self.url = self.get_input("Please enter the target URL: ")
        self.username = self.get_input("Please enter the username: ")
        self.password = self.get_input("Please enter the password: ")
        self.save_session()
        
    @staticmethod
    def get_input(prompt_text):
        return input(prompt_text)

    def color(self, text, color):
        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "purple": "\033[95m",
            "cyan": "\033[96m"
        }
        return colors.get(color, "") + text + "\033[0m"

#--------------------------------------------
    def check_login_page(self):
        response = self.session.get(self.url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Identify forms in the HTML
        forms = soup.find_all('form')

        login_form_detected = False

        for form in forms:
            inputs = form.find_all('input')
            input_names = [i.get('name') for i in inputs if i.get('name')]

            # Check common input names indicative of login forms
            if "username" in input_names or "password" in input_names or "login" in input_names:
                login_form_detected = True
                print(self.color("[INFO] Login form detected!", "green"))
                print(self.color("[DETAIL] Action URL: " + form.get('action'), "blue"))
                print(self.color("[DETAIL] Method: " + form.get('method'), "blue"))
                for input_field in inputs:
                    print(self.color("[DETAIL] Input field name: " + input_field.get('name', "N/A"), "blue"))
                    self.save_scan(scan_type="Login Page Checker", result="Login form detected", url=self.url)
                break
        if not login_form_detected:
            print(self.color("[INFO] No login form detected on the provided page.", "red"))
            self.save_scan(scan_type="Login Page Checker", result="No login form detected", url=self.url)
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()
#--------------------------------------------

    def brute_force_attack_simulation(self):
        # This function simulates a brute force attack by trying to login with different passwords.
        # It uses the provided username and a list of passwords from passwords.txt (one password per line).
        # It also looks for a login form on the page and uses the form parameters to simulate the login.
        # If the login is successful, it prints the password and returns.
        # If the login fails, it prints the password and continues with the next password in the list.
        # If the list of passwords is exhausted, it prints a message and returns.
        # If no login form is found, it prints a message and returns.

        # Load the list of passwords
        with open('passwords.txt', 'r') as f:
            passwords = f.readlines()
        passwords = [p.strip() for p in passwords]  # Remove trailing newline characters

        # Load list of usernames
        with open('usernames.txt', 'r') as f:
            usernames = f.readlines()
        usernames = [u.strip() for u in usernames]  # Remove trailing newline characters

        # Identify forms in the HTML (assuming there's only one form on the page)
        response = self.session.get(self.url)
        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
      
        # Check if the form has a username and password field
        form = forms[0]
        inputs = form.find_all('input')
        input_names = [i.get('name') for i in inputs if i.get('name')]
        if not ("username" in input_names and "password" in input_names):
            print(self.color("[ERROR] Could not detect the username and/or password fields.", "red"))
            return
        
        # Simulate login attempts
        for username in usernames:
            for password in passwords:
                form_parameters = {
                    'username': username,
                    'password': password
                }
                response = self.session.post(self.url, data=form_parameters)
                if response.status_code == 200:
                    print(self.color(f"[ALERT] Brute force attack successful! Username: {username}, Password: {password}", "red"))
                    self.save_scan(scan_type="Brute Force Attack Simulation", result=f"Username: {username}, Password: {password}", url=self.url)
                    return
                else:
                    print(self.color(f"[INFO] Login failed for username: {username}, password: {password}", "blue"))
        print(self.color("[INFO] Brute force attack unsuccessful. Password list exhausted.", "blue"))
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()

                    

#--------------------------------------------
    def password_policy_check(self):
        # Fetch the registration or change password page
        response = self.session.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Search for password policy clues
        policy_clues = [
            ("Minimum Length", ["minimum length", "min length"]),
            ("Uppercase", ["uppercase", "capital letter"]),
            ("Lowercase", ["lowercase"]),
            ("Digit", ["digit", "number"]),
            ("Special Character", ["special character", "symbol"]),
            ("Maximum Length", ["maximum length", "max length"]),
        ]
        
        detected_policies = []

        for policy, clues in policy_clues:
            for clue in clues:
                if clue in soup.get_text().lower():
                    detected_policies.append(policy)
                    break

        if detected_policies:
            print(self.color("[INFO] Detected Password Policies:", "blue"))
            self.save_scan(scan_type="Password Policy Check", result=f"Detected Password Policies: {detected_policies}", url=self.url)
            for policy in detected_policies:
                print(self.color(f"- {policy}", "green"))
                #log the detected policies
        else:
            print(self.color("[WARNING] No specific password policies detected. The site may have a generic policy or none at all.", "yellow"))
            self.save_scan(scan_type="Password Policy Check", result="No specific password policies detected", url=self.url)
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()
#--------------------------------------------
        
    def session_fixation_check(self):
        # Initiate an anonymous session and capture the session ID
        initial_response = self.session.get(self.url)
        initial_session_id = self.session.cookies.get('SESSIONID')  # Assuming cookie name is 'SESSIONID'

        # Parse the login form using BeautifulSoup
        soup = BeautifulSoup(initial_response.text, 'html.parser')
        login_form = soup.find('form')  # Assuming there's only one form on the page
        
        if not login_form:
            print(self.color("[ERROR] Unable to find a login form on the provided URL.", "red"))
            return

        form_parameters = {}
        for input_tag in login_form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name:
                if "user" in input_name.lower():
                    form_parameters[input_name] = self.username
                elif "pass" in input_name.lower():
                    form_parameters[input_name] = self.password

        # Check if we have both username and password fields
        if not (self.username in form_parameters.values() and self.password in form_parameters.values()):
            print(self.color("[ERROR] Could not detect the username and/or password fields.", "red"))
            self.save_scan(scan_type="Session Fixation Check", result="Could not detect the username and/or password fields", url=self.url)
            return

        # Simulate login using extracted form parameters
        login_response = self.session.post(self.url, data=form_parameters)

        # Capture session ID after login
        post_login_session_id = self.session.cookies.get('SESSIONID')

        # Check if session ID changed
        if initial_session_id and post_login_session_id and initial_session_id == post_login_session_id:
            print(self.color("[WARNING] Session Fixation vulnerability detected. Session ID does not change post authentication.", "yellow"))
            self.save_scan(scan_type="Session Fixation Check", result="Session Fixation vulnerability detected.", url=self.url)
        else:
            print(self.color("[INFO] Session ID changes post authentication. Not vulnerable to session fixation.", "green"))
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()
#--------------------------------------------

    def session_timeout_check(self):
        """
        Check for session timeouts by logging in, waiting for a certain amount of time, and then trying to access again.

        :param test_url: A URL within the application to test the session on.
        :param self.url: The URL of the login page (if authentication is required).
        :param username: The username for authentication (if required).
        :param password: The password for authentication (if required).
        """
        
        # If login details are provided, simulate a login
        if self.url and self.username and self.password:
            form_parameters = {
                'username': self.username,  # Adjust parameter names based on your application
                'password': self.password
            }
            response = self.session.post(self.url, data=form_parameters)

            if response.status_code != 200:
                print(self.color("[ERROR] Login failed. Please verify the credentials and login URL.", "red"))
                return

        # Obtain the initial session token (like a cookie) - for demonstration, we're using 'SESSIONID'
        initial_session_id = self.session.cookies.get('SESSIONID')
        if not initial_session_id:
            print(self.color("[ERROR] Couldn't obtain a session token. Please verify the login process.", "red"))
            return

        print(self.color(f"[INFO] Obtained session token: {initial_session_id}. Waiting to check for timeout...", "blue"))
        # Wait for a predefined time (e.g., 5 minutes) to see if session times out
        time.sleep(60)
        #print time counting down
        for i in range(60, 0, -1):
            print(self.color(f"Time left: {i}", "blue"))
            time.sleep(1)
        print(self.color("\n[INFO] Checking if session timed out...", "blue"))
        # Try accessing the application with the session token
        response = self.session.get(self.url)

        # Analyze the response to see if our session is still valid.
        # This is a basic check and may need to be adjusted based on the application's response.
        if response.status_code == 200:
            print(self.color("[WARNING] Session token did not timeout. This might be a security concern.", "yellow"))
            self.save_scan(scan_type="Session Timeout Check", result="Session token did not timeout", url=self.url)
        else:
            print(self.color("[INFO] Session token seems to have timed out as expected.", "green"))
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()
#--------------------------------------------

    def token_predictability_check(self, token_pattern=r"token=\w+"):
        """
        Enhanced check for the predictability of session tokens.
        """
        
        generated_tokens = []
        num_tokens = 100

        for _ in range(num_tokens):
            form_parameters = {
                'username': self.username,
                'password': self.password
            }
            response = self.session.post(self.url, data=form_parameters)

            token_match = re.search(token_pattern, response.text)
            if token_match:
                token_value = token_match.group().split('=')[1]
                generated_tokens.append(token_value)
            else:
                print(self.color("[ERROR] Couldn't extract token from response. Adjust your token_pattern.", "red"))
                return
            
            time.sleep(1)  # introduce a delay to avoid rapid login attempts

        # Shannon Entropy Calculation
        entropy = self.calculate_entropy(''.join(generated_tokens))

        # Token Length Analysis
        average_length = sum(len(token) for token in generated_tokens) / num_tokens
        token_length_issue = average_length < 20  # Just an example; adjust as needed

        # Character Distribution
        char_distribution = Counter(''.join(generated_tokens))
        char_dist_issue = any(v > num_tokens * 0.6 for v in char_distribution.values())

        if entropy > 3.5 and not token_length_issue and not char_dist_issue:
            print(self.color("[INFO] Tokens seem to be sufficiently random.", "green"))
        else:
            print(self.color("[ALERT] Tokens might have predictability issues!", "red"))
            if entropy <= 3.5:
                print(self.color(f"[DETAIL] Entropy: {entropy} (should be > 3.5)", "red"))
                self.save_scan(scan_type="Token Predictability Check", result=f"Entropy: {entropy} (should be > 3.5)", url=self.url)
            if token_length_issue:
                print(self.color(f"[DETAIL] Average token length: {average_length} (should be > 20)", "red"))
                self.save_scan(scan_type="Token Predictability Check", result=f"Average token length: {average_length} (should be > 20)", url=self.url)
            if char_dist_issue:
                print(self.color(f"[DETAIL] Character distribution: {char_distribution}", "red"))
                self.save_scan(scan_type="Token Predictability Check", result=f"Character distribution: {char_distribution}", url=self.url)
            
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()

    def calculate_entropy(self, s):
        """
        Calculate Shannon entropy of a string.
        """
        p, lns = Counter(s), float(len(s))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
#--------------------------------------------
        
    def insecure_password_recovery_check(self):
        """
        Attempt to identify potential weaknesses or misconfigurations in password recovery mechanisms.
        """

        # Simulate accessing the password recovery page
        response = self.session.get(self.url)
        if response.status_code != 200:
            print(self.color("[WARNING] Couldn't access the password recovery page!", "yellow"))
            return

        soup = BeautifulSoup(response.content, 'html.parser')

        # Check if security questions are being used (often they are guessable or easy to bypass)
        security_questions = ["What's your mother's maiden name?", "What was your first pet's name?", 
                            "What was your first school?", "What's your favorite movie?"]

        for question in security_questions:
            if question.lower() in response.content.decode().lower():
                print(self.color(f"[ALERT] Detected potentially insecure security question: '{question}'", "red"))

        # Check if the recovery form uses CAPTCHA (to prevent automated attempts)
        if "captcha" not in response.content.decode().lower():
            print(self.color("[ALERT] Password recovery form does not use CAPTCHA, potentially allowing for automated attempts!", "red"))

        # Check for any information disclosure like "This email does not exist in our database" which can be abused
        # Just simulating as a POST request; in a real-world scenario, you'd want to provide valid data
        post_response = self.session.post(self.url, data={'email': 'test@example.com'})

        if "email does not exist" in post_response.content.decode().lower():
            print(self.color("[ALERT] The application discloses whether an email exists in its database!", "red"))
            self.save_scan(scan_type="Insecure Password Recovery Check", result="The application discloses whether an email exists in its database", url=self.url)
        print(self.color("[INFO] Password recovery checks completed.", "blue"))
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()
#--------------------------------------------
    def run_checks(self):
        """
        The main driver function to execute all checks.
        """
        print(self.color("[INFO] Starting checks...", "blue"))
                # Run the individual functions
        self.brute_force_attack_simulation(self.url)
        self.password_policy_check(self.url)
        self.session_fixation_check(self.url)
        self.session_timeout_check(self.url)
        self.token_predictability_check(self.url)
        self.insecure_password_recovery_check(self.url)

        print(self.color("[INFO] Checks completed.", "blue"))
  
#--------------------------------------------
    def display_dashboard(self):
        print("\nChoose your preferred dashboard type:")

        print("[1] PrettyTable Dashboard")
        print("[2] HTML Browser-based Dashboard")
        choice = input("\nEnter your choice (1/2): ").strip()

        if choice == "1":
            from dashboard import PrettyTableDashboard
            dashboard_pt = PrettyTableDashboard(self.log_data)
            dashboard_pt.display()
        elif choice == "2":
            from dashboard import HTMLDashboard
            dashboard_html = HTMLDashboard(self.log_data)
            dashboard_html.display_in_browser()
        else:
            print("[ERROR] ❌ Invalid choice!")
#--------------------------------------------
    # check for updates
    def check_for_updates(self):
        print(self.color("[INFO] Checking for updates...", "blue"))
        Updater.check_for_updates()
        print(self.color("[INFO] Updates check completed.", "blue"))
        input(self.color("\nPress Enter to return to the main menu...", "blue"))
        self.clear()
        self.menu()
#--------------------------------------------
    def info(self):
        self.clear()
        print(self.color("════════════════════════════════════════════════════════════════", "yellow"))
        print(self.color("                    About AuthChecker Tool", "cyan"))
        print(self.color("════════════════════════════════════════════════════════════════", "yellow"))
        print("\n🔒 ", self.color("What is AuthChecker?", "green"))
        print("AuthChecker is a cutting-edge tool engineered by the wizards at SecureAxis. Designed to emulate and assess multiple authentication-related vulnerabilities,\nit bridges the gap between security research and practical application!")
        print("\n🔧 ", self.color("Feature Highlights:", "green"))
        print("  ⭐ ", self.color("Brute Force Attack Simulation:", "blue"), "Test the robustness of your password policy.")
        print("  ⭐ ", self.color("Login Page Checker:", "blue"), "Identify login forms on the target page.")
        print("  ⭐ ", self.color("Password Policy Check:", "blue"), "Ensure that your application follows the best practices.")
        print("  ⭐ ", self.color("Session Fixation Check:", "blue"), "Evaluate session security mechanisms.")
        print("  ⭐ ", self.color("Session Timeout Check:", "blue"), "Inspect the reliability of session timeouts.")
        print("  ⭐ ", self.color("Token Predictability Check:", "blue"), "Quantify token security measures.")
        print("  ⭐ ", self.color("Insecure Password Recovery Check:", "blue"), "Identify potential weaknesses in password recovery mechanisms.")
        print("  ⭐ ", self.color("Run All Checks:", "blue"), "Run all checks in one go!")
        print("  ⭐ ", self.color("Dashboard:", "blue"), "View the results of your checks in a beautiful dashboard!")
        
        # ... add any other features you implement in the future
        
        print("\n🌐 ", self.color("Connect With Us:", "green"))
        print("For the latest updates, collaboration opportunities, or to just drop a 'thank you', visit our GitHub repository or connect with us on Facebook or Linkedin. \nLet's make the web a safer place, together!")
        print(self.color("\n[INFO] Returning to main menu in 10 seconds...", "blue"))
        time.sleep(10)
        self.clear()
        self.menu()

  
    def menu(self):
        print("\n")
        print("\n")
        print(self.color("════════════════════════════════════════════════════════════════", "yellow"))
        print(self.color("                    AuthChecker Main Menu", "cyan"))
        print(self.color("════════════════════════════════════════════════════════════════", "yellow"))
        print("\n")
        print("\n🔍 ", self.color("Choose a check to run:", "green"))
        print("  1️⃣ ", self.color("Brute Force Attack Simulation", "blue"))
        print("  2️⃣ ", self.color("Login Page Checker", "blue"))
        print("  3️⃣ ", self.color("Password Policy Check", "blue"))
        print("  4️⃣ ", self.color("Session Fixation Check", "blue"))
        print("  5️⃣ ", self.color("Session Timeout Check", "blue"))
        print("  6️⃣ ", self.color("Token Predictability Check", "blue"))
        print("  7️⃣ ", self.color("Insecure Password Recovery Check", "blue"))
        print("  8️⃣ ", self.color("Run All Checks", "blue"))
        print("  9️⃣ ", self.color("Display Dashboard", "blue"))
        print("  🔟 ", self.color("Check for Updates", "blue"))
        print("  0️⃣ ", self.color("Exit Program", "red"))
        
        print("\n")
        choice = input(self.color("Enter your choice (1-10 or 0): ", "red"))
        return choice
       
        
    def run(self):
        while True:
            choice = self.menu()
            if choice == '1':
                self.brute_force_attack_simulation()
            elif choice == '2':
                self.check_login_page()
            elif choice == '3':
                self.password_policy_check()
            elif choice == '4':
                self.session_fixation_check()
            elif choice == '5':
                self.session_timeout_check()
            elif choice == '6':
                self.token_predictability_check()
            elif choice == '7':
                self.insecure_password_recovery_check()
            elif choice == '8':
                self.run_checks()
            elif choice == '9':
                self.display_dashboard()
            elif choice == '10':
                self.check_for_updates()
            elif choice == '0':
                print(self.color("\n[INFO] Exiting AuthChecker...", "blue"))
                sys.exit(0)
            else:
                print(self.color("\n[ERROR] Invalid choice. Please try again.", "red"))
                time.sleep(2)
                self.clear()
                self.menu()


    def banner(self):
        print(self.color("════════════════════════════════════════════════════════════════", "yellow"))
        print(self.color("                    AuthChecker, Welcome. ", "cyan"))
        print(self.color("════════════════════════════════════════════════════════════════", "yellow"))
        print("", self.color("What you input here will be saved for further use. Make sure you input the correct information.", "red"))
        print("\n🔍 ", self.color("Instructions:", "green"))
        print("  1️⃣ ", self.color("Enter the target URL.", "blue"))
        print("  2️⃣ ", self.color("Enter the username to be tested.", "blue"))
        print("  3️⃣ ", self.color("Enter the password to be tested.", "blue"))
        print("\n")

    def clear(self):
        """
        Clears the terminal screen.
        """
        os.system('cls' if os.name == 'nt' else 'clear')
        
    
        
if __name__ == "__main__":
    checker = AuthChecker()
    Updater.check_for_updates()
    checker.initialize_session()
    checker.clear()
    checker.run()
