from prettytable import PrettyTable
import webbrowser
import os


# HTML Dashboard class
class HTMLDashboard:

    def __init__(self, log_data):
        self.log_data = log_data

    def generate_html(self):
        html_content = """
        <html>
        <head>
            <title>AuthChecker Dashboard</title>
        </head>
        <body>
            <h2>AuthChecker Scan Results</h2>
            <table border=1>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Scan Type</th>
                        <th>Result</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
        """

        for entry in self.log_data:
            html_content += f"""
            <tr>
                <td>{entry['date']}</td>
                <td>{entry['scan_type']}</td>
                <td>{entry['result']}</td>
                <td>{entry['url']}</td>
            </tr>
            """

        html_content += """
                </tbody>
            </table>
        </body>
        </html>
        """

        return html_content

    def display_in_browser(self):
        content = self.generate_html()
        with open('dashboard.html', 'w') as f:
            f.write(content)
        webbrowser.open('dashboard.html')


# PrettyTable Dashboard class
class PrettyTableDashboard:

    def __init__(self, log_data):
        self.log_data = log_data

    def display(self):
        table = PrettyTable()
        table.field_names = ["Date", "Scan Type", "Result", "URL"]
        for entry in self.log_data:
            table.add_row([entry['date'], entry['scan_type'], entry['result'], entry['url']])
        print(table)
