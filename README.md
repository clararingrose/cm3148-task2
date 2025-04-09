# CM3148 Software Security and Malware Analysis coursework task 2

Login authentication system written in Python following SSDLC. Developed using [Flask](https://flask.palletsprojects.com/) for web app functionality and [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) for password strength checking.

To run the app:

1. Clone this repository and navigate to that folder in your terminal
2. Run `python3 -m venv venv` to set up the virtual environment
3. Run `source venv/bin/activate` to start the virtual environment
4. Run `pip3 install -r requirements.txt` to install the necessary dependencies
5. Run `python3 main.py` to start the web app
6. Go to [localhost:8080](http://localhost:8080) on your browser

(You may need to replace `python3` with `python` or `py`, and `pip3` with `pip` depending on your Python setup)