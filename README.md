# CM3148 Software Security and Malware Analysis coursework task 2

Login authentication system written in Python following SSDLC.

The app requires [reCAPTCHA](https://developers.google.com/recaptcha/intro) v2 Checkbox keys and a [Mailtrap](https://mailtrap.io) account for email sandboxing.

To run the app:

1. Run `git clone https://github.com/clararingrose/cm3148-task2.git` to download the repository
2. Run `cd cm3148-task2` to navigate to the repository
3. Run `python3 -m venv venv` to set up the virtual environment
4. Run `source venv/bin/activate` to start the virtual environment
5. Run `pip3 install -r requirements.txt` to install the necessary dependencies
6. Run `python3 app.py` to start the web app
7. Go to [localhost:8080](http://localhost:8080) on your browser

(You may need to replace `python3` with `python` or `py`, and `pip3` with `pip` depending on your Python setup)