# CM3148 Software Security and Malware Analysis coursework task 2

Login authentication system written in Python following SSDLC.

To run the app:

1. Run `git clone https://github.com/clararingrose/cm3148-task2.git` to download the repository
2. Run `cd cm3148-task2` to navigate to the repository
3. Run `python -m venv venv` to set up the virtual environment
4. Run `source venv/bin/activate` to start the virtual environment
5. Run `pip install -r requirements.txt` to install the necessary dependencies
6. Run `python app.py` to start the web app
7. Go to [localhost:8080](https://localhost:8080) on your browser. The app is set to run over HTTPS but does not have certificates, so you will get a security warning - this is safe to ignore.

The app requires a [Mailtrap](https://mailtrap.io) account for email sandboxing. Once you have created an account, go to 'Email Testing' and create a Project. Then, go to your project Inbox > Integration and copy the SMTP username and password into .env

(You may need to replace `python` with `python3` or `py`, and `pip` with `pip3` depending on your Python setup)
