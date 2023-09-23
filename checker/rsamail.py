#!/usr/bin/env python3

from ctf_gameserver import checkerlib

from seleniumwire import webdriver
import selenium.common.exceptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.chrome.options import Options

import secrets
import logging
import subprocess
import tempfile
import requests
import time
from json import JSONDecodeError
from datetime import datetime
from Crypto.Util import number

chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--disable-extensions")
chrome_options.add_argument("--no-sandbox")

PORT = 5555


class FaultyServiceException(Exception):
    def __init__(self, result):
        super().__init__(f"Service faulty: {result}")

        self.result = result


def randuser():
    return secrets.token_hex(secrets.randbelow(5) + 4)


def format_message(fromuser, subject, message):
    return f"""FROM: {fromuser}
DATE: {datetime.today().strftime('%d/%m/%Y')}
SUBJECT: {subject}

{message}"""

class TemplateChecker(checkerlib.BaseChecker):

    def new_session(self, olddata={}):
        logging.info("Creating selenium session...")
        driver = webdriver.Chrome(options=chrome_options)
        logging.info("Driver created")
        try:
            driver.set_page_load_timeout(30)
            logging.info("loading page initially...")
            driver.get(f'http://[{self.ip}]:{PORT}/')
            logging.info("initial page load done")
            if olddata:
                for k in olddata:
                    v = olddata[k]
                    logging.info(f"Loading local storage {k}={v}")
                    driver.execute_script("window.localStorage.setItem(arguments[0], arguments[1]);", k, v)
                # reload page for accounts to show up
                logging.info("Selenium reloading...")
                driver.get(f'http://[{self.ip}]:{PORT}/')
                logging.info("Selenium reloaded")

            return driver
        except selenium.common.exceptions.TimeoutException:
            logging.exception("new_session")
            driver.close()
            driver.quit()
            raise
        except selenium.common.exceptions.WebDriverException:
            logging.exception("new_session")
            driver.close()
            driver.quit()
            raise

    def get_data(self, driver):
        return driver.execute_script(
            "var ls = window.localStorage, items = {}; "
            "for (var i = 0, k; i < ls.length; ++i) "
            "  items[k = ls.key(i)] = ls.getItem(k); "
            "return items; ")

    def register1(self, driver, user):
        logging.info(f"Registering user {user} with javascript keygen")
        WebDriverWait(driver, 1, 0.1).until(lambda driver: driver.find_element(By.ID, 'create'))
        driver.find_element(By.ID, 'create').click()
        WebDriverWait(driver, 1, 0.1).until(expected_conditions.alert_is_present())

        alert = driver.switch_to.alert
        alert.send_keys(user)
        alert.accept()

        WebDriverWait(driver, 60, 0.5).until(lambda driver: any([user == element.text.strip() for element in driver.find_element(By.ID, 'accounts').find_elements(By.CLASS_NAME, "account")]))

    def register2(self, driver, user):
        logging.info(f"Registering user {user} with openssl generated key")
        with tempfile.NamedTemporaryFile() as tmp:
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", tmp.name, "-pkeyopt", "rsa_keygen_bits:2048", "-pkeyopt", "rsa_keygen_pubexp:3"])

            WebDriverWait(driver, 1, 0.1).until(lambda driver: driver.find_element(By.ID, 'import'))
            driver.find_element(By.ID, 'import').send_keys(tmp.name)

            WebDriverWait(driver, 1, 0.1).until(expected_conditions.alert_is_present())

            alert = driver.switch_to.alert
            alert.send_keys(user)
            alert.accept()

            WebDriverWait(driver, 2, 0.5).until(lambda driver: any([user == element.text.strip() for element in driver.find_element(By.ID, 'accounts').find_elements(By.CLASS_NAME, "account")]))

    def send_message(self, driver, fromuser, tousers, subject, message):
        logging.info(f'Sending message [{subject}] {message} from {fromuser} to {tousers}')
        driver.find_element(By.ID, 'outbox').click()
        driver.find_element(By.ID, 'recipient').send_keys(','.join(tousers))
        dropdown = Select(driver.find_element(By.ID, 'sender'))
        dropdown.select_by_visible_text(fromuser)
        driver.find_element(By.ID, 'subject').send_keys(subject)
        driver.find_element(By.ID, 'message').send_keys(message)
        driver.find_element(By.ID, 'sendmsg').click()

        driver.wait_for_request(f'/send/{tousers[-1]}', 10)

    def pubkey(self, user):
        try:
            req = requests.get(f'http://[{self.ip}]:{PORT}/pubkey/{user}')
            r = req.json()
            if len(r) != 2:
                logging.warning(f"pubkey is in invalid format: {r}")
                raise FaultyServiceException(checkerlib.CheckResult.FAULTY)
            return r
        except JSONDecodeError:
            logging.warning(f"pubkey is not json: {r}")
            raise FaultyServiceException(checkerlib.CheckResult.FAULTY)

    def backend_send_message(self, fromuser, touser, subject, message):
        try:
            pkey = self.pubkey(touser)
            N = int(pkey[0], 16)
            e = int(pkey[1], 16)
        except ValueError:
            logging.warning(f"Pubkey is invalid: {pkey}")
            raise FaultyServiceException(checkerlib.CheckResult.FAULTY)

        msg = format_message(fromuser, subject, message)
        data = msg.encode() + bytes(b' ' * (2048 // 8 - len(msg) - 1))
        plaintext = int.from_bytes(data, byteorder='big')
        ciphertext = pow(plaintext, e, N)
        r = requests.post(f'http://[{self.ip}]:{PORT}/send/{touser}', data=hex(ciphertext)[2:])
        if r.status_code != 200:
            logging.warning(f"Failed to send message via API: {r}")
        return msg

    def decrypt(self, msg, d, N):
        try:
            ciphertext = int(msg, 16)
        except ValueError:
            logging.warning(f"Message is not hex: {msg}")
            raise FaultyServiceException(checkerlib.CheckResult.FAULTY)
        plaintext = pow(ciphertext, d, N)
        return plaintext.to_bytes(2048 // 8 - 1, byteorder='big').strip()

    def backend_read_messages(self, user, d):
        try:
            pkey = self.pubkey(user)
            N = int(pkey[0], 16)
        except ValueError:
            logging.warning(f"Pubkey is invalid: {pkey}")
            raise FaultyServiceException(checkerlib.CheckResult.FAULTY)
        messages = requests.get(f'http://[{self.ip}]:{PORT}/inbox/{user}').json()
        return [self.decrypt(msg, d, N) for msg in messages]

    def select_account(self, driver, user):
        WebDriverWait(driver, 1, 0.1).until(lambda driver: any([user == element.text.strip() for element in driver.find_element(By.ID, 'accounts').find_elements(By.CLASS_NAME, "account")]))
        inbox = [element for element in driver.find_element(By.ID, 'accounts').find_elements(By.CLASS_NAME, "account") if user == element.text.strip()]
        inbox[0].click()

        driver.wait_for_request(f'/inbox/{user}', 10)

    def get_messages(self, driver, user):
        logging.info(f'Retrieving messages for {user}')
        self.select_account(driver, user)
        inboxlist = driver.find_element(By.ID, "inboxlist")
        messages = inboxlist.find_elements(By.CLASS_NAME, "msg")
        retval = []
        for msg in messages:
            msg.click()
            WebDriverWait(driver, 1, 0.1).until(lambda driver: driver.find_element(By.ID, "selectedmessage").is_displayed())
            retval.append({"from": driver.find_element(By.ID, "frommsg").text,
                           "date": driver.find_element(By.ID, "datemsg").text,
                           "subject": driver.find_element(By.ID, "subjectmsg").text,
                           "content": driver.find_element(By.ID, "textmsg").text
                           })
            driver.find_element(By.ID, "backtoinbox").click()
            WebDriverWait(driver, 1, 0.1).until(lambda driver: not driver.find_element(By.ID, "selectedmessage").is_displayed())
        logging.info(f'Retrieved messages: {retval}')
        return retval

    def place_flag1(self, tick, driver):
        user1 = randuser()
        user2 = randuser()
        self.register2(driver, user1)
        self.register1(driver, user2)

        keydata = self.get_data(driver)
        logging.info(f'Saving private keys: {keydata}')

        checkerlib.store_state(f'flaguser{tick}', [user2])
        checkerlib.store_state(f'keys{tick}', keydata)
        checkerlib.set_flagid(user2)
        flag = checkerlib.get_flag(tick)

        self.send_message(driver, user1, [user2], 'flag', flag)

        # Make mailbox readonly
        self.select_account(driver, user2)
        driver.find_element(By.ID, "disable").click()
        driver.wait_for_request(f'/disable/{user2}', 10)

    def place_flag2(self, tick, driver):
        NUM_RECIPIENTS = 5
        user1 = randuser()
        r = [randuser() for i in range(NUM_RECIPIENTS)]
        self.register2(driver, user1)
        for to in r:
            self.register2(driver, to)

        keydata = self.get_data(driver)
        logging.info(f'Saving private keys: {keydata}')

        checkerlib.store_state(f'flaguser{tick}', r)
        checkerlib.store_state(f'keys{tick}', keydata)
        flag = checkerlib.get_flag(tick)
        checkerlib.set_flagid(','.join(r))

        self.send_message(driver, user1, r, 'flag', flag)

        for user2 in r:
            # Make mailbox readonly
            self.select_account(driver, user2)
            driver.find_element(By.ID, "disable").click()
            driver.wait_for_request(f'/disable/{user2}', 10)

    def place_flag(self, tick):
        driver = None
        try:
            driver = self.new_session()

            if tick % 2 == 0:
                self.place_flag1(tick, driver)
            else:
                self.place_flag2(tick, driver)

            return checkerlib.CheckResult.OK
        except selenium.common.exceptions.TimeoutException:
            logging.exception("place-flag")
            return checkerlib.CheckResult.DOWN
        except selenium.common.exceptions.WebDriverException:
            logging.exception("place-flag")
            return checkerlib.CheckResult.DOWN
        except selenium.common.exceptions.UnexpectedAlertPresentException:
            logging.exception("place-flag")
            return checkerlib.CheckResult.FAULTY
        except FaultyServiceException as e:
            logging.exception("place-flag")
            return e.result
        finally:
            try:
                if driver:
                    driver.close()
                    driver.quit()
            except:
                logging.exception("place-flag")
                return checkerlib.CheckResult.FAULTY

    def check_service(self):
        driver = None
        try:
            driver = self.new_session()

            p = 1
            while (p - 1) % 3 == 0:
                p = number.getPrime(1024)
            q = 1
            while (q - 1) % 3 == 0:
                q = number.getPrime(1024)
            N = p * q
            phi = (p - 1) * (q - 1)
            e = 3
            d = pow(e, -1, phi)

            user1 = randuser()
            user2 = randuser()

            requests.post(f'http://[{self.ip}]:{PORT}/register', json={"user": user2, 'pubkey': [hex(N)[2:], str(e)]})

            self.register2(driver, user1)

            # javascript -> backend
            logging.info("javascript -> backend")
            subject = secrets.token_hex(8)
            body = secrets.token_hex(16)
            self.send_message(driver, user1, [user2], subject, body)

            sent_message = format_message(user1, subject, body)

            messages = self.backend_read_messages(user2, d)
            if not any([message == sent_message.encode() for message in messages]):
                logging.warning(f"Message \"{sent_message}\" not found in {messages} (javascript -> backend)")
                return checkerlib.CheckResult.FAULTY

            # backend -> javascript
            logging.info("backend -> javascript")
            subject = secrets.token_hex(8)
            body = secrets.token_hex(16)

            sent_message = self.backend_send_message(user2, user1, subject, body)

            messages = self.get_messages(driver, user1)
            if not any([message["from"] == user2 and message["content"] == body and message["subject"] == subject for message in messages]):
                logging.warning(f"Message \"{sent_message}\" not found in {messages} (backend -> javascript)")
                return checkerlib.CheckResult.FAULTY

            return checkerlib.CheckResult.OK
        except selenium.common.exceptions.TimeoutException:
            logging.exception("check-service")
            return checkerlib.CheckResult.DOWN
        except selenium.common.exceptions.WebDriverException:
            logging.exception("check-service")
            return checkerlib.CheckResult.DOWN
        except selenium.common.exceptions.UnexpectedAlertPresentException:
            logging.exception("place-flag")
            return checkerlib.CheckResult.FAULTY
        except FaultyServiceException as e:
            logging.exception("check-service")
            return e.result
        finally:
            try:
                if driver:
                    driver.close()
                    driver.quit()
            except:
                logging.exception("place-flag")
                return checkerlib.CheckResult.FAULTY

    def check_flag(self, tick):
        driver = None
        try:
            flaguser = checkerlib.load_state(f'flaguser{tick}')
            keys = checkerlib.load_state(f'keys{tick}')
            if flaguser is None:
                logging.warning("Missing flaguser in state")
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            if keys is None:
                logging.warning("Missing keys in state")
                return checkerlib.CheckResult.FLAG_NOT_FOUND

            logging.info(f'Loaded private keys: {keys}')
            driver = self.new_session(keys)
            flag = checkerlib.get_flag(tick)
            flags_found = True
            assert len(flaguser) > 0, "No flagusers???"
            for user in flaguser:
                messages = self.get_messages(driver, user)
                if not any([message['content'] == flag for message in messages]):
                    flags_found = False
            if flags_found:
                return checkerlib.CheckResult.OK
            else:
                return checkerlib.CheckResult.FLAG_NOT_FOUND
        except selenium.common.exceptions.TimeoutException:
            logging.exception("check-flag")
            return checkerlib.CheckResult.DOWN
        except selenium.common.exceptions.WebDriverException:
            logging.exception("check-flag")
            return checkerlib.CheckResult.DOWN
        except selenium.common.exceptions.UnexpectedAlertPresentException:
            logging.exception("place-flag")
            return checkerlib.CheckResult.FAULTY
        except FaultyServiceException as e:
            logging.exception("check-flag")
            return e.result
        finally:
            try:
                if driver:
                    driver.close()
                    driver.quit()
            except:
                logging.exception("place-flag")
                return checkerlib.CheckResult.FAULTY



if __name__ == '__main__':

    checkerlib.run_check(TemplateChecker)
