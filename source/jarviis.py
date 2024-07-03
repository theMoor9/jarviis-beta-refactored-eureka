"""
JARVIIS - "Just A Rather Visionary Intelligent Investing System"
-----------------------------------------------------------
Legenda di note di attenzione nel codice

(ctl+F) + KEYWORD 

Keywords:
    - ELIMINATO = Feature non più disponibile/Feature not available
    - REFACTORING = Occorre trovare una nuova soluzione/New solution needed
    - ESAMINA = Occorre trovare una nuova soluzione o possibile uso/New solution or possible use needed
    - UT = Unit Tested
"""

# Python standard modules
try: 
    import os
    import sys
    import time
    import platform
    import subprocess
    import shutil
    import datetime as date
    import threading
    import logging
    import pickle
    import traceback
    import getpass  
    import json
    import zipfile
    import base64
except ImportError as e:
    # Fallback in case of import error
    print(f"Fatal error: Failed to import python standard modules ({e})")
    exit(1)  
# Third-party modules
try:
    import numpy as np
    import pandas as pd
    import ccxt
    from progress.spinner import Spinner
    from progress.spinner import PixelSpinner
    try:
        import pynput  
    except: 
        pynput = None
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import WordCompleter
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
except ImportError as e:
    # Fallback in case of import error
    print(f"Fatal error: Failed to import required modules ({e})")
    exit(1)
# UI & dev tool fix quick setup
try:
    # Permette di eseguire il codice in modalità debug senza freeze dei moduli
    os.environ['PYDEVD_DISABLE_FILE_VALIDATION'] = '1'
    # Reset terminale
    if 'TMUX' in os.environ:
        print("\033[2J\033[H", end="")  # Resetta lo schermo in tmux
    else:
        print("\033c", end="")  # Reset standard del terminale
except Exception as e:
    print(f"Error: Failed to quick setup ({e})")
    pass
# Categorized exceptions for dinamaic handling
GLOBAL_EXCEPTIONS = [
    BaseException,           # Base class for all exceptions
    Exception,               # Base class for all built-in exceptions (excluding system-exiting exceptions)
    ArithmeticError,         # Base class for arithmetic errors
    BufferError,             # Buffer related errors
    LookupError,             # Base class for lookup errors
    
    # Concrete exceptions
    AssertionError,
    AttributeError,
    EOFError,
    FloatingPointError,
    GeneratorExit,
    ImportError,
    ModuleNotFoundError,     # Subclass of ImportError
    IndexError,
    KeyError,
    NameError,
    NotImplementedError,
    OSError,
    OverflowError,
    RecursionError,          # Subclass of RuntimeError
    ReferenceError,
    RuntimeError,
    StopIteration,
    StopAsyncIteration,
    SyntaxError,
    IndentationError,        # Subclass of SyntaxError
    TabError,                # Subclass of IndentationError
    TypeError,
    UnboundLocalError,       # Subclass of NameError
    UnicodeError,
    UnicodeEncodeError,      # Subclass of UnicodeError
    UnicodeDecodeError,      # Subclass of UnicodeError
    UnicodeTranslateError,   # Subclass of UnicodeError
    ValueError,
    ZeroDivisionError,
    
    # OS-related exceptions (subclass of OSError)
    BlockingIOError,         
    ChildProcessError,
    ConnectionError,
    BrokenPipeError,         # Subclass of ConnectionError
    ConnectionAbortedError,  # Subclass of ConnectionError
    ConnectionRefusedError,  # Subclass of ConnectionError
    ConnectionResetError,    # Subclass of ConnectionError
    FileExistsError,
    FileNotFoundError,
    InterruptedError,
    IsADirectoryError,
    NotADirectoryError,
    PermissionError,
    ProcessLookupError,
    TimeoutError,

    # Warnings
    Warning,
    DeprecationWarning,
    PendingDeprecationWarning,
    RuntimeWarning,
    SyntaxWarning,
    UserWarning,
    FutureWarning,
    ImportWarning,
    UnicodeWarning,
    BytesWarning,
    ResourceWarning
]
FATAL_EXCEPTIONS = [
    MemoryError,
    SystemError,
    KeyboardInterrupt,
    SystemExit
]
CCXT_CONNECTION_EXCEPTIONS = [
    ccxt.NetworkError,
    ccxt.ExchangeError,
    ccxt.ExchangeNotAvailable,
    ccxt.DDoSProtection,
    ccxt.RequestTimeout
]

"""
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
Task Buffer:
----------------------------------------
Data frame variables reliability bug fix - Version: 0.6.0-beta.0   UDATED: 2024-06-13
----------------------------------------
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
"""

class ExceptionManager:#UT
    """
    ### Class that manages exceptions 
    Prints them in a formatted way, with the help of the logging object.
    Contains two exception handling methodologies:
        - Exception handling with log
        - Exception handling with log and program termination

    The types of errors that can occur are:
        - Non-critical errors (Normal exceptions with log False if handled robustly)
        - Critical errors (Critical exceptions "Critical = True")
        - Fatal errors (Fatal exceptions "terminate = True")
        - Input errors (Exceptions "log = False")
    """
    def __init__(self, alert_logger):
        self.logger = alert_logger
        # initialize the dev file
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.dev_file_path = os.path.join(parent_dir, 'logs/dev.log')
        with open(self.dev_file_path, 'w') as file:
            file.write("Dev Log:\n")
        
    def handle_exception(self,section ,exception, log=True, critical=False, terminate=False):
        """
        ### Main method to manage exceptions
        Manages an exception, printing a formatted message and
        logging the exception.

        :param exception: The exception to handle.
        :param log: If True, logs the exception.
        :param critical: If True, the exception is critical.
        :param terminate: If True, terminates the program after handling the exception.
        """
        # Prints on dev file the full exception
        with open(self.dev_file_path, 'a') as file:
            file.write(f"{exception}\n")
        # If the termination flag is set, the exception must be critical and logged.
        if terminate and not critical or terminate and not log: 
            log = True
            critical = False

        error_message = (
            f"{section} genotype exception : {exception.__class__.__name__}"
            )
        
        if log:
            if terminate:
                log_method = self.logger.fatal 
            else:
                log_method = self.logger.error
            log_method(error_message)
        if critical:
            raise exception
        if terminate:
            sys.exit(1)   
        time.sleep(10)
class SetupManager:
    """
    ### Environment setup class
    Class that manages all the environmental components for the correct functioning of the program
    ,dynamically between the classes and methods that compose it.

    In particular, it deals with:
        - Create the necessary directories
        - Create the loggers
        - Create the pickle files
        - Create the configuration files
        - Create the API key files
        - Load the API key files
        - Clean the log files
        - Change the backtesting variables
    """
    def __init__(self, symbols, symbol_key, 
                 api_config,indicator_config, 
                 configs, logic_configs, ex_manager):
        self.symbols = symbols
        self.logic_configs = logic_configs
        self.symbol_key = symbol_key
        self.api_config = api_config
        self.indicator_config = indicator_config
        self.configs = configs
        self.directories = self.setup_directories()
        self.loggers = self.setup_loggers()
        self.exceptionManager = ex_manager(self.loggers['logger2'])
        self.static_pin = "1459"
        self.enc_pickle_path = os.path.join(self.directories['cache'], 'pickles.enc')
        self.setup_pickle_files()
        self.enc_keys_path = os.path.join(self.directories['apikeys_dir'], 'api_keys.enc')
        if not os.path.exists(self.enc_keys_path):
            self.api_config_setup()

    def handle_screen(self, reset):
        """
        ### Clean or reset the terminal screen.

        :param reset: If True, resets the screen. If False, simply clears it.
        """
        if 'TMUX' in os.environ:
            # If we are on tmux, we use the appropriate escape sequence
            if reset:
                # Resets the screen in tmux
                print("\033[2J\033[H", end="") 
            else:
                # Cleans the screen in tmux
                print("\033[H\033[2J", end="")  
        else:
            # Otherwise, use the standard escape sequence
            if reset:
                # Standard terminal reset
                print("\033c", end="") 
            else:
                # Standard terminal clean
                print("\033[H\033[J", end="")                                         
    def setup_directories(self):#UT
        """ 
        ### Main function to setup the necessary directories.
        Executes the setup of the necessary directories by creating
        the reference paths inside a dictionary accessible to the entire code
        and checking and creating them in case they do not exist.
        """
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            # Directory paths
            crypto_log_dir = os.path.join(parent_dir, 'logs/cryptos')
            stock_log_dir = os.path.join(parent_dir, 'logs/stocks')
            data_dir = os.path.join(parent_dir, 'data')
            archive = os.path.join(parent_dir, 'test')
            backups_dir = os.path.join(parent_dir, 'data/backups')
            cache = os.path.join(data_dir, 'cache/' + self.symbols[self.symbol_key]['symbol1'])
            apikeys = os.path.join(data_dir, 'keys')
            logging = os.path.join(crypto_log_dir, self.symbols[self.symbol_key]['symbol1'])     
            # Directory creation
            for directory in [crypto_log_dir, data_dir, archive, backups_dir, cache, logging, apikeys]:
                if not os.path.exists(directory):
                    os.makedirs(directory)
            # Directory dictionary configuration
            self.dirs = {
                'crypto_log_dir': crypto_log_dir,
                'data_dir': data_dir,
                'cache': cache,
                'backups_dir': backups_dir,
                'apikeys_dir': apikeys,
                # other directories...
            }
            return self.dirs
        except Exception as e:
            sys.exit(f"Fatal Error: SetupManager.setup_directories(), {str(e)}")
    def setup_loggers(self):#UT  
        """
        ### Main function to setup the necessary loggers.
        Executes the setup of the necessary loggers by creating
        the reference paths, checking and creating the log files
        and configuring the log objects for the two logging tasks:
            - Console log
            - Alert log

        The paths and log objects are inside two dictionaries accessible
        to the entire code.
        """
        try:
            # Paths of the log files
            log_files = {
                'console': os.path.join(self.directories['crypto_log_dir'], 
                                        self.symbols[self.symbol_key]['symbol1'], 
                                        'console.log'),
                'alert': os.path.join(self.directories['crypto_log_dir'], 
                                      self.symbols[self.symbol_key]['symbol1'], 
                                      'alert.log'),
                'dataframe': os.path.join(self.directories['crypto_log_dir'], 
                                          'dataframe.log')
            }
            # Reset of existing log files
            for log_file in log_files.values():
                if os.path.exists(log_file):
                    os.remove(log_file)
            # Initializazion of the loggers
            logger1 = logging.getLogger('logger1')
            logger1.setLevel(logging.INFO)
            fh1 = logging.FileHandler(log_files['console'])
            fh1.setFormatter(logging.Formatter('%(asctime)s - "JARVIIS" - %(message)s'))
            logger1.addHandler(fh1)

            logger2 = logging.getLogger('logger2')
            logger2.setLevel(logging.INFO)
            fh2 = logging.FileHandler(log_files['alert'])
            fh2.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger2.addHandler(fh2)
            # Configuration of the loggers dictionary
            logs = {
                'logger1': logger1,
                'logger2': logger2,
                # Others logger...
            }
            return logs  
        except Exception as e:
            sys.exit(f"Fatal Error: SetupManager.setup_loggers(), {str(e)}")
    def setup_pickle_files(self):#UT
        """
        ### Main function to setup the necessary pickle files.
        Executes the setup of the necessary pickle files by checking
        the existence of the encrypted pickle file and creating a dictionary
        accessible to the entire code for the use of the data contained in it.
        And the creation of new pickle files in case they do not exist.
        """
        try:
            # Load data from the encrypted pickle file if it exists 
            if os.path.exists(self.enc_pickle_path):
                with open(self.enc_pickle_path, 'rb') as file:
                    file_content = file.read()
                    salt = file_content[:16]
                    encrypted_data = file_content[16:]
                _, key = self.derive_key(self.static_pin, salt)
                cipher_suite = Fernet(key)
                decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                pickle_dict = json.loads(decrypted_data)
                if pickle_dict['position_control'] == "None":
                    self.logic_configs['position_control'] = None
                else:
                    self.logic_configs['position_control'] = pickle_dict['position_control']
                self.logic_configs['prc_buy'] = pickle_dict['prc_buy']
                self.logic_configs['prc_sell'] = pickle_dict['prc_sell']
            else:
                # Creates a new pickle file with default values if it does not exist
                currencies = {
                    'BTC': {'sell': 9999999, 'buy': 1, 'acc':"None"},
                    'ETH': {'sell': 9999999, 'buy': 1, 'acc':"None"},
                    'SOL': {'sell': 9999999, 'buy': 1, 'acc':"None"},
                    'AVAX': {'sell': 9999999, 'buy': 1, 'acc':"None"},
                    'ADA': {'sell': 9999999, 'buy': 1, 'acc':"None"}
                }
                # Creates a pickle file
                def create_pickle_file(cache_path, filename, default_value):
                    pickle_file = os.path.join(cache_path, filename)
                    if not os.path.exists(pickle_file):
                        with open(pickle_file, 'wb') as file:
                            pickle.dump(default_value, file)
                for currency in currencies.keys():
                    cache_path = os.path.join(self.directories['data_dir'], 'cache', currency)
                    os.makedirs(cache_path, exist_ok=True)
                    create_pickle_file(cache_path,'last_sell.pickle',currencies[currency]['sell'])
                    create_pickle_file(cache_path, 'last_buy.pickle', currencies[currency]['buy'])
                    create_pickle_file(cache_path, 'access.pickle', currencies[currency]['acc'])
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            # In case of error on the encrypted pickle file, create a new pickle file 
            if not self.save_pickle(0,0,0): 
                # and log the error
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            # In case of error on the encrypted pickle file, create a new pickle file
            else:
                self.exceptionManager.handle_exception("General", exception_id, terminate=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def api_config_setup(self):
        """
        ###Auxiliary method to set up the API configuration.
        Set up the API configuration by prompting the user to enter API keys for various services.
        This method saves the API keys in a dictionary and encrypts them using a user-provided PIN.

        Raises:
            ValueError: If there is a critical error during the setup process.
        """
        try:
            self.handle_screen(reset=False)
            print('JARVIIS: -API keys setup procedure, enter API keys.')
            time.sleep(0.6)
            print('JARVIIS: -Pay particular attention this may compromise my correct execution.')
            time.sleep(0.6)
            a = str(input('JARVIIS: -KRAKEN Trade key >>'))
            b = str(input('JARVIIS: -KRAKEN Trade secret >>'))
            c = str(input('JARVIIS: -KRAKEN Query key >>'))
            d = str(input('JARVIIS: -KRAKEN Query secret >>'))
            e = str(input('JARVIIS: -ALPACA Key >>'))
            f = str(input('JARVIIS: -ALPACA secret >>'))
            # set up the API configuration
            self.api_config = {
                'kraken_tradekey': a,
                'kraken_tradeprivate': b,
                'kraken_querykey': c,
                'kraken_queryprivate': d,
                'base_url': "https://paper-api.alpaca.markets",
                'alpaca_unifiedkey': e,
                'alpaca_unifiedprivate': f,
                'is_configured': True
            }
            self.save_api_keys(getpass.getpass("JARVIIS: -Enter the encryption PIN ") ) 
            self.handle_screen(reset=False)
            print("JARVIIS: -API keys setup successfully completed!")   
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, critical=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def derive_key(self, pin, salt=None):
        """
        ### Auxiliary method to derive a key from a given PIN.
        Derive a key from a given PIN using PBKDF2HMAC with SHA256.

        :param pin: The PIN to derive the key from.
        """
        try:
            if salt is None:
                salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
            return salt, key
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, critical=True)
        except Exception as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def save_pickle(self, p1, p2, p3):
        """
        ### Saves the data in a pickle file, encrypting it with a static PIN.

        :param p1: The first parameter to save.
        :param p2: The second parameter to save.
        :param p3: The third parameter to save.

        Returns:
            bool: True if the data is saved successfully, False otherwise.
        """
        try:
            # Derive the key using a static code
            salt, key = self.derive_key(self.static_pin)
            cipher_suite = Fernet(key)
            # Create a dictionary with the data to save
            data = {
                'prc_buy': p1,
                'prc_sell': p2,
                'position_control': p3
            }
            # Serialize the data using pickle
            serialized_data = json.dumps(data)
            # Encrypt the data
            encrypted_data = cipher_suite.encrypt(serialized_data.encode())
            # Save the salt and encrypted data together
            with open(self.enc_pickle_path, 'wb') as file:
                file.write(salt + encrypted_data)
            return True
        except:
            return False
    def save_api_keys(self, pin):
        """
        ### Saves the API keys in an encrypted file.

        :param pin: The PIN to use for encryption.
        """
        try:
            salt, key = self.derive_key(pin)
            cipher_suite = Fernet(key)
            # Usa json.dumps() per convertire in una stringa JSON
            api_keys_str = json.dumps(self.api_config)  
            encrypted_data = cipher_suite.encrypt(api_keys_str.encode())
            with open(self.enc_keys_path, 'wb') as file:
                file.write(salt + encrypted_data)  # Salva il salt e i dati crittografati insieme
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, critical=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def load_api_keys(self, pin, limit_attempts=0):
        """
        ### Load the API keys from an encrypted file.
        
        :param pin: The PIN to use for decryption.

        Returns:
            dict: The API keys configuration.
        
        Raises:
            invalidToken: If the PIN is incorrect.

            - If the user enters 'k' or 'K', the encrypted file is deleted and the setup is restarted.
            - handles the exception with a maximum of 3 attempts.

        """
        try:
            self.handle_screen(reset=True)
            attempts = 3
            while attempts > limit_attempts:
                if attempts < 3 :
                    self.handle_screen(reset=False)
                    time.sleep(0.9) 
                    pin = getpass.getpass("JARVIIS: -Enter decryption PIN ")
                    break
                try:
                    if not os.path.exists(self.enc_keys_path):
                        self.handle_screen(reset=False)
                        print(
"JARVIIS: -The encrypted API keys file does not exist. Follow the setup first."
)
                        time.sleep(3.3)
                        self.api_config_setup()

                    with open(self.enc_keys_path, 'rb') as file:
                        file_contents = file.read()
                    # Salt extraction
                    salt = file_contents[:16] 
                    # Extract encrypted data
                    encrypted_data = file_contents[16:]  
                    _, key = self.derive_key(pin, salt=salt)
                    cipher_suite = Fernet(key)
                    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                    self.api_config = json.loads(decrypted_data)
                    return self.api_config
                # Catch of specific exceptions
                except Exception as e:  
                    exception_name = e.__class__.__name__
                    if exception_name == "InvalidToken":
                        if pin in ('k','K'): 
                            if os.path.exists(self.enc_keys_path):
                                os.remove(self.enc_keys_path)
                            self.api_config_setup()
                            return self.api_config
                        else:
                            time.sleep(0.9)
                            print("JARVIIS: -Wrong PIN! ")
                            """
                            Gives the user another chance, 
                            if they haven't exceeded the maximum number of attempts
                            """
                            if attempts > limit_attempts + 1:  
                                attempts -= 1
                                time.sleep(0.9)
                                print("JARVIIS: -Remaining attempts: " + str(attempts))
                                time.sleep(3)
                                pass
                            else:
                                time.sleep(0.9)
                                print("JARVIIS: -Maximum number of attempts reached. Exiting.")
                                # Exits after the maximum number of attempts
                                sys.exit(0)  
                    else:
                        print(f"JARVIIS: -An unexpected error occurred: {exception_name}")
                        pass
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, terminate=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def log_cleaner(self):
        pass
        # while True:
        #     time.sleep(3)
        #     if os.path.exists(self.directories['crypto_log_dir'] + '/Alert.log'):
        #         creation_time = os.path.getctime(self.directories['crypto_log_dir'] + '/Alert.log')
        #         if (time.time() - creation_time) // (24 * 3600) >= 1:
        #             with open(self.directories['crypto_log_dir'] + '/Alert.log', 'w'):
        #                 pass # Il file viene pulito
        #             if os.path.exists(self.directories['crypto_log_dir'] + '/Alert.log'):
        #                 src_file_path = self.directories['crypto_log_dir'] + '/Alert.log'
        #                 shutil.move(src_file_path, self.directories['backups_dir'])
        #                 zip_name = str(date.datetime.now().date())+".zip"
        #                 # Creare un nuovo file ZIP
        #                 zip_file = zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED)
        #                 # Iterare attraverso tutti i file nella cartella e aggiungerli al file ZIP
        #                 for root, dirs, files in os.walk(self.directories['backups_dir'] + '/alerts'):
        #                     for file in files:
        #                         # Costruire il percorso del file da aggiungere al file ZIP
        #                         file_path = os.path.join(root, file)
        #                         # Aggiungere il file al file ZIP
        #                         zip_file.write(file_path)
        #                 # Chiudere il file ZIP
        #                 zip_file.close()
        #     # dopo 7 giorni e registra archivio   
        #     if os.path.exists(self.directories['crypto_log_dir']+'/Console.log'):
        #         creation_time = os.path.getctime(self.directories['crypto_log_dir']+'/Console.log')
        #         if (time.time() - creation_time) // (24 * 3600) >= 30:
        #             with open(self.directories['crypto_log_dir']+'/Console.log', 'w'):
        #                 pass # Il file viene pulito
        #             if os.path.exists(self.directories['crypto_log_dir']+'/Console.log'):
        #                 src_file_path = self.directories['crypto_log_dir']+'/Console.log'
        #                 shutil.move(src_file_path, self.directories['backups_dir'])
        #                 zip_name = str(date.datetime.now().date())+".zip"
        #                 # Creare un nuovo file ZIP
        #                 zip_file = zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED)
        #                 # Iterare attraverso tutti i file nella cartella e aggiungerli al file ZIP
        #                 for root, dirs, files in os.walk(self.directories['backups_dir']+'console'):
        #                     for file in files:
        #                         # Costruire il percorso del file da aggiungere al file ZIP
        #                         file_path = os.path.join(root, file)
        #                         # Aggiungere il file al file ZIP
        #                         zip_file.write(file_path)
        #                 # Chiudere il file ZIP
        #                 zip_file.close()
    def change_variables(self):
        """
        ### Changes the backtesting variables.
        Allows the user to change the backtesting variables dynamically through the UI.
        """
        try:
            self.handle_screen(reset=True)
            print(
            """
JARVIIS: -Change Backtesting Variables:

    CHOOSE STRATEGY ELEMENT
    ------------------------
    Indicators configs: 
    [ 1 ] Bollinger Bands
    [ 2 ] MACD/SMA Periods
    [ 3 ] ADX/RSI Periods

    General configs:
    [ 4 ] Fee
    [ 5 ] Trail/stop loss tolerance
    [ 6 ] Leverage

    [ 0 ] Exit\n
            """
            )

            def handle_bollinger_bands():
                time.sleep(0.9)
                print("""
JARVIIS: -The granularity of the time_frame must be one of the following:

        ‘1m’, ‘5m’, ‘15m’, ‘30m’, ‘1h’, ‘4h’,‘1d’, ‘1w’, or ‘2w’
                      
                      """)
                time.sleep(0.9)
                a = str(input('JARVIIS: -Data Frame 1 time frame >>'))
                b = int(input('JARVIIS: -Data Frame 1 length >>'))
                c = int(input('JARVIIS: -Data Frame 1 multiplier >>'))
                d = str(input('JARVIIS: -Data Frame 2 time frame >>'))
                e = int(input('JARVIIS: -Data Frame 2 length >>'))
                f = int(input('JARVIIS: -Data Frame 2 multiplier >>'))
                g = int(input('JARVIIS: -Bollinger tentatives >>'))
                self.indicator_config['df1']['time_frame'] = a
                self.indicator_config['df1']['length'] = b
                self.indicator_config['df1']['mult'] = c
                self.indicator_config['df2']['time_frame'] = d
                self.indicator_config['df2']['length'] = e
                self.indicator_config['df2']['mult'] = f
                self.configs['logic_triggers']['LB_value'] = g
                self.handle_screen(reset=True)
                return
            def handle_macd_sma_periods():
                time.sleep(0.9)
                print("""
JARVIIS: -Set the period for the following Moving Averages and MACD:
                      """)
                time.sleep(0.9)
                a = str(input('JARVIIS: -SMA period 1 >>'))
                b = str(input('JARVIIS: -SMA period 2 >>'))
                c = str(input('JARVIIS: -MACD period 1 >>'))
                d = str(input('JARVIIS: -MACD period 2 >>'))
                self.indicator_config['SMA_period_thin'] = a
                self.indicator_config['SMA_period_wide'] = b
                self.indicator_config['MACD_period_thin'] = c
                self.indicator_config['MACD_period_wide'] = d
                self.handle_screen(reset=True)
                return
            def handle_adx_rsi_periods():
                time.sleep(0.9)
                print("""
JARVIIS: -Set the period for the following indicators:
                      """)
                time.sleep(0.9)
                a = str(input('JARVIIS: -ADX period >>'))
                b = str(input('JARVIIS: -RSI period >>'))
                self.indicator_config['ADX_period'] = a
                self.indicator_config['RSI_period'] = b
                self.handle_screen(reset=True)
                return
            def handle_fee():
                time.sleep(0.9)
                print("""
JARVIIS: -Set the maximum fee expected:
                      """)
                time.sleep(0.9)
                input_ = str(input('JARVIIS: -Fee % multiplier >>'))
                self.configs['fee'] = input_
                self.handle_screen(reset=True)
                return
            def handle_trail_stop_loss_tolerance():
                time.sleep(0.9)
                print("""
JARVIIS: -Set the tolerance for the following stop loss and trail stop values:
                      """)
                time.sleep(0.9)
                a = str(input('JARVIIS: -Sell stop loss tolerance % multiplier>>'))
                b = str(input('JARVIIS: -Buy stop loss tolerance % multiplier>>'))
                c = str(input('JARVIIS: -Buy trail stop tolerance % multiplier>>'))
                d = str(input('JARVIIS: -Sell trail stop tolerance % multiplier>>'))
                self.configs['logic_triggers']['sell_stop_loss_tolerance'] = a
                self.configs['logic_triggers']['buy_stop_loss_tolerance'] = b
                self.configs['logic_triggers']['buy_trailstop_tolerance'] = c
                self.configs['logic_triggers']['sell_trailstop_tolerance'] = d
                self.handle_screen(reset=True)
                return
            def handle_leverage():
                time.sleep(0.9)
                print(
                    """
JARVIIS: -Change mode of leverage :

    CHOOSE MODE
    --------------
    [ M ] Manual
    [ A ] Automatic MACD signal

    * Wrong input sets Auto mode
                    """
                    )
                time.sleep(0.9)
                input_ = input("JARVIIS: -Select mode >> ")
                if input_ == 'M' or 'm':
                    time.sleep(0.9)
                    input_ = str(input('\nJARVIIS: -Leverage multiplier >> '))
                    self.configs['params_sell']['leverage'] = input_
                    self.configs['params_buy']['leverage'] = input_
                    if self.logic_configs['trend_flow'] == 'Bullish':
                        self.configs['params_sell']['reduce_only'] = True
                        self.configs['params_buy']['reduce_only'] = False
                    if self.logic_configs['trend_flow'] == 'Bearish':
                        self.configs['params_sell']['reduce_only'] = False
                        self.configs['params_buy']['reduce_only'] = True
                    self.configs['auto_leverage_selector'] = False
                    self.handle_screen(reset=True)
                    return
                else:
                    self.configs['params'].clear()
                    self.configs['auto_leverage_selector'] = True
                    self.handle_screen(reset=True)
                    return
            
            time.sleep(0.9)
            input_ = input("JARVIIS: -Enter the element code >> ")
            input_ = str(input_)
            # Verifies the user's input and calls the appropriate function
            if input_ == '1':
                handle_bollinger_bands()
            elif input_ == '2':
                handle_macd_sma_periods()
            elif input_ == '3':
                handle_adx_rsi_periods()
            elif input_ == '4':
                handle_fee()
            elif input_ == '5':
                handle_trail_stop_loss_tolerance()
            elif input_ == '6':
                handle_leverage()
            elif input_ == '0':
                return
            else:
                time.sleep(0.9)
                print("\nJARVIIS: -Invalid input. Please try again.")
                time.sleep(0.9)
                return
            
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, terminate=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    @staticmethod
    def static_handle_screen(reset = True):
        """
        ### Handle sreen clone method
        Static method to clean or reset the terminal screen outside.
        Cleans or resets the terminal screen based on the function instantiation.

        :param reset: If True, resets the screen. If False, simply clears it.
        """
        if 'TMUX' in os.environ:
            # Se siamo su tmux, utilizziamo la sequenza di escape appropriata
            if reset:
                print("\033[2J\033[H", end="")  # Resetta lo schermo in tmux
            else:
                print("\033[H\033[2J", end="")  # Pulisce lo schermo in tmux
        else:
            # Altrimenti, utilizziamo la sequenza di escape standard
            if reset:
                print("\033c", end="")  # Reset standard del terminale
            else:
                print("\033[H\033[J", end="")  # Pulizia standard del terminale )
    @staticmethod
    def cache_cleaner():
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            data_dir = os.path.join(parent_dir, 'Data')
            spinner_cache = Spinner('JARVIIS: -I am wiping cache memory. ')
            # Verifica se la cartella "data" esiste
            if os.path.exists(data_dir):
                cache_dir = os.path.join(data_dir, 'cache')  # Percorso alla cartella "cache"

                # Verifica se la cartella "cache" esiste
                if os.path.exists(cache_dir):
                    # Elenco delle cartelle da cancellare
                    folders_to_clear = ['BTC', 'ETH', 'SOL', 'AVAX', 'ADA']

                    # Ciclo per cancellare il contenuto delle cartelle
                    for folder_name in folders_to_clear:
                        folder_path = os.path.join(cache_dir, folder_name)
                        spinner_cache.next()
                        time.sleep(0.3)
                        # Verifica se la cartella esiste
                        if os.path.exists(folder_path):
                            # Elimina tutti i file nella cartella
                            for filename in os.listdir(folder_path):
                                file_path = os.path.join(folder_path, filename)
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                                spinner_cache.next()
                                time.sleep(0.3)
                            # Elimina tutte le sottocartelle nella cartella
                            for subfolder in os.listdir(folder_path):
                                subfolder_path = os.path.join(folder_path, subfolder)
                                if os.path.isdir(subfolder_path):
                                    shutil.rmtree(subfolder_path)
                                spinner_cache.next()
                                time.sleep(0.3)
                
            spinner_cache.finish()
        except Exception as e:
            sys.exit(f"Fatal Error: SetupManager.cache_cleaner(), {str(e)}")
class ThreadManager:
    """
    ### Thread Manager class

    Class that manages the threads of the program, starting them and stopping them
    dynamically between the classes and methods that compose it.

    In particular, it deals with:
        - Throttle the engine
        - Listen for commands
        - Clean the log files
    """
    def __init__(self, main_class, symbols, symbol_key, ex_manager):
        self.exceptionManager = ex_manager
        self.easter_egg = False
        self.pause_spinner = False
        self.closing_spinner = False
        self.first_fire = True
        self.symbols = symbols
        self.symbol_key = symbol_key 
        self.jarviisReactor = main_class
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.exe_thread = threading.Thread(target = self.jarviisReactor.core)
        self.spinner = None  
        if pynput is not None:
            self.commands_thread = threading.Thread(target = self.listen_for_commands)
            self.commands_thread.start()
        else:
            self.commands_thread = None
        self.throttle_engine_thread = threading.Thread(target = self.throttle_engine)
        self.throttle_engine_thread.start()
        # self.setupManager = su_class # su_class è da aggiunger al costruttore
        # self.clean_log_thread = threading.Thread(target = self.setupManager.log_cleaner)
        # self.clean_log_thread.start()
        self.threads = {
            1: self.throttle_engine_thread,
            2: self.commands_thread,
            #3: self.clean_log_thread,
        }
    
    def handle_screen(self, reset):
        """
        ### Handle sreen method
        Cleans or resets the terminal screen based on the function instantiation.
        
        :param reset: If True, resets the screen. If False, simply clears it.
        """
        if 'TMUX' in os.environ:
            # If we are on tmux, we use the appropriate escape sequence
            if reset:
                # Resets the screen in tmux
                print("\033[2J\033[H", end="") 
            else:
                # Cleans the screen in tmux
                print("\033[H\033[2J", end="")  
        else:
            # Otherwise, use the standard escape sequence
            if reset:
                # Standard terminal reset
                print("\033c", end="") 
            else:
                # Standard terminal clean
                print("\033[H\033[J", end="")                                       
    def throttle_engine(self):
        """
        ### Thread initialization function
        Method that initializes the spark for the start 
        of the threading of the core function
        and manages the display of the running program using the spinner 
        with a controlled variable that allows the program to be paused and 
        resumed to display other scripts progress.
        """
        try:
            # Uses the key to access the correct symbol
            symbol = self.symbols[self.symbol_key]['symbol1']  
            if platform.system() == 'Linux':
                self.spinner = Spinner('JARVIIS: -Running on ' + symbol + " ")
            else:
                self.spinner = PixelSpinner('JARVIIS: -Running on ' + symbol + " ")
            time.sleep(3.3)
            self.handle_screen(reset=False) 
            # Variable control for the spinner
            while not self.closing_spinner:
                if self.exe_thread.is_alive() and not self.pause_spinner :
                    self.spinner.next()
                elif not self.pause_spinner :
                    self.spark()
                time.sleep(0.1)
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, terminate=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def spark(self):
        """
        ### Spark method for core thread execution
        Function that initializes the program execution thread
        according to the first_fire regulation that allows to
        avoid the double initialization error of the thread as
        an extra security measure.
        """
        try:
            if self.first_fire:
                self.first_fire = False
                self.exe_thread.start()
            else:
                self.handle_screen(reset=True)
                print("Start Failed.")
                time.sleep(6)
                self.first_fire = True
                logger2.error('Error: Failed throttle up')
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, terminate=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
    def listen_for_commands(self):
        """
        ### Keyboard command listener
        Method that initializes the listening of keyboard commands
        and manages the general functionalities of the program
        if the operating system allows it.

        The commands are:
            - [ESC] to start the shutdown procedure
            - [DEL] to cancel the closure
            - [D] to update the dataframe log script
            - [R] to run the resource usage script
        """
        global pressed_key
        # Flag that allows the error to be printed only once
        first_time_error = True 
        def on_press(key):
            """
            ### Keyboard listener function
            Function that listens for keyboard commands and assigns
            the pressed key to a global variable for use in the main function.
            
            :param key: The pressed key.
            """
            global pressed_key
            if first_time_error:
                try:
                    if key == pynput.keyboard.Key.delete:
                        pressed_key = 'delete'
                    elif key == pynput.keyboard.Key.space:
                        pressed_key = 'space'
                    elif key == pynput.keyboard.Key.enter:
                        pressed_key = 'enter'
                    elif key == pynput.keyboard.Key.esc:
                        pressed_key = 'esc'
                    elif getattr(key, 'char', None):
                        pressed_key = key.char
                    else:
                        pressed_key = None
                except AttributeError:
                    pressed_key = str(key)
        try:
            pressed_key = None
            listener = pynput.keyboard.Listener(on_press=on_press)
            listener.start()  
            while first_time_error:     
                if pressed_key in ('esc','Esc','ESC'):
                    self.pause_spinner = True
                    self.handle_screen(reset=True)
                    print("JARVIIS: -Starting shutdown procedure...\n")
                    time.sleep(0.9)
                    print("JARVIIS: -Press [Entr] to confirm [Del] to go back")
                    while True:
                        if pressed_key == 'enter':
                            self.handle_screen(reset=False)
                            self.jarviisReactor.taskManager.initiate_shutdown()
                            self.hitman()
                            self.handle_screen(reset=True)
                            print("JARVIIS: -Goodbye! :)")
                            time.sleep(10)
                            self.handle_screen(reset=False)
                            sys.exit()
                        # Easter egg
                        elif pressed_key in ('k','K'):
                            self.handle_screen(reset=False)
                            self.jarviisReactor.taskManager.initiate_shutdown()
                            self.easter_egg = True
                            self.hitman()
                            self.handle_screen(reset=True)
                            print("JARVIIS: -Goodbye! :)")
                            time.sleep(3)
                            print("JARVIIS: -...")
                            time.sleep(3)
                            print("Hitman: *shoots*")
                            self.handle_screen(reset=False)
                            print("*!!!Bang!!!*")
                            time.sleep(0.5)
                            self.handle_screen(reset=False)
                            print("*...Silence...*")
                            time.sleep(5)
                            self.handle_screen(reset=False)
                            print("JARVIIS: -I can't be killed for real, bye! ;)")
                            time.sleep(3)
                            self.handle_screen(reset=True)
                            sys.exit(0)
                        elif pressed_key == ('delete'):
                            self.handle_screen(reset=False)
                            # Resets if closure is canceled
                            self.pause_spinner = False  
                            print("JARVIIS: -Procedure canceld.")
                            time.sleep(3)
                            self.handle_screen(reset=False)
                            break
                # Update dataframe log script 
                elif pressed_key in ('d','D'):
                    self.pause_spinner = True
                    # Saves the dataframe in a readable format by Dipso.py
                    self.jarviisReactor.dataframe_handler()
                    # Calls Dipso.py script and pauses current spinner
                    dipso_script_path = os.path.join(self.current_dir, "dipso.py")
                    subprocess.run([sys.executable, dipso_script_path], check=True, shell=False )
                    self.handle_screen(reset=False)
                    self.pause_spinner = False
                # Resouce usage script
                elif pressed_key in ('r', 'R'): 
                    self.pause_spinner = True
                    # Gets the path of the current directory of the script
                    # Builds the path of the Garu.py script
                    garu_script_path = os.path.join(self.current_dir, 'garu.py')
                    # Calls Garu.py script and pauses current spinner
                    subprocess.run([sys.executable, garu_script_path], check=True, shell=False)
                    self.handle_screen(reset=False)
                    self.pause_spinner = False  
                pressed_key = None
        except SystemExit:
            sys.exit(0)
        except Exception as e:
            if first_time_error:
                logger2.error(f"Command error: {str(e)}")
                first_time_error = False 
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)   
    def hitman(self):
        """
        ### Hitman method
        Method that manages the termination of all threads
        when the shutdown procedure is started.
        The method waits for the threads to finish their execution.
        """
        try:
            print("Hitman: Terminating ongoing threads...")
            time.sleep(0.9)
            self.closing_spinner = True
            for thread_id, thread_obj in self.threads.items():           
                if thread_obj is not threading.current_thread():
                    thread_obj.join()
                    # Print the thread identifier and the thread object name
                    print(f"Hitman: Thread ID {thread_id} {thread_obj.name} terminated successfully.")
                    time.sleep(0.9)
            print("Hitman: All threads have been closed. ")
            # Easter egg
            if self.easter_egg :
                time.sleep(3)
                print("Hitman: Program 'bout to be killed bitch.")
                time.sleep(3)
            time.sleep(3)
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, terminate=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError, terminate=True)
class JarviisReactor:
    """
    ### Jarviis Main Class
    This class has all the core methods that are key to the 
    expression of the app meaning

    Composition:
        - Two auxiliary classes
        - Core method cicling
        - Auxliary methods
    """
    def __init__(self, symbols, symbol_key, 
                 api_config, indicator_config, 
                 configs, logic_configs, data_dir, 
                 su_class, ex_manager):
        self.chart = None
        self.support_chart = None
        self.exceptionManager = ex_manager
        # Shutdown flag
        self.shutdown_flag = False 
        # symbols_config
        self.symbols = symbols 
        # key of the selected symbol in the search menu
        self.symbol_key = symbol_key 
        self.indicator_config = indicator_config 
        self.setupManager = su_class
        (self.couple, 
         self.symbolSel1,
         self.symbolSel2,
         self.time_frame,
         self.time_frame2) = (self.symbols[self.symbol_key]['couple'],                    
                            self.symbols[self.symbol_key]['symbol1'],
                            self.symbols[self.symbol_key]['symbol2'],
                            self.indicator_config['df1']['time_frame'],
                            self.indicator_config['df2']['time_frame'])
        self.api_config = api_config
        self.configs = configs
        self.logic_configs = logic_configs
        self.csv_data_path =  os.path.join(data_dir, "Csv")
        self.taskManager = self.TaskManager(self, self.api_config, 
                                            self.symbols, self.symbol_key, 
                                            self.configs, self.exceptionManager)
        self.setup_trading_environment()
    
    class TaskManager:#UT
        """
        ### Task Manager class
        This class manages the auxiliary tasks of the program,
        such as the handling of connections, the execution of
        the elements that consitutes the core logic, 
        and the management of the shutdown procedure.

        Relationships:
            - Setup Manager
            - Core logic
            - Exception Manager
        """
        def __init__(self, parent, api_config, symbols, symbol_key, configs, ex_manager):
            self.exceptionManager = ex_manager
            self.api_config = api_config
            self.api_bridges = {
                # Dictionary dedicated to cataloging the various bridges created with the apikeys,
                # aimed at making the code scalable in terms of the number of exchanges available
                'kraken_trade' : None,
                'kraken_query' : None,
                'alpaca_unified' : None,
            }
            self.symbols = symbols
            self.symbol_key = symbol_key
            self.parent = parent
            self.configs = configs
            
        def connection_handler(self, signal):
            """
            ### Connection handler method
            Method that manages the connection to the APIs
            and the reconnection in case of disconnection.
            
            :param signal: The signal to manage the connection.
            """
            if signal == "set":
                self.api_bridges['kraken_trade'] = ccxt.kraken({
                    'apiKey': self.api_config['kraken_tradekey'],
                    'secret': self.api_config['kraken_tradeprivate'],
                    'enableRateLimit': True,
                })
                self.api_bridges['kraken_query'] = ccxt.kraken({
                    'apiKey': self.api_config['kraken_querykey'],
                    'secret': self.api_config['kraken_queryprivate'],
                    'enableRateLimit': True,
                })
            if signal == "check":
                attempts = 0
                time.sleep(10)
                while self.alchemist('KRA120') == False and attempts < 3600:
                    self.api_bridges['kraken_trade'] = ccxt.kraken({
                        'apiKey': self.api_config['kraken_tradekey'],
                        'secret': self.api_config['kraken_tradeprivate'],
                        'enableRateLimit': True,
                    })
                    self.api_bridges['kraken_query'] = ccxt.kraken({
                        'apiKey': self.api_config['kraken_querykey'],
                        'secret': self.api_config['kraken_queryprivate'],
                        'enableRateLimit': True,
                    })
                    attempts += 1
                    time.sleep(1)
                if attempts == 3600:
                    logger2.error(f'Connection Error: {attempts} too many attempts')
                    return False
                logger2.info(f'Connection restored successfully')
                time.sleep(1)
                return True
            
                    
            """
            self.api_bridges['alpaca_unified'] = (
                alpapi.REST( Instantiate REST API Connection EXE
                    key_id=general1, alpaca_exekey
                    secret_key= general2, alpaca_exeprivate
                    base_url= general3,  base_url
                    api_version='v2'
                    )
                )
            """   
        def alchemist(self,code,general1= '',general2='',general3='',general4='', general5=''):
            """
            ### Alchemist method
            Method that manages the alchemy of the program,
            transforming the codes into the desired actions.

            STRUTTURA achemsit() CODE "ABC000"
            Kraken: KRA
            Alpaca: ALP
            110: ... 
            120: ceck connetion 
            210: fetch balance 
            220: fetch_ohlcv 
            300: BUY/SELL 
            ...: ...

            :param code: The code to be transformed.
            :param generalN: General parameters used for the alchemy.
            """
            if len(code) == 6:
                if code[0:3] == 'KRA':
                    # To be implemented
                    if code[3:6]== '110': 
                        return None
                    # Connection check
                    if code[3:6]== '120':
                        if self.api_bridges['kraken_trade'].has['fetchTicker'] and self.api_bridges['kraken_query'].has['fetchTicker']:
                            return True
                        else:
                            return False
                    # Balance
                    if code[3:6]== '210':
                        while True:
                            try:
                                self.connection_handler(signal= 'set')
                                return self.api_bridges['kraken_query'].fetchBalance()
                            except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:   
                                self.exceptionManager.handle_exception("Connection",conn_err,log=True)                         
                                time.sleep(30)
                                # Gestione connessione
                                if self.connection_handler(signal= 'check'):
                                    # Ritenta l'operazione dopo aver ristabilito la connessione
                                    logger2.info(f'Restoring operations')
                                else:
                                    self.exceptionManager.handle_exception("Connection", conn_err,critical=True)
                            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                                self.exceptionManager.handle_exception("General", exception_id,critical=True)
                            except tuple(FATAL_EXCEPTIONS) as FatalError:
                                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
                    # Market
                    if code[3:6]== '220':
                        while True:
                            try:   
                                self.connection_handler(signal= 'set')
                                """
                                general1 = couple,
                                general2 = time_frame,
                                general3 = since,
                                general4 = limit
                                """
                                return self.api_bridges['kraken_query'].fetch_ohlcv(general1, general2) 
                            except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:                            
                                self.exceptionManager.handle_exception("Connection", conn_err,log=True)
                                time.sleep(30)
                                # Gestione connessione
                                if self.connection_handler(signal= 'check'):
                                    # Ritenta l'operazione dopo aver ristabilito la connessione
                                    logger2.info(f'Restoring operations')
                                else:
                                    self.exceptionManager.handle_exception("Connection", conn_err,critical=True)
                            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                                self.exceptionManager.handle_exception("General", exception_id,critical=True)
                            except tuple(FATAL_EXCEPTIONS) as FatalError:
                                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
                    # Buy/Sell
                    if code[3:6]== '300':
                        while True:
                            try:
                                self.connection_handler(signal= 'set')
                                """
                                general1 = couple,
                                general2 ='limit/market',
                                general3 = 'buy/sell',
                                general4 = amount
                                general4.1 = price only for limit
                                general5 = params{'leverage': multiplier, 'reduce_only':True/False }
                                """

                                return self.api_bridges['kraken_trade'].createOrder(general1, 
                                                                                    general2, 
                                                                                    general3, 
                                                                                    general4,
                                                                                    None,
                                                                                    general5)      
                            except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:                           
                                self.exceptionManager.handle_exception("Connection", conn_err,log=True)
                                time.sleep(30)
                                # Gestione connessione
                                if self.connection_handler(signal= 'check'):
                                    # Ritenta l'operazione dopo aver ristabilito la connessione
                                    logger2.info(f'Restoring operations')  
                                else:
                                    self.exceptionManager.handle_exception("Connection", conn_err,critical=True)
                            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                                self.exceptionManager.handle_exception("General", exception_id,critical=True)
                            except tuple(FATAL_EXCEPTIONS) as FatalError:
                                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
                    # Retrieve balance
                    if code[3:6]== '400':
                        while True:
                            symbolSel1 = self.symbols[self.symbol_key]['symbol1']   
                            try:
                                self.connection_handler(signal= 'set')
                                blnc = self.api_bridges['kraken_query'].fetchBalance()                       
                                stablecoin_total_size = general1
                                crypto_total_size = blnc['free'][symbolSel1]
                                return (stablecoin_total_size,crypto_total_size)
                            except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:                           
                                self.exceptionManager.handle_exception("Connection", conn_err,log=True)
                                time.sleep(30)
                                if self.connection_handler(signal= 'check'):
                                    # Retry the operation after restoring the connection
                                    logger2.info(f'Restoring operations')
                                else:
                                    self.exceptionManager.handle_exception("Connection", conn_err,critical=True)
                            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                                self.exceptionManager.handle_exception("General", exception_id,critical=True)
                            except tuple(FATAL_EXCEPTIONS) as FatalError:
                                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
                    # Operation suitability and taxes
                    if code[3:6]== '410':
                        try:
                            # Calcolo della tassa per la vendita
                            tax = (general1 * self.configs['fee'])  # Tassa basata sull'ultimo prezzo di chiusura per la vendita
                            # Calcolo del profitto considerando l'ultima operazione di vendita
                            profit_sell = general1 - general2
                            gross_profit_sell = profit_sell - tax
                            # Calcolo del profitto considerando l'ultima operazione di acquisto
                            profit_buy = general3 - general1
                            gross_profit_buy = profit_buy - tax
                            return gross_profit_sell, gross_profit_buy
                        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                            self.exceptionManager.handle_exception("General", exception_id, critical=True) 
                        except tuple(FATAL_EXCEPTIONS) as FatalError:
                            self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
                    # Range value from percentage
                    if code[3:6]== '420':
                        try:
                            # Usato per calcolare il prezzo di acquisto/vendita in base al profitto percentuale
                            if general3 == 'long':
                                return general1 * (1 - (general2 / 100))
                            elif general3 == 'short':
                              return general1 * (1 + (general2 / 100))
                        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                            self.exceptionManager.handle_exception("General", exception_id, critical=True) 
                        except tuple(FATAL_EXCEPTIONS) as FatalError:
                            self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
                if code[0:3] == 'ALP': 
                    # To be implemented
                    if code[3:6] == '110':
                        pass
                    # To be implemented
                    if code[3:6]== '120':
                        pass
                    # Account
                    if code[3:6]== '210':
                        try:
                            self.connection_handler(signal= 'set')
                            return self.api_bridges['alpaca_unified'].get_account() # Print Account Detailsprint(account.id, account.equity, account.status)
                        except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:                           
                            self.exceptionManager.handle_exception("Connection", conn_err,log=True)
                            time.sleep(30)
                            if self.connection_handler(signal= 'check'):
                                # Ritenta l'operazione dopo aver ristabilito la connessione
                                return self.api_bridges['kraken_query'].get_account() 
                            else:
                                logger2.Crirtical(f"Critical Error: Connection issue {conn_err}")
                                raise ValueError(f"Critical Error: Connection issue {conn_err}")
                    # Market
                    if code[3:6]== '220':
                        try:
                            self.connection_handler(signal= 'set')
                            return self.api_bridges['alpaca_unified'].get_barset(general1,general2, limit=100) # asset, time_frame
                        except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:                         
                            self.exceptionManager.handle_exception("Connection", conn_err,log=True)
                            time.sleep(30)
                            if self.connection_handler(signal= 'check'):
                                # Ritenta l'operazione dopo aver ristabilito la connessione
                                return self.api_bridges['kraken_query'].get_barset(general1,general2, limit=100) # asset, time_frame
                            else:
                                logger2.Crirtical(f"Critical Error: Connection issue {conn_err}")
                                raise ValueError(f"Critical Error: Connection issue {conn_err}")
                    # Buy/Sell
                    if code[3:6]== '300':
                        try:
                            self.connection_handler(signal= 'set')
                            # asset, amount , 'buy/sell', market, time in force
                            return self.api_bridges['alpaca_unified'].submit_order(general1, 
                                                                                   general2, 
                                                                                   general3, 
                                                                                   'market', 
                                                                                   'day') 
                            #!!!!!!!!EFFETTUA UNO STUDIO SUL SIGNIFICATO DELLE VARIABILI MARKET E TIME IN FORCE!!!!!!!! 
                        except tuple(CCXT_CONNECTION_EXCEPTIONS) as conn_err:                          
                            self.exceptionManager.handle_exception("Connection", conn_err,log=True)
                            time.sleep(30)
                            if self.connection_handler(signal= 'check'):
                                # Ritenta l'operazione dopo aver ristabilito la connessione
                                # asset, amount , 'buy/sell', market, time in force
                                return self.api_bridges['kraken_query'].submit_order(general1, 
                                                                                     general2, 
                                                                                     general3, 
                                                                                     'market', 
                                                                                     'day')
                            else:
                                logger2.Crirtical(f"Critical Error: Connection issue {conn_err}")
                                raise ValueError(f"Critical Error: Connection issue {conn_err}")
            else:
                print('DEV: CODE ERROR')
                pass                   
        def initiate_shutdown(self):
            # Sets the flag to terminate core()
            self.parent.shutdown_flag = True                 
    class Merchant:#UT
        
        """
        ### Merchant class
        This class manages the trading operations of the program,
        such as the opening and closing of positions and keeping track
        of the variables that regulate the trading logic.

        Relationships:
            - TaskManager
            - ExceptionManager
        """
        def __init__(self, taskManager,
                     closures,initconfig, 
                     symbolSel1, symbolSel2, 
                     couple, configs, ex_manager):
            self.exceptionManager = ex_manager
            self.taskManager = taskManager
            self.closures = closures
            self.logic_configs = initconfig  
            self.symbolSel1 = symbolSel1
            self.symbolSel2 = symbolSel2  
            self.couple = couple
            self.configs = configs
        
        def buy(self, op_size, multiplier, call):
            """### Buy method""" 
            try:
                op_size = op_size * multiplier
                order = self.taskManager.alchemist(code='KRA300',
                                                   general1= self.couple,
                                                   general2='market',
                                                   general3= 'buy',
                                                   general4= op_size,
                                                   general5= self.configs['params_buy']
                                                   )
                # LOGIC CONTROLS REMOVED FOR PRIVACY
                
                if call == 'cross':
                    # Setting the price for trailing stop for long position
                    self.logic_configs['trailStopPriceLong'] = self.taskManager.alchemist(
                        code='KRA420',
                        general1 = self.closures['last_close'], 
                        general2 = configs['logic_triggers']['buy_stop_loss_tolerance'],
                        general3 = 'Long'
                        )
                    # Log message
                    logger1.info(f'Bought w/GoldenCross - Order ID: {order["id"]}')

                if call == 'Bollinger':
                    # Setting the price for trailing stop for long position
                    self.logic_configs['trailStopPriceLong'] = self.taskManager.alchemist(
                        code='KRA420',
                        general1 = self.closures['last_close'], 
                        general2 = configs['logic_triggers']['buy_stop_loss_tolerance'],
                        general3 = 'Long'
                        )
                    # Log message
                    logger1.info(f'Bought w/Bollinger_support_GoldenCross - Order ID: {order["id"]}')
                
                elif call == 'Trail':# Trailstop
                    # Setting the price for trailing stop for long position
                    self.logic_configs['prc_buy_stoploss']= self.taskManager.alchemist( 
                        code='KRA420',
                        general1 = self.closures['last_close'], 
                        general2 = configs['logic_triggers']['buy_stop_loss_tolerance'],
                        general3 = 'Long'
                        )
                    # Log message
                    logger1.info(f'Bought w/TrailingStop - Order ID: {order["id"]}')              
                # Saving the purchase price and the last position
                with open(cache+'/last_buy.pickle', 'wb') as a2, open(cache+'/access.pickle', 'wb') as a3:
                    pickle.dump(self.closures['last_close'], a2) 
                    pickle.dump(self.logic_configs['position_control'], a3)
                # Log message
                logger1.info(f'Order: Amount {self.symbolSel2}:{op_size}, Last Close:{self.closures["last_close"]}')
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True) 
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)           
        def sell(self, op_size, multiplier, call):
            """### Sell method"""
            try:
                op_size = op_size * multiplier
                order = self.taskManager.alchemist(code='KRA300',
                                                    general1= self.couple,
                                                    general2= 'market',
                                                    general3= 'sell',
                                                    general4= op_size,
                                                    general5= self.configs['params_sell']
                                                    )
                # LOGIC CONTROLS REMOVED FOR PRIVACY

                if call == 'cross':
                    # Gestione del prezzo per trailing stop per la posizione short
                    self.logic_configs['trailStopPriceShort'] = self.taskManager.alchemist(
                        code='KRA420',
                        general1 = self.closures['last_close'], 
                        general2 = configs['logic_triggers']['sell_stop_loss_tolerance'],
                        general3 = 'Short'
                        )
                    # Messaggio di log
                    logger1.info(f'Sold w/DeathCross - Order ID: {order["id"]}')

                if call == 'Bollinger':
                    # Messaggio di log
                    logger1.info(f'Sold w/Bollinger_support_DeathCross - Order ID: {order["id"]}')
                    
                elif call == 'Trail':
                    # Messaggio di log
                    logger1.info(f'Sold w/TrailingStop - Order ID: {order["id"]}')

                elif call == 'Stoploss on trail':
                    
                    # Gestione del prezzo per trailing stop per la posizione short ELIMINATO
                    # self.logic_configs['trailStopPriceShort'] = self.taskManager.alchemist(
                    #     code='KRA420',
                    #     general1 = self.closures['last_close'], 
                    #     general2 = configs['logic_triggers']['sell_stop_loss_tolerance'],
                    #     general3 = 'Short'
                    #     )
                    # Messaggio di log
                    logger1.info(f'Sold w/STOPLOSS! - Order ID: {order["id"]}')
                # Salvataggio del prezzo di acquisto e l'ultima posizione
                with open(cache+'/last_sell.pickle', 'wb') as a1, open(cache+'/access.pickle', 'wb') as a3:
                    pickle.dump(self.closures['last_close'], a1) 
                    pickle.dump(self.logic_configs['position_control'], a3)            
                # Messaggio di log    
                logger1.info(f'Order: Amount {self.symbolSel1}:{op_size}, Last Close:{self.closures["last_close"]}')
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True) 
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)

    def setup_trading_environment(self):
        """        
        ### Setup Trading Environment method
        Method that initializes the trading environment.
        It initializes the DataFrame and memory variables for the
        trading logic.
        """
        # Initialize the DataFrame
        def df_init():
            """
            ### DataFrame Initialization method
            """
            try:
                self.taskManager.connection_handler(signal= 'set')
                if self.taskManager.alchemist('KRA120'):
                    logger1.info("(Connection to the exchange established successfully)")
                    logger2.info('Ready for Alerts')
                    self.taskManager.connection_handler(signal= 'set')
                    balance = self.taskManager.alchemist(code = 'KRA210')
                    result = f"Account balance: (" + self.symbolSel1 + ":" + str(balance['free'][self.symbols[self.symbol_key]['symbol1']]), self.symbolSel2 + ":"+ str(balance['free'][self.symbols[self.symbol_key]['symbol2']]) +")"
                    logger1.info(result)
                else:
                    logger1.info("Exchange connection error")
                    self.taskManager.connection_handler(signal= 'set')

                self.taskManager.connection_handler(signal= 'set')
                # Retrieve the candles data from the kraken_trade using CCXT
                candles = self.taskManager.alchemist(code='KRA220',general1 = self.couple, general2= self.time_frame)
                candles2 = self.taskManager.alchemist(code='KRA220',general1 = self.couple,general2= self.time_frame2)
                # Creates a DataFrame with the candles data
                candle_columns = ['timestamp', 'open', 'high', 'low', 'close', 'volume']
                chart = pd.DataFrame(candles, columns=candle_columns)
                support_chart = pd.DataFrame(candles2, columns=candle_columns)
                self.update_market_data(chart,1)
                self.update_market_data(support_chart,2)
                return chart, support_chart

            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, critical=True) 
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
        def memory_handler():
            """
            ### Initialization of the instance variables
            The if control serves to check the integrity of the file
            If the file is empty or not intact, it initializes the variables
            with predefined values for buying and selling and at least gets
            the real market position
            """
            try:
                with (
                    open(cache + '/last_sell.pickle', 'rb') as a1, 
                    open(cache + '/last_buy.pickle', 'rb') as a2, 
                    open(cache + '/access.pickle', 'rb') as a3
                    ):
                    if os.path.getsize(cache + '/last_sell.pickle') > 0:
                        self.logic_configs['prc_sell']  = pickle.load(a1)
                    else:
                        self.logic_configs['prc_sell'] = 9999999
                    if os.path.getsize(cache + '/last_buy.pickle') > 0:
                        self.logic_configs['prc_buy'] = pickle.load(a2)
                    else:
                        self.logic_configs['prc_buy'] = 1
                    if os.path.getsize(cache + '/access.pickle') > 0:
                        self.logic_configs['position_control']  = pickle.load(a3)
                        if self.logic_configs['position_control'] == "None":
                            self.logic_configs['position_control'] = None
                    else:
                        self.logic_configs['position_control'] = None
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, critical=True) 
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)

        self.taskManager.connection_handler(signal= 'set')
        self.chart, self.support_chart = df_init()

        closures = {
            'last_close' : self.chart.iloc[-2]['close'],
            'last_close2' : self.support_chart.iloc[-2]['close'],
        }
        # Initialization of the class for transactions
        self.merchantsWill = self.Merchant(
            self.taskManager,
            closures,
            self.logic_configs,
            self.symbolSel1,
            self.symbolSel2,
            self.couple,
            self.configs,
            self.exceptionManager
            )
        memory_handler()
    def update_market_data(self, dataframe, timeframe_call):
        """
        ### Update Market Data method
        Method that updates the market data in the DataFrame
        and removes the oldest candles.
        Also calculates the indicators and the market trend.
        Which are used in the trading logic.

        :param dataframe: DataFrame
            The DataFrame containing the market data.
        :param timeframe_call: int
            The time frame of the candles.
        """
        # Parameters for the indicators
        SMAperiod1 = self.indicator_config['SMA_period_thin']
        SMAperiod2 = self.indicator_config['SMA_period_wide']
        SMAperiod3 = self.indicator_config['MACD_period_thin']
        SMAperiod4 = self.indicator_config['MACD_period_wide']
        length = self.indicator_config['df1']['length']
        mult = self.indicator_config['df1']['mult']
        length2 = self.indicator_config['df2']['length']
        mult2 = self.indicator_config['df2']['mult']
        ADXperiod = self.indicator_config['ADX_period']
        RSIperiod = self.indicator_config['RSI_period']

        # Add candle to the DataFrame and remove the oldest candles
        def add_candle(timeframe_call):
            nonlocal dataframe
            try:
                self.taskManager.connection_handler(signal= 'set')
                # Get the candles data from the kraken_trade using CCXT
                if timeframe_call == 1:
                    candles = self.taskManager.alchemist(code='KRA220',general1 = self.couple, general2= self.time_frame)
                else:
                    candles = self.taskManager.alchemist(code='KRA220',general1 = self.couple,general2= self.time_frame2)

                candles_df = pd.DataFrame(candles, columns=['timestamp', 'open', 'high', 'low', 'close', 'volume'])
                dataframe = pd.concat([dataframe, candles_df]).drop_duplicates(subset=['timestamp'], keep='last').reset_index(drop=True)
                if len(dataframe) > 26298: # 3 years in hours and resets the index
                    dataframe = dataframe.iloc[1:].reset_index(drop=True)
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
        # Technical indicators
        def SMA_cross():
            try:
                # Calcola le SMA 
                dataframe['SMA1'] = dataframe['close'].rolling(window=SMAperiod1).mean()
                dataframe['SMA2'] = dataframe['close'].rolling(window=SMAperiod2).mean()
                # Trova le intersezioni tra SMA1 e SMA2 e verifica l'andamento
                dataframe['cross'] = 'null'  # Inizializza con 'null' per nessun segnale
                for i in range(1, len(dataframe)):
                    if dataframe['SMA1'][i] > dataframe['SMA2'][i] and dataframe['SMA1'][i - 1] <= dataframe['SMA2'][i - 1]:
                        dataframe.at[i, 'cross'] = 'Death'
                    elif dataframe['SMA1'][i] < dataframe['SMA2'][i] and dataframe['SMA1'][i - 1] >= dataframe['SMA2'][i - 1]:
                        dataframe.at[i, 'cross'] = 'Golden'
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)  
        def BollingerBands(tf_call):
            try:
                # Calcola le bande di Bollinger
                close = np.array(dataframe['close'])
                basis = pd.Series(close).rolling(window=length).mean()
                dev = pd.Series(close).rolling(window=length).std()
                dev2 = mult * dev

                basis2 = pd.Series(close).rolling(window=length2).mean()
                dev1 = pd.Series(close).rolling(window=length2).std()
                dev3 = mult2 * dev1

                if tf_call == 1:
                    dataframe['up'] = basis + dev
                    dataframe['low'] = basis - dev
                    dataframe['upper'] = basis + dev2
                    dataframe['lower'] = basis - dev2
                elif tf_call == 2:
                    dataframe['up'] = basis2 + dev1
                    dataframe['low'] = basis2 - dev1
                    dataframe['upper'] = basis2 + dev3
                    dataframe['lower'] = basis2 - dev3
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True) 
        def ADX(tf_call):
            try:
                # Componenti
                def calculate_true_range(high, low, previous_close):
                    return max(high - low, abs(high - previous_close), abs(low - previous_close))
                def calculate_directional_movement(high, low, previous_high, previous_low):
                    plus_dm = max(high - previous_high, 0) if (high - previous_high) > (previous_low - low) else 0
                    minus_dm = max(previous_low - low, 0) if (previous_low - low) > (high - previous_high) else 0
                    return plus_dm, minus_dm
                def calculate_average_true_range(true_range_values, period):
                    return np.mean(true_range_values[-period:])
                def calculate_directional_indicators(plus_dm_values, minus_dm_values, atr_values, period):
                    plus_di = (np.mean(plus_dm_values[-period:]) / np.mean(atr_values[-period:])) * 100
                    minus_di = (np.mean(minus_dm_values[-period:]) / np.mean(atr_values[-period:])) * 100
                    return plus_di, minus_di
                def calculate_dx(plus_di, minus_di):
                    if plus_di + minus_di == 0:
                        return 0
                    else:
                        return (abs(plus_di - minus_di) / (plus_di + minus_di)) * 100
                def calculate_adx(dx_values, period):
                    return np.mean(dx_values[-period:])


                high = dataframe['high']
                low = dataframe['low']
                close = dataframe['close']
                true_range_values = [calculate_true_range(high[i], low[i], close[i - 1]) for i in range(1, len(dataframe))]
                plus_dm_values, minus_dm_values = zip(*[calculate_directional_movement(high[i], low[i], high[i - 1], low[i - 1]) for i in range(1, len(dataframe))])
                atr_values = [calculate_average_true_range(true_range_values[:i], ADXperiod) for i in range(1, len(dataframe))]
                plus_di_values = []
                minus_di_values = []
                for i in range(1, len(dataframe)):
                    plus_dm_window = plus_dm_values[:i]
                    minus_dm_window = minus_dm_values[:i]
                    atr_window = atr_values[:i]
                    plus_di, minus_di = calculate_directional_indicators(plus_dm_window, minus_dm_window, atr_window, ADXperiod)
                    plus_di_values.append(plus_di)
                    minus_di_values.append(minus_di)   
                dx_values = [calculate_dx(plus_di, minus_di) for plus_di, minus_di in zip(plus_di_values, minus_di_values)]
                adx_values = [calculate_adx(dx_values, ADXperiod)]
                
                for dx in dx_values:
                    adx = ((adx_values[-1] * (ADXperiod - 1)) + dx) / ADXperiod
                    adx_values.append(adx)
                if tf_call == 1:
                    dataframe['adx'] = adx_values
                elif tf_call == 2:
                    dataframe['adx'] = adx_values
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)   
        def RSI(tf_call):
            try:
                # Calcola la differenza tra i prezzi di chiusura tra i giorni consecutivi
                dataframe['price_diff'] = dataframe['close'].diff()

                # Calcola i guadagni e le perdite
                dataframe['gain'] = dataframe['price_diff'].where(dataframe['price_diff'] > 0, 0)
                dataframe['loss'] = -dataframe['price_diff'].where(dataframe['price_diff'] < 0, 0)

                # Calcola la media mobile esponenziale dei guadagni e delle perdite
                dataframe['avg_gain'] = dataframe['gain'].rolling(window=RSIperiod).mean()
                dataframe['avg_loss'] = dataframe['loss'].rolling(window=RSIperiod).mean()

                # Calcola il rapporto RSI
                dataframe['rs'] = dataframe['avg_gain'] / dataframe['avg_loss']

                # Calcola l'RSI
                if tf_call == 1:
                    dataframe['rsi'] = 100 - (100 / (1 + dataframe['rs']))
                elif tf_call == 2:
                    dataframe['rsi'] = 100 - (100 / (1 + dataframe['rs']))
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)   
        def MACD():
            try:
                 # Calcolo di SMA veloce e lento
                ema_fast = dataframe['close'].ewm(span=SMAperiod3, adjust=False).mean()
                ema_slow = dataframe['close'].ewm(span=SMAperiod4, adjust=False).mean()

                # Calcolo della linea MACD e della linea del segnale
                dataframe['macd_value'] = ema_fast - ema_slow
                dataframe['signal_line'] = dataframe['macd_value'].ewm(span=9, adjust=False).mean()

                # Calcolo dell'istogramma MACD
                dataframe['macd_histogram'] = dataframe['macd_value'] - dataframe['signal_line']
                
                # Identificazione del trend del mercato in base all'istogramma MACD
                dataframe['market_trend'] = np.where(
                    dataframe['macd_histogram'] > dataframe['macd_histogram'].shift(1),
                    'BULL' ,
                    'BEAR'
                )
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)       
        # Support functions
        def minmax ():
            try:
                current_close = dataframe.iloc[-2]['close']
                sell_tStopLossPercent = self.configs['logic_triggers']['sell_trailstop_tolerance']
                buy_tStopLossPercent = self.configs['logic_triggers']['buy_trailstop_tolerance']
                # Aggiornamento del prezzo per il Trailing Stop in posizione Long
                if self.logic_configs['position_control']:  # Assumendo che 'position_control' indichi una posizione aperta         
                    if 'maxPriceLong' not in self.logic_configs or current_close > self.logic_configs['maxPriceLong']:
                        self.logic_configs['maxPriceLong'] = current_close     
                        self.logic_configs['trailStopPriceLong'] = current_close * (1 - sell_tStopLossPercent / 100)
                # Aggiornamento del prezzo per il Trailing Stop in posizione Short
                if not self.logic_configs['position_control']:  # Assumendo che 'position_control' False indichi nessuna posizione aperta
                    if 'minPriceShort' not in self.logic_configs or current_close < self.logic_configs['minPriceShort']:
                        self.logic_configs['minPriceShort'] = current_close
                        self.logic_configs['trailStopPriceShort'] = current_close * (1 + buy_tStopLossPercent / 100)
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
        def hunger_signal(macd_value):
            try:
                # Modifica del tipo di ordine tramite il dizionario configs['params'] in base al MACD trend 
                # Utilizzato da taskManager.alchemist(KRA300,p1,p2,p3,p4).createOrder()
                if macd_value >= 999:
                    self.configs['params_sell'] = {'leverage': self.symbols[self.symbol_key]['leverage']} # Ordine margin 
                    self.configs['params_buy'] = {'leverage': self.symbols[self.symbol_key]['leverage']} 
                    if self.logic_configs['trend_flow'] == 'Bullish':
                        self.configs['params_sell']['reduce_only'] = True
                        self.configs['params_buy']['reduce_only'] = False
                    if self.logic_configs['trend_flow'] == 'Bearish':
                        self.configs['params_sell']['reduce_only'] = False
                        self.configs['params_buy']['reduce_only'] = True
                elif macd_value < 999:
                    self.configs['params_sell'].clear() # Ordine spot
                    self.configs['params_buy'].clear()
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
        # Call the nested functions
        add_candle(timeframe_call)
        SMA_cross()
        BollingerBands(timeframe_call)
        ADX(timeframe_call)
        RSI(timeframe_call)
        MACD()
        if self.configs['auto_leverage_selector']:
            hunger_signal(dataframe.iloc[-2]['macd_value'])
        minmax()
        """
        Logica che inverte le aperture delle posizioni ESAMINA
        Aperture short e conseguenti chiusure durante i periodi bearish
        Aperture long e conseguenti chiusure durante i  periodi bullish
        """
        # if self.chart.iloc[-2]['market_trend'] == 'BULL':  
        #     self.logic_configs['trend_flow'] = 'Bullish'
        # elif self.chart.iloc[-2]['market_trend'] == 'BEAR':
        #     self.logic_configs['trend_flow'] = 'Bearish'
        # Update the DataFrame based on the timeframe for the trading logic
        if timeframe_call == 1:
            self.chart = dataframe
        else:
            self.support_chart = dataframe          
    def dataframe_handler(self):
        """
        ### DataFrame Handler method
        Method that manages the DataFrame in a format useful for Dipso.py
        """
        try:
            self.chart.to_csv(self.csv_data_path + "/chart_data.csv")
        except tuple(GLOBAL_EXCEPTIONS) as exception_id:
            self.exceptionManager.handle_exception("General", exception_id, log=True)
        except tuple(FATAL_EXCEPTIONS) as FatalError:
            self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
    def execute_trading_logic(self, merchantsWill):#UT
        """
        ### Execute Trading Logic method
        Method that executes the trading logic based on the values
        of the variables that regulate the trading logic.

        :param merchantsWill: Merchant
            The instance of the Merchant class that handles the trading operations.
        """
        
        (min_order_size,
         symbolSel2) = (self.symbols[self.symbol_key]['min_order_size'],
                        self.symbols[self.symbol_key]['symbol2'])
        
        sell_stop_loss_tolerance = self.configs['logic_triggers']['sell_stop_loss_tolerance']
        buy_stop_loss_tolerance = self.configs['logic_triggers']['buy_stop_loss_tolerance']

        crossgolden_adx = self.configs['indicators_triggers']['crossgolden_adx']
        crossgolden_rsi = self.configs['indicators_triggers']['crossgolden_rsi']
        crossdeath_rsi = self.configs['indicators_triggers']['crossdeath_rsi']
        crossdeath_adx = self.configs['indicators_triggers']['crossdeath_adx']
        upperbb_adx = self.configs['indicators_triggers']['upperbb_adx']
        upperbb_rsi = self.configs['indicators_triggers']['upperbb_rsi']
        upperbb_rsi_limit = self.configs['indicators_triggers']['upperbb_rsi_limit']
        lowerbb_rsi = self.configs['indicators_triggers']['lowerbb_rsi']
        lowerbb_adx = self.configs['indicators_triggers']['lowerbb_adx']

        # Profit Enhancer function
        def profit_enhancer():pass
        # Main trade activity
        def main_trade_activity(merchantsWill):
            try:
                # Operation Suitability
                """ 
                Gross Profit sell and buy are the variables used for the profitability 
                signals of the operation, they are calculated by the Alchemist module

                uses .iloc[-1] for the current value for accuracy instead 
                of .iloc[-2] that is used for a more precise control of the signals 
                since .iloc[-1] is fluctuating
                """
                (gross_profit_sell, 
                gross_profit_buy) = self.taskManager.alchemist(code='KRA410',
                                                    general1 = self.chart.iloc[-1]['close'], 
                                                    general2 = self.logic_configs['prc_buy'],
                                                    general3 = self.logic_configs['prc_sell'])
                # Operation sizes
                balance = self.taskManager.alchemist(code='KRA210')
                conv_balance = balance['free'][symbolSel2] / self.chart.iloc[-1]['close']
                (stablecoin_total_size_buy,
                crypto_total_size_sell) = self.taskManager.alchemist(code='KRA400', 
                                                                    general1=conv_balance) 
                #TRADING LOGICS 
                # Buy 
                if stablecoin_total_size_buy is not None and stablecoin_total_size_buy > min_order_size:
                    if self.logic_configs['position_control'] is None or not self.logic_configs['position_control']:
                        # SMACross bullish/bearish for the inversion of the buy/sell actions
                        if self.chart.iloc[-2]['cross'] == 'Golden' and self.logic_configs['trend_flow'] == 'Bullish':
                            merchantsWill.buy(stablecoin_total_size_buy, 1, 'Cross')
                        # BollingerBandLower 
                        if self.chart.iloc[-2]['lower'] > self.chart.iloc[-2]['close']: 
                            # Tentatives need to be more than 4 to be activated
                            if self.logic_configs['LB_tentatives'] == self.configs['logic_triggers']['LB_value']:
                                # Alteration with short positions excluded from Bollinger Band 
                                if(self.logic_configs['bollinger_buy_control'] is None or self.logic_configs['bollinger_buy_control'] == True):
                                    merchantsWill.buy(stablecoin_total_size_buy, 1, 'Bollinger') #9% of total
                        # Increment tentatives that need to be more than 4 to be activated
                        elif self.chart.iloc[-2]['lower'] > self.chart.iloc[-2]['close']: 
                            if self.logic_configs['LB_tentatives']  == self.configs['logic_triggers']['LB_value']:
                                self.logic_configs['LB_tentatives'] += 1
                    # Trailstop
                    if self.logic_configs['trailStopPriceShort'] is not None:
                        if self.logic_configs['trailStopPriceShort'] <= self.chart.iloc[-2]['close'] and not self.logic_configs['position_control']:
                            merchantsWill.buy(stablecoin_total_size_buy,1,'Trail') 
                # Confirm signals 
                else:
                    if (self.logic_configs['position_control'] is None or not self.logic_configs['position_control']):
                        # SMACross bullish/bearish for the inversion of the buy/sell actions
                        if self.chart.iloc[-2]['cross'] == 'Golden' and self.logic_configs['trend_flow'] == 'Bullish':
                            logger1.info('No balance for Cross Golden') 
                        # BollingerBandLower 
                        if self.chart.iloc[-2]['lower'] > self.chart.iloc[-2]['close']: 
                            if self.logic_configs['LB_tentatives']  == self.configs['logic_triggers']['LB_value']:
                                # Alteration with short positions excluded from Bollinger Band 
                                if(self.logic_configs['bollinger_buy_control'] is None or self.logic_configs['bollinger_buy_control'] == True):
                                    logger1.info('No balance for Bollinger Buy')
                # Sell
                if crypto_total_size_sell is not None and crypto_total_size_sell > 1 and gross_profit_sell > 0: 
                    if (self.logic_configs['position_control'] is None or self.logic_configs['position_control']):
                        # SMACross bullish/bearish for the inversion of the buy/sell actions
                        if self.chart.iloc[-2]['cross'] == 'Death' and gross_profit_sell > 1 and self.logic_configs['trend_flow'] == 'Bullish':                       
                            merchantsWill.sell(crypto_total_size_sell,1,'Cross') 
                        # Short openings Logic
                        if self.chart.iloc[-2]['cross'] == 'Death' and self.logic_configs['trend_flow'] == 'Bearish':
                            merchantsWill.sell(stablecoin_total_size_buy, 1, 'Cross')
                        # BollingerBandUpper 
                        if self.chart.iloc[-2]['upper'] < self.chart.iloc[-2]['close'] and gross_profit_sell > 1 :
                            # Alternanza esclusiva con Trailstop
                            if self.logic_configs['bollinger_sell_control'] == True: 
                                merchantsWill.sell(crypto_total_size_sell,1,'Bollinger') 
                    # Trailstop 
                    if self.logic_configs['trailStopPriceLong'] is not None:
                        if self.logic_configs['trailStopPriceLong'] >= self.chart.iloc[-2]['close'] and self.logic_configs['position_control']:
                            merchantsWill.sell(crypto_total_size_sell,1,'Trail')     
                    # Stoploss on buyTrailstop 
                    if self.logic_configs['stoploss_control'] and self.chart.iloc[-2]['close'] <= self.logic_configs['prc_buy_stoploss']:
                        merchantsWill.sell(crypto_total_size_sell,1,'Stoploss on trail')   
                # Confirm signals  
                else:
                    if (self.logic_configs['position_control'] is None or self.logic_configs['position_control']):
                        # SMACross bullish/bearish for the inversion of the buy/sell actions
                        if self.chart.iloc[-2]['cross'] == 'Death' and gross_profit_sell > 0 and self.logic_configs['trend_flow'] == 'Bullish':                       
                            logger1.info('No balance for Cross Death')
                        # Short openings Logic
                        if self.chart.iloc[-2]['cross'] == 'Death' and self.logic_configs['trend_flow'] == 'Bearish':
                            logger1.info('No balance for Cross Death')
                        # BollingerBandUpper 
                        if self.chart.iloc[-2]['upper'] < self.chart.iloc[-2]['close'] and gross_profit_sell > 0 :
                            logger1.info('No balance for Bollinger Sell')
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, log=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)
            
        ## Activity calls ##
        main_trade_activity(merchantsWill)   
        # profit_enhancer()    
    def core(self):
        """
        ### Core method
        Method that runs the core of the JARVIIS trading logic.
        It updates the market data, executes the trading logic, and saves the data.
        """
        while not self.shutdown_flag:
            try:
                self.update_market_data(self.chart,1)
                self.update_market_data(self.support_chart,2)
                self.execute_trading_logic(self.merchantsWill)
                if not self.setupManager.save_pickle(self.logic_configs['prc_buy'], self.logic_configs['prc_sell'], self.logic_configs['position_control']):
                    logger2.error("Error: Failed to save pickle data.")
                time.sleep(10) # Update interval
            except tuple(GLOBAL_EXCEPTIONS) as exception_id:
                self.exceptionManager.handle_exception("General", exception_id, critical=True)
            except tuple(FATAL_EXCEPTIONS) as FatalError:
                self.exceptionManager.handle_exception("Fatal", FatalError,terminate=True)

def main(symbols_configs, api_config, indicator_config):# Main
    """
    ### Main Function
    The main function of the application that manages the user interface
    and initializes the main classes of JARVIIS app.
    """
    try:
        """
        The following global variables are instantiated like this
        for convienence since they are used in multiple classes
        """
        global logger1,logger2,cache
    
        SetupManager.static_handle_screen()
        # WordCompleter prepared options
        opzioni_completer = WordCompleter(symbols_configs, ignore_case=True)

        print("JARVIIS: -Welcome! :D")
        time.sleep(3.3)
        if pynput is not None:
            print(
    """
    ONGOING COMMANDS
    ----------------
     
    [Esc] Exit
    [ D ] Update dataframe log
    [ K ] Set Apikeys (Input in pin section)
    [ R ] Resource usage

    [Ctrl + C] Force Shutdown
    """
            )
        else:
            print(
    """
    ONGOING COMMANDS
    ----------------

    [Ctrl + C] Exit
    """
            )
        
        while True:
            time.sleep(6.9)
            SetupManager.static_handle_screen()
            print('JARVIIS: -Asset selection\n')
            time.sleep(0.9)
            print ("    CRYPTOS")
            time.sleep(0.3)
            print("    -------")
            time.sleep(0.3)
            i = 0
            for i in symbols_configs:
                print ("    [",i,"] " + symbols_configs[i]['symbol1'])
                time.sleep(0.3)
            time.sleep(0.3)
            print ("\n    [ C ] Reset cache")
            time.sleep(0.3)
            print ("    [ Q ] Quit")
            time.sleep(0.9)
            # Prompt for the selection of the couple
            symbol_key = prompt("\nJARVIIS: -Select: ", completer=opzioni_completer)
            # Logic to handle the selection
            if symbol_key in symbols_configs:
                SetupManager.static_handle_screen()
                print(f"JARVIIS: -You selected: {symbols_configs[symbol_key]['couple']}")
                time.sleep(0.9)
                # Instance creation of SetupManager
                setupManager = SetupManager(symbols_configs, 
                                            symbol_key, 
                                            api_config, 
                                            indicator_config, 
                                            configs, 
                                            logic_configs,
                                            ExceptionManager
                                            )
                a = 'y'
                a = input("\nJARVIIS: -Would you like to change strategy variabiles? [Y/N] >> ")
                if a in ('y', 'Y'):
                    setupManager.change_variables()
                elif a not in ('n', 'N'):
                    time.sleep(0.9)
                    print("\nJARVIIS: -Wrong input, try again...")
                    a = 'y'
                while a in ('y', 'Y'):      
                    SetupManager.static_handle_screen()  
                    a = input(
                "JARVIIS: -Would you like to try to change strategy variabiles again? [Y/N] >> "
                    )
                    if a in ('y', 'Y'):
                        setupManager.change_variables()
                    elif a not in ('n', 'N'):
                        time.sleep(0.9)
                        print("\nJARVIIS: -Wrong input.. again, bruh c'mon!")
                        a = 'y'
                time.sleep(0.9)
                SetupManager.static_handle_screen()
                time.sleep(0.9)
                api_config = setupManager.load_api_keys(
                    getpass.getpass("\nJARVIIS: -Enter decryption PIN ")
                    )
                # Access to the configured directories
                data_dir = setupManager.directories['data_dir']
                cache = setupManager.directories['cache']
                # Access to the configured loggers
                logger1 = setupManager.loggers['logger1']
                logger2 = setupManager.loggers['logger2']
                # Class for exception handling
                exceptionManager = ExceptionManager(logger2)
                # Core class of JARVIIS
                jarviisReactor = JarviisReactor(symbols_configs,
                                                symbol_key, 
                                                api_config, 
                                                indicator_config, 
                                                configs, 
                                                logic_configs, 
                                                data_dir,
                                                setupManager,
                                                exceptionManager
                                                )
                # Start and listen thread closure class
                ThreadManager(jarviisReactor, 
                              symbols_configs, 
                              symbol_key,
                              exceptionManager
                              ) 
                break 
            if symbol_key in ('q', 'Q'):  
                SetupManager.static_handle_screen()   
                print("JARVIIS: -Exiting program... ")
                time.sleep(3)
                print("JARVIIS: -Goodbye! :)")
                time.sleep(3)
                SetupManager.static_handle_screen()   
                sys.exit(0)
            elif symbol_key in ('c', 'C'): 
                SetupManager.static_handle_screen()  
                SetupManager.cache_cleaner()
                continue    
            else:
                SetupManager.static_handle_screen()
                print("JARVIIS: -Invalid selection.")
                time.sleep(6)
    except Exception as e:
        logger2.critical(f"Fatal Error: main(), {str(e)}")
        sys.exit(1)  

# Script entry point
if __name__ == "__main__":
    ## Static variables ##
    api_config = {
        'kraken_tradekey': '',
        'kraken_tradeprivate': '',
        'kraken_querykey': '',
        'kraken_queryprivate': '',
        'base_url': "https://paper-api.alpaca.markets",
        'alpaca_unifiedkey': "",
        'alpaca_unifiedprivate': "",
    }
    symbols_configs = {
        '1': {'couple': "BTC/USDT", 
              'symbol1': "BTC", 
              'symbol2':'USDT', 
              'min_order_size': 0.0001, 
              'leverage': 3}, 
        '2': {'couple': "ETH/USDT", 
              'symbol1': "ETH", 
              'symbol2':'USDT', 
              'min_order_size': 0.01, 
              'leverage': 3},
        '3': {'couple': "SOL/USDT", 
              'symbol1': "SOL", 
              'symbol2':'USDT', 
              'min_order_size': 0.25, 
              'leverage': 3},
        '4': {'couple': "AVAX/USDT", 
              'symbol1': "AVAX", 
              'symbol2':'USDT', 
              'min_order_size': 0.3, 
              'leverage': 3},
        '5': {'couple': "ADA/USDT", 
              'symbol1': "ADA", 
              'symbol2':'USDT', 
              'min_order_size': 15, 
              'leverage': 3}
    }
    logic_configs = {
        'couple': '',
        'symbol1' : '',
        'symbol': '',
        'min_order_size': None,
        # Altenate between short and long positions
        'position_control' : None, 
        # Altrante with short positions except those resulting from Bollinger Band
        'bollinger_buy_control' : None, 
        # Exclusive alternation with Trailstop
        'bollinger_sell_control' : None, 
        'prc_buy' : None, 
        'prc_buy_stoploss' : None, 
        'prc_sell' : None, 
        # Exclusive control for stoploss on trailstop
        'stoploss_control' : None, 
        'trailStopPriceLong' : None,
        'trailStopPriceShort' : None,
        'maxPriceLong' : None,
        'minPriceShort' : None,
        # Variable that regulates whether to play on short(Bearish) or long(Bullish)
        'trend_flow': 'Bullish',
        'LB_tentatives' : None,
    }
    ##BACKTESTING VARIABLES##
    indicator_config = {
        # The granularity of the time_frame
        # must be one of ‘1m’, ‘5m’, ‘15m’, ‘30m’, ‘1h’, ‘4h’,‘1d’, ‘1w’, or ‘2w’.
        # DF stats
        "df1" : {
            'time_frame': '1d',
            # BandaBollinger stats
            'length': 0,
            'mult': 0.0,
        },
        "df2": {
            'time_frame': '1d',
            # BandaBollinger stats
            'length': 0,
            'mult': 0.0,

        },
        # SMA stats
        'SMA_period_thin': 0,
        'SMA_period_wide': 0,
        'MACD_period_thin': 0,
        'MACD_period_wide': 0,
        # ADX stats
        'ADX_period': 0, 
        # RSI stats
        'RSI_period': 0
        # Other configurations fpllows here...
    }
    configs = {
        # Kraken max exchange fee 
        'fee' : None, 
        # Personal risk percentage
        'personal_risk_prct' : None,
        #'inidcators_triggers'
        'indicators_triggers' : {
            'crossgolden_adx' : None,
            'crossgolden_rsi' : None,
            'crossdeath_rsi' : None,
            'crossdeath_adx' : None,
            'upperbb_adx' : None,
            'upperbb_rsi' : None,
            'upperbb_rsi_limit': None,
            'lowerbb_rsi' : None,
            'lowerbb_adx' : None,
            'macd_death_limit': None,
        },
        'logic_triggers' :{
            # Max value of tentatives for BollingerBandLower to buy
            'LB_value' : None,
            # % Stoploss tolerance
            'sell_stop_loss_tolerance' : None , # % Tolleranza stoploss 
            'buy_stop_loss_tolerance' : None, 
            # Trailstop tolerance
            'buy_trailstop_tolerance' : None, # out of position
            'sell_trailstop_tolerance' : None, # in position
            },
        'params_buy' : {}, # {'leverage': 3, 'reduce_only': False}
        'params_sell' : {}, # {'leverage': 3, 'reduce_only': True}
        'auto_leverage_selector': True, # False = Manual, True = Auto

    }
    
    main(symbols_configs, api_config, indicator_config)

