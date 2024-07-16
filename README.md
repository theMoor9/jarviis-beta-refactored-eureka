                                 ___   ___   _____  __   __  ____  ____   ____
                                |_ _| / _ \ |  _  \|  | |  ||_  _||_  _| /  *_\
                                 | | | |_| || |_| | \ \ / /  |  |  |  |  \   \
                                _| | |  _  ||  _  /  \   /   |  |  |  |  _\   \
                               |___| |_| |_||_| \_\   \_/   |____||____|\_____/ Δ

                                <Just a rather visionary ideal investing system>

# Tools:
- **Jarviis**:
  - ADX
  - RSI
  - Bollinger Bands
  - SMA
  - MACD

- **Dipso**:
  - Funzione di supporto ai fini del controllo delle logiche di trading

- **Garu**:
  - Funzione di supporto ai fini tecnici di programmazione

# Functions:
La meccanica di lucro usa l'interesse composto tramite il seguente funzionamento:
- `JarviisReactor.update_market_data.SMA_cross()`
- `JarviisReactor.update_market_data.BollingerBands()`

Utilizza l'incrocio delle SMA per definire la struttura principale di trading, supportata dalle bande di Bollinger in maniera restrittiva, mirata ad ottemprare alle lacune di schematicità degli incroci in contrapposizione alla fluidità di mercato.

- `logic_config['params_buy/sell']`

Inoltre, dopo la prima attivazione trascorso un periodo di circa 3 mesi di consolidazione capitale, si attiva la meccanica di Leverage con moltiplicatore relativo alle disponibilità di Kraken (BTC/USDT x3).

- `JarviisReactor.update_market_data.MACD()`

Essa è regolamentata tramite il supporto del MACD che indica i periodi di rialzo e di ribasso, permettendo l'attivazione del Leverage in maniera esclusiva nei momenti di rialzo per cogliere con più determinazione il flusso di mercato.

- `configs['trend_flow']`

E' presente in aggiunta una logica (inattiva) che inverte le aperture delle posizioni:
- Aperture short e conseguenti chiusure durante i periodi bearish
- Aperture long e conseguenti chiusure durante i periodi bullish

# Concurrency/Parallelism:
Se si vuole applicare l'assistente su altri symbols occorre creare un account dedito al singolo asset.

# Security:
E' presente la crittazione delle variabili apikey e di sessione con salt.

# Architecture:
Microservices API system

# Progetti futuri:
- Ampliazione strategia - Performance profitability system
- Refactoring SOLID
- Refactoring RUST

# STRUTTURA DESCRITTIVA:

## LIBRERIE:
- numpy
- ccxt
- time
- threading
- os
- logging
- pickle
- progress.spinner
- traceback
- keyboard
- sys
- subprocess
- shutil
- pandas
- prompt_toolkit
- cryptography.hazmat.backends
- cryptography.hazmat.primitives
- cryptography.hazmat.primitives.kdf.pbkdf2
- base64
- cryptography.fernet
- getpass
- json
- zipfile
- datetime

---

```python
class SetupManager:
    def __init__(self, symbols, symbol_key, api_config):
        # Chiama self.setup_directories()
        # Chiama self.setup_loggers()
        # Chiama self.setup_pickle_files()
        # Chiama self.api_config_setup()

    def clear_screen_self_method(self):
    def setup_directories(self):
    def setup_loggers(self):
    def setup_pickle_files(self):
    def api_config_setup(self):
        # Chiama self.clear_screen_self_method()
    def derive_key(self, pin, salt=None):
    def encrypt_api_keys(self, pin):
        # Chiama self.derive_key()
    def decrypt_api_keys(self, pin, limit_attempts=0):
        # Chiama self.clear_screen_self_method()
        # Chiama self.derive_key()
        # Chiama self.api_config_setup()
    def log_cleaner(self):
    @staticmethod
    def cache_cleaner():

class ThreadManager:
    def __init__(self, main_class, su_class, symbols, symbol_key):
        # Crea il thread con self.throttler()
        # Crea il thread con self.listen_for_commands()
        # Crea il thread con jarviisReactor.core()
    def reset_screen_self_method(self):
    def clear_screen_self_method(self):
    def throttler(self):
        # Chiama self.clear_screen_self_method()
        # Chiama self.spark()
    def spark(self):
        Chiama self.reset_screen_self_method()
    def listen_for_commands(self):
        Chiama self.clear_screen_self_method()
        # Chiama self.reset_screen_self_method()
        # Chiama self.hitman()
        # Chiama jarviisReactor.dataframe_handler()
    def hitman(self):
    @staticmethod
    def reset_screen():

class JarviisReactor:
    # Classe che si occupa delle esecuzioni delle task atte allo svolgimento delle operazioni generali
    class TaskManager:
        def __init__(self, parent, api_config, symbols, symbol_key, logic_config):
        def connection_handler(self):
        # Funzione esecuzione capillare delle operazioni
        def alchemist(self, code, general1='', general2='', general3='', general4='', general5=''):
            # Chiama self.connection_handler()
        def initiate_shutdown(self):

    # Classe che si occupa della logica delle transazioni
    class Transactions:
        def __init__(self, taskManager, closures, initconfig, symbolSel1, symbolSel2, couple, MACDtrend):
        def buy(self, op_size, multiplier, call):
            # Chiama self.taskManager.alchemist(code='KRA300')
            # Chiama self.taskManager.alchemist(code='KRA420')
        def sell(self, op_size, multiplier, call):
            # Chiama self.taskManager.alchemist(code='KRA300')
            # Chiama self.taskManager.alchemist(code='KRA420')

    def __init__(self, symbols, symbol_key, api_config, indicator_config, logic_config, configs, data_dir):
        # Chiama self.update_market_data(self.chart, 1)
        # Chiama self.update_market_data(self.support_chart, 2)
        # Chiama self.setup_trading_environment()
        # Inizializza la classe self.TaskManager
        # Inizializza la classe self.Transactions

    def setup_trading_environment(self):
        # Definisce e chiama df_init(): # Inizializza il DF
            # Chiama self.connection_handler()
            # Chiama self.alchemist('KRA120')
            # Chiama self.alchemist('KRA210')
            # Chiama self.alchemist('KRA220')
        # Definisce e chiama memory_handler(): # Inizializza le variabili salvate in memoria
        # Chiama self.connection_handler()

    # Aggiorna i dati di mercato e riceve il dataframe e la tipologia di timeframe
    def update_market_data(self, dataframe, timeframe_call):
        # Definisce e chiama SMA_cross()
        # Definisce e chiama BollingerBands(tf_call)
        # Definisce e chiama ADX(tf_call)
        # Definisce e chiama RSI(tf_call)
        # Definisce e chiama MACD()
        # Definisce e chiama minmax()

    # Crea un file CSV con i dati del dataframe
    def dataframe_handler(self):
    
    # Contiene la logica di trading principale e riceve oggetto classe Transactions
    def execute_trading_logic(self, transactionElements):
        # Definisce e chiama main_trade_activity(transactionElements)
            # Chiama self.taskManager.alchemist(code='KRA410')
            # Chiama self.taskManager.alchemist(code='KRA400')
            # Chiama self.taskManager.alchemist(code='KRA210')
            # Chiama transactionElements.buy()
            # Chiama transactionElements.sell()

    # Ciclo principale del programma
    def core(self):
        # Chiama self.taskManager.connection_handler()
        # Chiama self.taskManager.alchemist('KRA220')
        # Chiama self.update_market_data(self.chart, 1)
        # Chiama self.update_market_data(self.support_chart, 2)
        # Chiama self.execute_trading_logic(self.transactionElements)

# Main
def main(symbols_config, api_config):
    # Chiama setupManager.cache_cleaner()
    # Chiama threadManager.reset_screen()

# Chiamata alla funzione principale
if __name__ == "__main__":
    main(symbols_config, api_config)

```

# Author
Kenneth Boldrini

# License
This repository is licensed. See the [LICENSE](./LICENSE) file for more details.
