"""
Dipso.py(Dataframe Image & Price Simulation Overview) 
"""


import pandas as pd
import os
import logging
from progress.spinner import Spinner
import time
import sys

if 'TMUX' in os.environ:
    # Cleans the screen in tmux
    print("\033[H\033[2J", end="")  
else:
    # Standard terminal clean
    print("\033[H\033[J", end="") 

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
data_dir = os.path.join(parent_dir,"data")
result_dir = os.path.join(data_dir,"results")
csv_dir = os.path.join(data_dir,"csv")
log_dir = os.path.join(parent_dir,"logs/cryptos")

logger = logging.getLogger('logger')
logger.setLevel(logging.INFO)
fh = logging.FileHandler(os.path.join(log_dir,'dataframe.log'))
fh.setFormatter(logging.Formatter('%(asctime)s - "JARVIIS" - %(message)s'))
logger.addHandler(fh)





indicators_triggers = {
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
    }

def display_dataframe(data):
    spinner1 = Spinner('DIPSO: -I am retrieving data... ')
    spinner2 = Spinner('DIPSO: -I am displaying the data.. ')
    # Cleans the log
    with open(os.path.join(log_dir,'Dataframe.log'), 'w') as f: pass 
    # Add a DateTime column
    def convert_timestamp_to_datetime(df, timestamp_col_name, datetime_col_name):
        df[datetime_col_name] = pd.to_datetime(df[timestamp_col_name], unit='ms', utc=True)
        data['datetime_cet'] = data['datetime'].dt.tz_convert('Europe/Rome')

    convert_timestamp_to_datetime(data, 'timestamp', 'datetime')
    # Set the display option for pandas so that it shows all columns
    pd.set_option('display.max_columns', None)
    # Select only the two columns of interest
    selected_columns = data[['datetime_cet', 'cross', 'upper','up', 'adx', 'close', 'low', 'lower','rsi','macd_value']].copy()
    # List to accumulate messages
    log_messages = []
    position = None
    positionType = ''
    # Max price reached in long position
    max_price_long = float('-inf')  
    # Min price reached in short position
    min_price_short = float('inf')  
    trail_stop_price_long = None
    trail_stop_price_short = None
    stoploss = None
    entryPercentage = None
    buy_price = None
    sell_price = None
    # trailing stop tolerance percentage to sell
    sell_tStopLossPercent = None  
    # trailing stop tolerance percentage to buy
    buy_tStopLossPercent = None  

    
    # Iterate through the rows of the selected columns and accumulate the messages
    for index, row in selected_columns.iterrows():
        spinner1.next()
        log_message = (
                f"- datetime: {row['datetime_cet'], row['close']}"
            )
        # BUY
        if row['cross'] == 'Golden':
            log_message = log_message + f" - close: {row['close']} - BUYs - Cross: {row['cross']}"
            buy_price = row['close']

        if row['lower'] > row['close']:
            log_message = log_message + f" - close : {row['close']} - BUYs - Lower: {row['lower']} "
            buy_price = row['close']    

        # SELL
        if row['cross'] == 'Death' :
            log_message = log_message + f" - close: {row['close']} - SELLs - Cross: {row['cross']}"
        if row['upper'] < row['close'] :
            log_message = log_message + f" - close : {row['close']} - SELLs - Upper: {row['upper']} "





        log_messages.append(log_message)
        time.sleep(0.1)

    spinner1.finish()
    print("\033[H\033[J", end="")

    # Print the messages outside the loop
    for message in log_messages:
        spinner2.next()
        logger.info(message)
        time.sleep(0.1)

    spinner2.finish()
    print("\033[H\033[J", end="")



if __name__ == "__main__":
    # For testing, we read a dataframe from a CSV file
    df = pd.read_csv(os.path.join(csv_dir,"chart_data.csv"))
    display_dataframe(df)
    print('DIPSO: -Dataframe image and portfolio simulation overview complete. :D')
    time.sleep(1.5)
    print('DIPSO: -Check your files at: \n\n /logs/cryptos/dataframe.log')
    time.sleep(9)
    print("\033[H\033[J", end="")
    sys.exit()

