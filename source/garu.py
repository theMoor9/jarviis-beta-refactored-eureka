"""Get_App_Resource_Usage"""

import sys
import logging
import time
import os
import psutil
import pandas as pd
from progress.spinner import Spinner
import warnings

if 'TMUX' in os.environ:
    # Cleans the screen in tmux
    print("\033[H\033[2J", end="")  
else:
    # Standard terminal clean
    print("\033[H\033[J", end="")
print("GARU: -Hello! :D")
time.sleep(6)
if 'TMUX' in os.environ:
    # Cleans the screen in tmux
    print("\033[H\033[2J", end="")  
else:
    # Standard terminal clean
    print("\033[H\033[J", end="")

# Claculation of resources per minute

# Monitoring function                                                                             
def get_application_resource_usage():
    # Create an empty DataFrame
    df = pd.DataFrame(columns=['cpu_percent', 'memory_percent', 'memory_active'])
    spinner = Spinner('GARU: -I am calculating the resources... ')
    # Define a function to get the resources information
    def get_resources_info():
        

        # Create an empty list for Python processes
        python_procs = []
        # Iterate over all running processes
        for proc in psutil.process_iter(['name']):
            # If the process name is "python", add the process to the list
            if proc.info['name'] == 'python.exe':
                python_procs.append(proc)
        # Get the CPU and memory usage for all Python processes
        cpu_percent = sum([proc.cpu_percent(interval=None) for proc in python_procs])
        memory_info = tuple(sum(x) for x in zip(*[proc.memory_info() for proc in python_procs]))
        memory_percent = memory_info[0] / psutil.virtual_memory().total * 100
        memory_active = memory_info[0]

        # Return a dictionary with the resources information
        return {
            'cpu_percent': cpu_percent / psutil.cpu_count(),
            'memory_percent': memory_percent,
            'memory_active': memory_active,
        }

    # Run an infinite loop to monitor the resources used
    while True:
        spinner.next()
        #   Get the resources information
        resources_info = get_resources_info()

        # Create a temporary DataFrame with the resources information
        temp_df = pd.DataFrame(resources_info, index=[0])

        # Optionally, remove completely empty or NA columns from the DataFrame
        temp_df = temp_df.dropna(axis=1, how='all')

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=FutureWarning)
            # Concatenate the temporary DataFrame with the original DataFrame
            df = pd.concat([df, temp_df], ignore_index=True)
        # Wait for a second before repeating the loop
        time.sleep(0.3)
        # If 60 seconds (1 minute) have passed, calculate the averages of the resources used
        if len(df) >= 60:
            hour_df = df.tail(60)
            hour_df.index = pd.to_datetime(hour_df.index)  
            hour_avg = hour_df.resample('1H').mean()
            logger2.info(f"""Resources usage:       
                                    -CPU Percent     {hour_avg['cpu_percent'][0]:.2f}%
                                    -Memory Percent  {hour_avg['memory_percent'][0]:.2f}%
                                    -Memory Used     {hour_avg['memory_active'][0] / (1024 ** 2):.2f} MB""")
            # Empty the DataFrame for the next cycle
            df = pd.DataFrame(columns=['cpu_percent', 'memory_percent', 'memory_active'])
            spinner.finish()
            print("\033[H\033[J", end="")
            print('GARU: -Resources log updated. :D')
            time.sleep(1.5)
            print('GARU: -Check your files at: \n\n /logs/resources.log')
            time.sleep(9)
            print("\033[H\033[J", end="")
            sys.exit()

# Logger initialization
# Setting the logger for the first log file
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
log_dir = os.path.join(parent_dir, 'logs')
formatter = logging.Formatter('%(asctime)s - "GARU" - %(message)s')
# Setting the logger for the second log file
logger2 = logging.getLogger('logger2')
logger2.setLevel(logging.INFO)
file_handler2 = logging.FileHandler(os.path.join(log_dir, 'resources.log'))
file_handler2.setFormatter(formatter)
logger2.addHandler(file_handler2)


get_application_resource_usage()



