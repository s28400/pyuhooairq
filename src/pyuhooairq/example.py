#!/usr/bin/env python3
from pyuhooairq import Uhoo

email = 'josh@hessindustria.com'
password = 'pass'

def main():
    # Create instance with credientials
    myuhoo = Uhoo (email, password)
    # Get list of devices associated with account
    device_list = myuhoo.get_all_devices()
    print(f'\nDevices: {device_list}')

    # Get latest data from particular device serial
    airq_data = myuhoo.get_current_airq_data(device_serial="34ff6d064242353636201857")
    print(f'\nData: {airq_data}')


if __name__ == "__main__":
    main()