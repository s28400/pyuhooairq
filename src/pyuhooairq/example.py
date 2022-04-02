#!/usr/bin/env python3
from pyuhooairq import Uhoo
import getpass


def main():
    print('Welcome to the pyhuooairq example script! This will demonstrate basic usage of the module.')
    email = input('Enter your uHoo account email: ')
    password = getpass.getpass('Password: ')

     # Create instance with credientials
    myuhoo = Uhoo (email, password)
    # Get list of devices associated with account
    device_list = myuhoo.get_all_devices()

    if not len(device_list):
        print('No devices found with this account')

    print('Found devices! Please copy a device serial number from the list:')
    for device in device_list:
        print(device)

    serial_number = input('Please input device serial number to sample data: ')

    # Get latest data from particular device serial
    airq_data = myuhoo.get_current_airq_data(device_serial=serial_number)
    print(f'\nData: {airq_data}')

    print('\nExample complete')


if __name__ == "__main__":
    main()