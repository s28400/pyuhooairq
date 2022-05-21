#!/usr/bin/env python3
from pyuhooairq import Uhoo
import getpass


def main():
    print('Welcome to the pyhuooairq example script!')
    email = input('Enter your uHoo account email: ')
    password = getpass.getpass('Password: ')

     # Create instance with credientials
    myuhoo = Uhoo (email, password)
    # Get list of devices associated with account
    device_list = myuhoo.get_all_devices()

    if not len(device_list):
        print('No devices found with this account')

    print('Found devices! Please select a device from the list:')
    while True:
        print('\n')
        pos = 1
        for device in device_list:
            print(f'{pos}. {device}')
            pos+=1

        device_number = int(input('Please select a device number: '))

        serial_number = device_list[device_number-1]['serialNumber']

        # Get latest data from particular device serial
        airq_data = myuhoo.get_current_airq_data(device_serial=serial_number)
        print(f'\nData: {airq_data}')


if __name__ == "__main__":
    main()
