if __name__ == '__main__':

    import os
    import time
    import hashlib

    import aes256
    
    print('Step 1:')
    while True:
        print('Press 1 for encryption  and 2 for decryption')
        way = input()
        if way not in ['1', '2']:
            print('Action denied')
            continue
        else:
            break
    print()

    print('Step 2:')
    while True:
        print('Enter full name of file')
        input_path = os.path.abspath(input())

        if os.path.isfile(input_path):
            break
        else:
            print('This is not a file')
            continue
    print()

    print('Step 3:')
    while True:
        print('Enter your password for encryption/decryption.')
        password = input()
        password = password.encode('utf8')
        key = hashlib.sha256(password).digest()
        break
    print('\r\nPlease, wait...')

    size = os.path.getsize(input_path)
    time_before = time.time()

    if way == '1':
        out_path, processing_time = aes256.encrypt_file(key, input_path)

    else:  # if way == '2'
        out_path = aes256.decrypt_file(key, input_path)


    elapsed_time = time.time() - time_before
print('Real speed :', (size*1e-6/elapsed_time), 'Mb/s\n')
print('Processing speed  :', (size*1e-6/processing_time), 'Mb/s')


