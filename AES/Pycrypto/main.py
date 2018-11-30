if __name__ == '__main__':

    import os
    import time
    from Crypto.Hash import MD5
    import aes256
    import numpy as np
    import h5py
    use_aesni = True

    print('Step 1:')
    while True:
        print('Press 1 for encryption  and 2 for decryption')
        way = input()
        if way not in ['1', '2']:
            print('Action denied')
            continue
        else:
            break

    print('Step 2:')
    file_name = 'video_example.mp4' if way == '1' else 'encrypted_video_example.mp4'
    input_path = os.path.abspath(file_name)

    print()

    print('Step 3:')
    password = 'kitty123'
    password = password.encode('utf8')
    key = MD5.new(password).digest()

    print('\r\nPlease, wait...')

    size = os.path.getsize(input_path)
    speed = []
    time_before = time.time()

    if way == '1':
        for _ in range(1):
            _, processing_time = aes256.encrypt_file(key, input_path, chunksize=size, use_aesni=use_aesni)
            speed.append(size*1e-6/processing_time)


    else:  # if way == '2'
        for _ in range(1):
            _, processing_time = aes256.decrypt_file(key, input_path, use_aesni=use_aesni)
            speed.append(size*1e-6/processing_time)


    elapsed_time = time.time() - time_before
print('Past time :', elapsed_time, 'sec\n')
print('Processing speed  :', (size*1e-6/processing_time), 'Mb/s')

"""
with h5py.File('CFB_mode/128_enc_ni.hdf5', 'w') as f:
    f.create_dataset("speed", data=np.array(speed))
"""