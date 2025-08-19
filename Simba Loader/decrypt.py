import struct

def assemble_encrypted_buffer(scattered_data):
    encrypted_buffer = bytearray()
    offset = 0
    while offset < len(scattered_data):
        chunk_size = min(68, len(scattered_data) - offset)
        encrypted_buffer.extend(scattered_data[offset : offset + chunk_size])
        offset += 68 + 31
    return encrypted_buffer

def decrypt_shellcode(encrypted_buffer):
    decrypted_buffer = bytearray(encrypted_buffer)
    for i in range(0, len(decrypted_buffer), 4):
        if i + 4 > len(decrypted_buffer):
            break
        dword = struct.unpack('<I', decrypted_buffer[i:i+4])[0]
        dword = (dword + i) % 0x100000000
        dword = (dword ^ (i + 0xB0B6)) % 0x100000000
        decrypted_buffer[i:i+4] = struct.pack('<I', dword)
    return decrypted_buffer

def main():
    try:
        with open('shellcode.bin', 'rb') as f:
            scattered_data = f.read()
    except FileNotFoundError:
        print("Error: shellcode.bin not found.")
        return
    except Exception as e:
        print(f"Error reading shellcode.bin: {e}")
        return
    
    encrypted = assemble_encrypted_buffer(scattered_data)
    print(f"Assembled encrypted buffer size: {len(encrypted)} bytes")
    
    decrypted = decrypt_shellcode(encrypted)
    
    try:
        with open('decrypted_shellcode.bin', 'wb') as f:
            f.write(decrypted)
        print(f"Decrypted shellcode written to decrypted_shellcode.bin ({len(decrypted)} bytes).")
        print(f"Entry point at offset 0x86ED0 ({0x86ED0} bytes).")
    except Exception as e:
        print(f"Error writing decrypted_shellcode.bin: {e}")
    
    entry_offset = 0x86ED0
    if len(decrypted) >= entry_offset + 16:
        print(f"First 16 bytes at entry point (0x86ED0): {decrypted[entry_offset:entry_offset+16].hex()}")

if __name__ == "__main__":
    main()