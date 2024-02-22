import socket

def main():
    #host ip 설정
    host_ip = ''
    host_port = 10000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as guest_s:
        guest_s.connect((host_ip, host_port))
        print("connected")
        
        while True:
            message = input('')
            guest_s.sendall(message.encode())
            print("send message : ", message)
            if message == 'quit':
                close_data = message
                break
        
        guest_s.close()

if __name__ == "__main__":
    main()
