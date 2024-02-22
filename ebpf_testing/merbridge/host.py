import socket

#socket으로 연결
def main():
    host_ip = '' # window ipconfig로 확인
    host_port = 10000


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as host_s:
        host_s.bind((host_ip, host_port))
        print("socket binding")
        
        host_s.listen()
        print("listening...")
        
        client_conn, addr = host_s.accept()
        with client_conn:
            print("accepted", addr)
            try:
                while True:
                    message = client_conn.recv(1024) #1024 byte
                    if not message:
                        print('disconnected (',addr[0], ':', addr[1],')')
                        break
                    print("receive message:", message.decode())
            except Exception :
                print(Exception)

if __name__ == "__main__":
    main()
