#include <winsock2.h>
#include <iostream>
#include <string>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

class TCPClient
{
public:
    TCPClient(const std::string& serverIP, uint16_t port);
    bool initWinSock();
    bool createSocket();
    bool connectToServer();
    bool sendData(const std::string& data);
    bool recvData(std::string& receivedData);
    void closeConnection();
    ~TCPClient();

private:
    SOCKET sclient;
    sockaddr_in serverAddr;
    std::string serverIP;
    uint16_t port;
};

TCPClient::TCPClient(const std::string& serverIP, uint16_t port)
    : sclient(INVALID_SOCKET), serverIP(serverIP), port(port)
{
    memset(&serverAddr, 0, sizeof(serverAddr));
}

bool TCPClient::initWinSock()
{
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA data;
    if (WSAStartup(sockVersion, &data) != 0)
    {
        std::cerr << "Winsock initialization failed." << std::endl;
        return false;
    }
    return true;
}

bool TCPClient::createSocket()
{
    sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sclient == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed!" << std::endl;
        return false;
    }
    return true;
}

bool TCPClient::connectToServer()
{
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid address!" << std::endl;
        return false;
    }

    if (connect(sclient, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connection failed!" << std::endl;
        return false;
    }

    return true;
}

bool TCPClient::sendData(const std::string& data)
{
    int sendResult = send(sclient, data.c_str(), static_cast<int>(data.length()), 0);
    if (sendResult == SOCKET_ERROR)
    {
        std::cerr << "Send failed!" << std::endl;
        return false;
    }
    return true;
}

bool TCPClient::recvData(std::string& receivedData)
{
    char recData[255];
    int ret = recv(sclient, recData, sizeof(recData) - 1, 0);
    if (ret > 0)
    {
        recData[ret] = '\0'; 
        receivedData = recData;
        return true;
    }
    else if (ret == 0)
    {
        std::cout << "Connection closed by server." << std::endl;
        return false;
    }
    else
    {
        std::cerr << "Receive failed!" << std::endl;
        return false;
    }
}

void TCPClient::closeConnection()
{
    if (sclient != INVALID_SOCKET)
    {
        closesocket(sclient);
        sclient = INVALID_SOCKET;
    }
}

TCPClient::~TCPClient()
{
    closeConnection();
    WSACleanup();
}

int main()
{
    TCPClient client("127.0.0.1", 8888);// 指定服务器额地址和端口

    if (!client.initWinSock()) 
        return 1;

    while (true) {
        if (!client.createSocket()) 
            return 1;

        if (!client.connectToServer())
            return 1;

        std::string data;
        std::cout << "Enter message to send: ";
        std::getline(std::cin, data); 

        if (!client.sendData(data))
            continue;

        std::string receivedData;
        if (client.recvData(receivedData))
        {
            std::cout << "Received from server: " << receivedData << std::endl;
        }

        client.closeConnection();// 每次循环中都会重新创建socket，一旦IO操作完成就需要关闭连接，保证每次连接的独立性
    }

    return 0;
}
