#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <wchar.h> // para vswprintf_s
#pragma comment (lib,"Ws2_32.lib")




class OBDC_Server {
    //********************************* STATE *************************************************
public: enum class STATE { NONE, CONNECTED, LISTENING, REQUESTING, ERROR_DETECTED };
public:STATE status = STATE::NONE;
public:BOOL bConnected = FALSE;
      //******************************* AVALIABLE IP's *****************************************

public:static const int  WSS_IP_STRING_SIZE = 256;
      static int const        MAX_SERVICENAME_LENGHT = 256;
public: static const int MAX_IP_ADRESSES = 10;
      //protected: wchar_t      ip_client_string[WSS_IP_STRING_SIZE];
      //public: wchar_t* getIP_string(wchar_t* buffer) {
      //    lstrcpyW(buffer, ip_client_string);
      //    return buffer;
      //}
protected: int          IP_Adresses_avaliables = 0;
protected: wchar_t IP_Avaliable[MAX_IP_ADRESSES][MAX_SERVICENAME_LENGHT];
         //****************************** SOCKET ****************************************************
protected: BOOL         WSAIniciated = FALSE;
public:static const int IPString_Lenght = 50;
public:      wchar_t IPString[IPString_Lenght] = { 0 };
public:      wchar_t PortString[IPString_Lenght] = { 0 };
protected: WSADATA wsaData = { 0 };
protected: const int ServerIndex = 0;
public: unsigned int ClientIndex = 1;
      //***************************** EVENTS *****************************************************
public:static const int TIME_OUT_FOR_EVENTS = 50;//50 milliseconds
public:int TimeOutForEvents = TIME_OUT_FOR_EVENTS;
protected: DWORD EventTotal = 1;
         //***************************** Various ******************************************************
protected: int iResult = 0;
public: int lastWSAError = 0;
protected: static const int ErrorBufferLen = 1000;
protected: wchar_t lpBuffer[ErrorBufferLen];
         //*******************************  CLIENTS ARRAYS********************************************
public: static const int DATA_BUFSIZE = 512;
protected: WSAEVENT EventArray[WSA_MAXIMUM_WAIT_EVENTS];
protected: SOCKET SocketArray[WSA_MAXIMUM_WAIT_EVENTS];
public: sockaddr AddressArray[WSA_MAXIMUM_WAIT_EVENTS];
public: CHAR BufferRecieved[DATA_BUFSIZE + 1][WSA_MAXIMUM_WAIT_EVENTS] = { 0 };
public:int ReceivedBytes[WSA_MAXIMUM_WAIT_EVENTS] = { 0 };
public: BOOL OverflowAlert[WSA_MAXIMUM_WAIT_EVENTS] = { FALSE };
public: STATE StateArray[WSA_MAXIMUM_WAIT_EVENTS] = { STATE::NONE };
      //******************************* SEND -RECIEVE data ****************************************
protected: static const int SendBufferSize = 512;
protected: char SendBuffer[SendBufferSize];
protected: int SendBytes = 0;

         /// <summary>
         /// printf() style debugging
         /// https://stackoverflow.com/questions/15240/
         /// </summary>
         /// <param name="lpszFormat">Debugging text</param>
         void XTrace0(LPCTSTR lpszText)
         {
             ::OutputDebugString(lpszText);
         }

         /// <summary>
         /// printf() style debugging
         /// https://stackoverflow.com/questions/15240/
         /// </summary>
         /// <param name="lpszFormat">-Debugging text</param>
         /// <param name="">.... parameters in _vstprintf_s() style</param>
         void XTrace(LPCTSTR lpszFormat, ...)
         {
             va_list args;
             va_start(args, lpszFormat);
             int nBuf;
             TCHAR szBuffer[512];
             nBuf = _vstprintf_s(szBuffer, 511, lpszFormat, args);
             ::OutputDebugString(szBuffer);
             va_end(args);
         }

         /// <summary>
         /// printf() style messaging
         /// https://stackoverflow.com/questions/15240/
         /// </summary>
         /// <param name="bufferReturned">pointer to a 512 WORDs array </param>
         /// <param name="lpszFormat">-Debugging text</param>
         /// <param name="">.... parameters in _vstprintf_s() style</param>
         wchar_t* MessageFormated(wchar_t* bufferReturned, LPCTSTR lpszFormat, ...)
         {
             va_list args;
             va_start(args, lpszFormat);
             int nBuf;
             nBuf = vswprintf_s(bufferReturned, 511, lpszFormat, args);
             //::OutputDebugString(szBuffer);
             va_end(args);
             return bufferReturned;
         }
         /// <summary>
         /// Empieza haciendo una llamada a WSAStartup() lo que inicializa el sistema WinsockDLL de windows.
         /// Inmediatamente llama a GetAddrInfoW() para hacer recibir un listado de las IP disponibles
         /// Las IP's son guardadas en el arreglo privado ipstringbuffer[]
         /// </summary>
         /// <returns>WSAError code
         /// this function does not alter the content of "status"</returns>
public: int GetIPList(ADDRINFOW** resultReturned) {

    ADDRINFOW* resultReturnedI = *resultReturned;
    ADDRINFOW 	hints;
    // Initialize Winsock**************************************************************************************
    lastWSAError = 0;
    wchar_t ComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };	//Obnener el nombre de la computadora
    wchar_t ServiceName[MAX_SERVICENAME_LENGHT] = { 0 };
    DWORD bufCharCount = 0;
    wchar_t comodin[256], comodin2[256];
    int iResult = 0;
    const wchar_t* s;
    //Obtener el IP de la computadora
    LPSOCKADDR sockaddr_ip;
    ADDRINFOW* ptr = NULL;
    ADDRINFOW* result = NULL;

    INT iRetval;
    wchar_t ipstringbuffer[46];
    DWORD ipbufferlength = 46;


    // Obtiene el nombre de la computadora, necesario para la 
    //funcion GetAddrInfoW()
    ComputerName[0] = 0;
    bufCharCount = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(ComputerName, &bufCharCount))
    {
        lastWSAError = GetLastError();
        XTrace(L"GetComputerName failed: %s", WindowsErrorToString(lastWSAError));
    }

    if (!WSAIniciated)
    {
        //Inicializa el sistema de sockets de windows
        lastWSAError = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (lastWSAError != 0) {
            XTrace(L"WSAStartup failed: %s", WindowsErrorToString(lastWSAError));
            status = STATE::ERROR_DETECTED;
            return lastWSAError;
        }
        WSAIniciated = true;
        XTrace(s = L"WSAStartup() success");
    }
    //Obtiene un listado de las direcciones IP**********************************************************************************

    ZeroMemory(&hints, sizeof(hints));
    ZeroMemory(&ServiceName, MAX_SERVICENAME_LENGHT);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;


    wcscpy_s(ComputerName, L"");
    lastWSAError = GetAddrInfoW(
        ComputerName,
        ServiceName,
        &hints,
        &result);
    if (lastWSAError != 0) {
        XTrace(L"getaddrinfo failed: %s", WindowsErrorToString(lastWSAError));
        WSACleanup();
        status = STATE::ERROR_DETECTED;
        return lastWSAError;
    }
    XTrace(L"getaddrinfo() success");
    *resultReturned = result;
    // Retrieve each address and print out the hex bytes
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        switch (ptr->ai_family) {
        case AF_UNSPEC:
            break;
        case AF_INET:
        {
            sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
            // The buffer length is changed by each call to WSAAddresstoString
            // So we need to set it for each iteration through the loop for safety
            ipbufferlength = 46;
            iRetval = WSAAddressToStringW(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
                ipstringbuffer, &ipbufferlength);
            if (iRetval)
                XTrace(L"WSAAddressToString failed with ", WSAGetLastError());
            else
            {
                SaveIpAddress(ipstringbuffer);
                break;
            }
        }
        }
    }
}
      /// <summary>
/// Guarda la IP en formato string en el arreglo interno IP[]. Permite un numero máximo de IP's= MAX_IP_ADRESSES
/// </summary>
/// <param name="newIpAddress">IP en formato String</param>
protected: void SaveIpAddress(wchar_t* newIpAddress)
{
    if (newIpAddress)
    {
        if (IP_Adresses_avaliables < MAX_IP_ADRESSES)
        {
            lstrcpyW(IP_Avaliable[IP_Adresses_avaliables], newIpAddress);

            IP_Adresses_avaliables++;
        }
        else
        {
            XTrace(L"Maximun number of allowed IP's reached.\n");
            XTrace(L"Discarting:\n", newIpAddress);
        }
    }
}
         /// <summary>
         /// Initialize SERVER.
         /// Initialize WSA subsystem.
         /// Initializes Server Socket and listens to requesting clients
         /// Initializes Server Events
         /// </summary>
         /// <param name="IPString">Server IP</param>
         /// <param name="port">Server Port</param>
         /// <returns>True if succeed. FALSE if fails, lastWSAError saves the WSAGelLastError() value
         /// this function does alter the content of "status" ERROR_DETECTED: if socket cannot be created
         /// status=LISTENING if has been created</returns>
public: BOOL CreateServerSocket(wchar_t* IPString, int port) {
    lastWSAError = 0;
    // socket() data --------------------
    int iFamily = AF_INET;
    int iType = SOCK_STREAM;
    int iProtocol = IPPROTO_TCP;
    //  bind() data ---------------------
    sockaddr_in service = { 0 };
    IN_ADDR in_addr = { 0 };
    //  Listen() data -------------------
    int    backlog = 0;
    // Initialize Winsock*****************************************************************

    lastWSAError = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (lastWSAError != 0) {
        XTrace(L"WSAStartup failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        status = STATE::ERROR_DETECTED;
        return FALSE;
    }

    WSAIniciated = TRUE;
    // Create socket****************************************************************
    closesocket(SocketArray[ServerIndex]);
    SocketArray[ServerIndex] = socket(iFamily, iType, iProtocol);
    if (SocketArray[ServerIndex] == INVALID_SOCKET)
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"socket failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        status = STATE::ERROR_DETECTED;
        return FALSE;
    }
    // Set non-blocking mode****************************************************************
    //-------------------------
    // Set the socket I/O mode: In this case FIONBIO
    // enables or disables the blocking mode for the 
    // socket based on the numerical value of iMode.
    // If iMode = 0, blocking is enabled; 
    // If iMode != 0, non-blocking mode is enabled.

    u_long iMode = 1;
    iResult = ioctlsocket(SocketArray[ServerIndex], FIONBIO, &iMode);
    if (iResult == SOCKET_ERROR)
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"ioctlsocket failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        status = STATE::ERROR_DETECTED;
        return FALSE;
    }
    // Bind the socket to a specific port of an IP adress***********************************
    if ((iResult = InetPton(AF_INET, IPString, &in_addr)) != 1) {
        //The InetPton function returns a value of 0 if the pAddrBuf parameter points to a string
        //that is not a valid IPv4 dotted - decimal string or a valid IPv6 address string.
        //Otherwise, a value of - 1 is returned, and a specific error code can be retrieved by 
        //calling the WSAGetLastError() for extended error information.
        if (iResult == 0) {
            //WSAEFAULT=The system detected an invalid pointer address.
            lastWSAError = WSAEFAULT;
            XTrace(L"InetPton failed: IPString is not a valid IP");
            closesocket(SocketArray[ServerIndex]);
            WSACleanup();
            status = STATE::ERROR_DETECTED;
            return FALSE;
        }
        lastWSAError = WSAGetLastError();
        XTrace(L"InetPton failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        closesocket(SocketArray[ServerIndex]);
        WSACleanup();
        status = STATE::ERROR_DETECTED;
        return FALSE;

    }
    service.sin_family = AF_INET;
    service.sin_addr = in_addr;
    service.sin_port = htons(port);
    SOCKADDR* prtSOCKADDR = (SOCKADDR*)&service;
    wchar_t IPString2[20];
    wchar_t PortString2[20];
    socketaddress_to_string(prtSOCKADDR, IPString2, PortString2);
    iResult = bind(SocketArray[ServerIndex], (SOCKADDR*)&service, sizeof(service));
    if (iResult == SOCKET_ERROR) {
        lastWSAError = WSAGetLastError();
        XTrace(L"bind failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        closesocket(SocketArray[ServerIndex]);
        WSACleanup();
        status = STATE::ERROR_DETECTED;
        return FALSE;
    }
    //The IP and port received are saved in variables of the WSA_non_blocking object
    wcscpy_s(this->IPString, this->IPString_Lenght, IPString);
    _itow_s(port, PortString, 10);
    //-------------------------
    // Associate event types FD_ACCEPT and FD_CLOSE*****************************************
    // with the listening socket and NewEvent
    // Create new event
    EventArray[0] = WSACreateEvent();
    iResult = WSAEventSelect(SocketArray[ServerIndex], EventArray[0], FD_ACCEPT | FD_CONNECT | FD_CLOSE | FD_READ | FD_WRITE);
    if (iResult == SOCKET_ERROR) {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAEventSelect failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        closesocket(SocketArray[ServerIndex]);
        WSACleanup();
        status = STATE::ERROR_DETECTED;
        return FALSE;
    }
    // Listen *********************************************************************
    iResult = listen(SocketArray[ServerIndex], 1);
    if (iResult == SOCKET_ERROR) {
        lastWSAError = WSAGetLastError();
        XTrace(L"listen failed: %d. %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        closesocket(SocketArray[ServerIndex]);
        WSACleanup();
        status = STATE::ERROR_DETECTED;
        return FALSE;
    }
    XTrace(L"listen succeed\n");
    status = STATE::LISTENING;
    StateArray[ServerIndex] = STATE::LISTENING;
    return TRUE;
}

      /// <summary>
      /// Check if WSA has triggered an event on the server or on a client.
      /// The function waits for TimeOutForEvents milliseconds and returns
      /// with a value of 0 if there are no events waiting.
      /// If it detects an event, the system launches the corresponding 
      /// internal function to accept new clients, close unnecessary sockets, 
      /// and load incoming messages into buffers.
      /// </summary>
      /// <returns>Returns zero if no events have been detected.
      /// Returns one, if any event has been processed.
      /// Returns SOCKET_ERROR if there has been an error. 
      /// In case of error, lastWSAError stores the value returned by WSAGetLastError
      /// this function does not alter the content of "status"
      /// 
      ///</returns>
public:int testForEvents() {
    lastWSAError = 0;
    WSANETWORKEVENTS NetworkEvents = { 0 };
    // Wait for one of the sockets to receive I/O notification and
    DWORD Event = WSAWaitForMultipleEvents(
        ClientIndex,             //The number of event object handles in the array pointed to by lphEvents. 
        EventArray,             //A pointer to an array of event object handles.              
        FALSE,                  // If FALSE, the function returns when any of the event objects is signaled.
        TimeOutForEvents,       //The time-out interval, in milliseconds.
        FALSE                   //If FALSE, the thread is not placed in an alertable wait state and I/O completion routines are not executed.
    );
    switch (Event)
    {
    case WSA_WAIT_FAILED:
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAWaitForMultipleEvents() failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        return SOCKET_ERROR;
    }
    case WSA_WAIT_IO_COMPLETION:
        XTrace(L"WSAWaitForMultipleEvents() WSA_WAIT_IO_COMPLETION\n");
        return 0;
    case WSA_WAIT_TIMEOUT:
        XTrace(L"WSAWaitForMultipleEvents() WSA_WAIT_TIMEOUT\n");
        return 0;
    default:
        break;
    }
    XTrace(L"WSAWaitForMultipleEvents() OK! Numero de Evento en Array:%u\n", Event - WSA_WAIT_EVENT_0);
    iResult = WSAEnumNetworkEvents(
        SocketArray[Event - WSA_WAIT_EVENT_0],          //A descriptor identifying the socket.
        EventArray[Event - WSA_WAIT_EVENT_0],           //An optional handle identifying an associated event object to be reset.
        &NetworkEvents);                                //A structure that is filled with a record of network events that occurred and any associated error codes.
    if (iResult == SOCKET_ERROR)
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAEnumNetworkEvents() failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));

        return SOCKET_ERROR;
    }
    if (NetworkEvents.lNetworkEvents & FD_ACCEPT) {
        XTrace(L"SocketArray[%u]FD_ACCEPT\n", Event - WSA_WAIT_EVENT_0);
        return FD_ACCEPT_response();
    }
    if (NetworkEvents.lNetworkEvents & FD_CLOSE) {
        XTrace(L"SocketArray[%u]FD_CLOSE\n", Event - WSA_WAIT_EVENT_0);
        FD_CLOSE_response(Event - WSA_WAIT_EVENT_0);
        return TRUE;
    }
    if (NetworkEvents.lNetworkEvents & FD_CONNECT) {
        XTrace(L"SocketArray[%u]FD_CONNECT\n", Event - WSA_WAIT_EVENT_0);
        return TRUE;
    }
    if (NetworkEvents.lNetworkEvents & FD_READ) {
        XTrace(L"SocketArray[%u]FD_READ\n", Event - WSA_WAIT_EVENT_0);
        FD_READ_response(Event - WSA_WAIT_EVENT_0);
        return TRUE;
    }
    if (NetworkEvents.lNetworkEvents & FD_WRITE) {
        XTrace(L"SocketArray[%u]FD_WRITE\n", Event - WSA_WAIT_EVENT_0);
        FD_WRITE_response(Event - WSA_WAIT_EVENT_0);
        return TRUE;
    }
    XTrace(L"SocketArray[%u]FD_XXXX WSAEnumNetworkEvents() ha devuelto:%u\n", Event - WSA_WAIT_EVENT_0, NetworkEvents.lNetworkEvents);
    return TRUE;
}
      /// <summary>
      /// FD_ACCEPT event response.
      /// Accept incoming client. Inicialize events, update status arrays and clear Buffers for send/recv data
      /// </summary>
      /// <returns>TRUE if succeed. FALSE if fails.
      /// In case of error, lastWSAError stores the value returned by WSAGetLastError().
      ///</returns>
protected: BOOL FD_ACCEPT_response() {

    lastWSAError = 0;
    //Create a new ClientSocket to accept the requested conection
    if (ClientIndex >= WSA_MAXIMUM_WAIT_EVENTS)
    {
        XTrace(L"FD_ACCEPT: Top Client conections researched %u:\n", ClientIndex);
        return FALSE;
    }
    int sizeAddress = sizeof(AddressArray[ClientIndex]);
    SocketArray[ClientIndex] = accept(SocketArray[ServerIndex], &AddressArray[ClientIndex], &sizeAddress);
    if (SocketArray[ClientIndex] == INVALID_SOCKET) {
        lastWSAError = WSAGetLastError();
        XTrace(L"accept() failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        return FALSE;
    }
    // Associate event types FD_CONNECT | FD_CLOSE | FD_READ | FD_WRITE*****************************************
    // with the listening socket and NewEvent
    // Create new event
    EventArray[ClientIndex] = WSACreateEvent();
    iResult = WSAEventSelect(SocketArray[ClientIndex], EventArray[ClientIndex], FD_CONNECT | FD_CLOSE | FD_READ | FD_WRITE);
    if (iResult == SOCKET_ERROR) {

        lastWSAError = WSAGetLastError();
        XTrace(L"WSAEventSelect failed in SocketArray[%u] with error %u: %s\n", ClientIndex, lastWSAError, WindowsErrorToString(lastWSAError));
        closesocket(SocketArray[ClientIndex]);
        return FALSE;
    }
    //Update Arrays to new client
    StateArray[ServerIndex] = STATE::CONNECTED;
    StateArray[ClientIndex] = STATE::CONNECTED;
    BufferRecieved[ClientIndex][0] = 0;
    ReceivedBytes[ClientIndex] = 0;
    OverflowAlert[ClientIndex] = FALSE;
    ClientIndex++;
    XTrace(L"accept succeed\n");
    return TRUE;
}
         /// <summary>
         /// FD_CLOSES event response.
         /// Closes the client socket. And update the internal Arrays to fill in the gap.
         /// </summary>
         /// <param name="SocketArrayIndex">Index of the closing socket in the internal SocketArray[]</param>
protected:void FD_CLOSE_response(int SocketArrayIndex) {

    closesocket(SocketArray[SocketArrayIndex]);
    WSACloseEvent(EventArray[SocketArrayIndex]);

    for (unsigned int index = SocketArrayIndex; index < (ClientIndex - 1); index++)
    {
        SocketArray[index] = SocketArray[index + 1];
        EventArray[index] = EventArray[index + 1];
        AddressArray[index] = AddressArray[index + 1];
        StateArray[index] = StateArray[index + 1];
        ReceivedBytes[index] = ReceivedBytes[index + 1];
        OverflowAlert[index] = OverflowAlert[index + 1];
        for (unsigned int byte = 0; byte < WSA_MAXIMUM_WAIT_EVENTS + 1; byte++) {
            BufferRecieved[index][byte] = BufferRecieved[index + 1][byte];
        }
    }
    ClientIndex--;
}
         /// <summary>
         /// FD_READ event response.
         /// Read the incoming data and put a zero at the end
         /// activates or deactivates the OverflowAlert if the incoming data is bigger or smaller than buffer
         /// </summary>
         /// <param name="SocketArrayIndex">Index of the receiving socket in the internal SocketArray[]</param>
protected:void FD_READ_response(int SocketArrayIndex) {
    ReceivedBytes[SocketArrayIndex] = recv(SocketArray[SocketArrayIndex], BufferRecieved[SocketArrayIndex], DATA_BUFSIZE, 0);
    if (ReceivedBytes[SocketArrayIndex] >= DATA_BUFSIZE)
    {
        OverflowAlert[SocketArrayIndex] = TRUE;
    }
    else {
        OverflowAlert[SocketArrayIndex] = FALSE;
    }
    //El tamaño del buffer es DATA_BUFSIZE+1 para poder colocar un cero al final
    BufferRecieved[SocketArrayIndex][ReceivedBytes[SocketArrayIndex]] = 0;
}
         /// <summary>
         /// Called when buffer space becomes available. Not implemented. Does nothing.
         /// </summary>
         /// <param name="SocketArrayIndex">ClientSocket Index in SocketArray[]</param>
protected:void FD_WRITE_response(int SocketArrayIndex) {
    /*
    https://docs.microsoft.com/es-es/windows/win32/api/winsock2/nf-winsock2-wsaeventselect?redirectedfrom=MSDN

    The FD_WRITE network event is handled slightly differently.
    An FD_WRITE network event is recorded when a socket is first
    connected with a call to the connect, ConnectEx, WSAConnect,
    WSAConnectByList, or WSAConnectByName function or when a socket
    is accepted with accept, AcceptEx, or WSAAccept function and then
    after a send fails with WSAEWOULDBLOCK and buffer space becomes available.
    Therefore, an application can assume that sends are possible starting
    from the first FD_WRITE network event settingand lasting until a send
    returns WSAEWOULDBLOCK.After such a failure the application will find
    out that sends are again possible when an FD_WRITE network event is
    recordedand the associated event object is set.
    */
}

         /// <summary>
         /// Send the content of "char" buffer to a client
         /// </summary>
         /// <param name="socketIndex">Index of the receiving socket in the internal SocketArray[]</param>
         /// <param name="text">text to send</param>
         /// <param name="textLen">size of text to send</param>
         /// <returns>TRUE if success.FALSE if fails. If socketIndex is out of bounds of "socketIndex"
         /// returns fails but lastWSAError is not updated
         /// In case of OTHER error, lastWSAError stores the value returned by WSAGetLastError().</returns>
public:BOOL SendText(unsigned int socketIndex, char* text, int textLen) {
    lastWSAError = 0;
    int bytesSend = 0;
    if ((socketIndex > 0) && (socketIndex < ClientIndex)) {
        bytesSend = send(SocketArray[socketIndex], text, textLen, 0);
        if (bytesSend == SOCKET_ERROR) {
            lastWSAError = WSAGetLastError();
            XTrace(L"Error al enviar texto. Codigo: %u = %s", lastWSAError, WindowsErrorToString(lastWSAError));
            return FALSE;
        }
        return TRUE;
    }
    else
    {
        XTrace(L"WSA_non_blocking::SendText() error: socketIndex out of bounds\n");
        return FALSE;
    }
}
      /// <summary>
      /// My personal version of inet_ntop()
      /// </summary>
      /// <param name="address">IP structure to retrieve a string</param>
      /// <param name="IPString">buffer where the ip will be stored</param>
      /// <param name="PortString">buffer where the port will be stored</param>
      /// <returns>Puntero a IPString</returns>
public: static wchar_t* socketaddress_to_string(sockaddr* address, wchar_t* IPString, wchar_t* PortString) {
    int source = 0, dest = 0;
    wchar_t byte_string[4] = { 0 };
    wchar_t word_string[6] = { 0 };
    for (int nByte = 2; nByte < 6; nByte++) {
        _itow_s((unsigned char)address->sa_data[nByte], byte_string, 10);
        source = 0;
        while (byte_string[source] != 0)
        {
            IPString[dest] = byte_string[source]; source++; dest++;
        }
        if (nByte < 5)IPString[dest++] = L'.';
        else IPString[dest] = 0;
    }

    WORD hByte = (unsigned char)(address->sa_data[0]);
    WORD lByte = (unsigned char)(address->sa_data[1]);
    WORD port = (hByte * 256) + lByte;
    _itow_s(port, word_string, 10);
    source = 0;
    while (word_string[source] != 0) {
        PortString[source] = word_string[source];
        source++;
    }
    PortString[source] = 0;
    return IPString;
}
      /// <summary>
      /// Translate Windows Error code to Human code
      /// </summary>
      /// <param name="ErrorCode">Windows Error code</param>
      /// <returns>pointer to this->lpBuffer</returns>
public: wchar_t* WindowsErrorToString(int ErrorCode)
{

    if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        ErrorCode,
        0,
        lpBuffer,
        ErrorBufferLen,
        NULL) == 0)
    {
        XTrace(L"Error with FormatMessage\n");
    }
    return lpBuffer;
}


};


class OBDC_Client {
    //*************** STATUS **********************************************************
public: enum class STATE { NONE, CONNECTED, LISTENING, REQUESTING, ERROR_DETECTED };
public:STATE            state = STATE::NONE;
public:BOOL             bConnected = FALSE;
      //*************** SOCKET *********************************************************
protected: BOOL         WSAIniciated = FALSE;
protected: SOCKET       ClientSocket = INVALID_SOCKET;
protected: WSADATA      wsaData = { 0 };
protected: sockaddr_in  ClientAdress = { 0 };
protected: int          ClientAdressLen;
public:static const int IPString_Lenght = 50;
public:      wchar_t    IPString[IPString_Lenght] = { 0 };
public:      wchar_t    PortString[IPString_Lenght] = { 0 };

public:  static int const WSS_IP_STRING_SIZE = 256;
      static int const        MAX_SERVICENAME_LENGHT = 256;
public: static const int MAX_IP_ADRESSES = 10;
protected: wchar_t      ip_client_string[WSS_IP_STRING_SIZE];
public: wchar_t* getIP_string(wchar_t* buffer) {
    lstrcpyW(buffer, ip_client_string);
    return buffer;
}
protected: int          IP_Adresses_avaliables = 0;
protected: wchar_t IP[MAX_IP_ADRESSES][MAX_SERVICENAME_LENGHT];
         //****************** EVENTS *****************************************************
public:  static int const  TIME_OUT_FOR_EVENTS = 50; //50 miliseconds
protected: DWORD        EventTotal = 1;
protected: WSAEVENT     EventArray[WSA_MAXIMUM_WAIT_EVENTS];
         //************************** SEND RECIEVE ********************************************

public:  static int const  DATA_BUFSIZE = 512;
public: CHAR            BufferRecieved[DATA_BUFSIZE + 1] = { 0 };
public:int              ReceivedBytes = { 0 };
public: BOOL            OverflowAlert = { FALSE };
      //***************************** VARIOS *****************************************
public:int              TimeOutForEvents = TIME_OUT_FOR_EVENTS;
public:int              lastWSAError = 0;
protected: int          iResult = 0;
protected: static const int lpBufferWindowsErrorLen = 1000;
protected: wchar_t      lpBufferWindowsError[lpBufferWindowsErrorLen];

         /// <summary>
         /// Muestra un mensaje en la ventana del depurador
         /// </summary>
         /// <param name="lpszText">Texto a mostrar</param>
         void XTrace0(LPCTSTR lpszText)
         {
             ::OutputDebugString(lpszText);
         }

         /// <summary>
         /// Muestra un mensaje en la ventana del depurador compatible con la sintaxis printf()
         /// </summary>
         /// <param name="lpszFormat">Texto a mostrar</param>
         /// <param name="">Datos a insertar en el texto</param>
         void XTrace(LPCTSTR lpszFormat, ...)
         {
             va_list args;
             va_start(args, lpszFormat);
             int nBuf;
             TCHAR szBuffer[512]; // get rid of this hard-coded buffer
             nBuf = _vstprintf_s(szBuffer, 511, lpszFormat, args);
             ::OutputDebugString(szBuffer);
             va_end(args);
         }

         /// <summary>
         /// Inicializa la maquinaria WinSock2 de windows.
         /// Inicializa el socket cliente.
         /// Inicializa el evento FD_CONNECT|FD_CLOSE|FD_READ|FD_WRITE.
         /// No altera el STATUS del objeto WSA_non_blocking_Client
         /// </summary>
         /// <returns>TRUE si el socket está inicializado y enlazado con el Evento.
         /// FALSE si algo ha fallado. lastWSAError guarda el ultimo error generado</returns>
public: int CreateClientSocket() {

    lastWSAError = 0;
    // socket() data *******************************************************************
    int iFamily = AF_INET;
    int iType = SOCK_STREAM;
    int iProtocol = IPPROTO_TCP;
    // Initialize Winsock*****************************************************************
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAStartup failed, returned= %d. lastWSAError=%u\n", iResult, lastWSAError);
        state = STATE::ERROR_DETECTED;
        return FALSE;
    }
    // Create socket****************************************************************
    ClientSocket = socket(iFamily, iType, iProtocol);
    if (ClientSocket == INVALID_SOCKET)
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"socket function failed with error = %d\n", lastWSAError);
        state = STATE::ERROR_DETECTED;
        return FALSE;
    }
    // Associate event types  FD_READ|FD_WRITE| FD_CONNECT |FD_CLOSE*****************************************
        // with the listening socket and NewEvent
        // Create new event
    EventArray[0] = WSACreateEvent();
    iResult = WSAEventSelect(ClientSocket, EventArray[0], FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE);
    if (iResult == SOCKET_ERROR) {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAEventSelect failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        closesocket(ClientSocket);
        WSACleanup();
        state = STATE::ERROR_DETECTED;
        return FALSE;
    }
    return TRUE;
}
      /// <summary>
      /// Initiates a connection to the SERVER on the specified IP and ports.
      /// If it fails to connect, but the connect command runs successfully,
      /// put STATUS in "REQUESTING" and WSA_non_blocking_Client goes on hold
      /// of the triggering of an event "FD_CONNECT". The method returns immediately,
      /// DOES NOT block the application, but the application must
      /// call WSAnb_Client.Attemp_connect () to try again and
      /// WSAnb_Client.testForEvents () regularly (with a WM_TIMER, for example)
      /// to react to the FD_CONNECT event that will occur when the Server accepts the
      /// connection requested.
      /// Attemp_connect () modifies STATUS- CONNECTED if it has connected to the first one or NONE
      /// if it has been rejected by time to not block the application
      /// </summary>
      /// <param name="IPString">IP v4 of the server to which you want to connect</param>
      /// <param name="port">Port of the IP to which you want to connect</param>
      /// <returns>TRUE if connected or rejected to not block. FALSE if something has failed.
      /// lastWSAError saves the last value of WSAGetLastError. between the possible values of lastWSAError,
      /// WSAEWOULDBLOCK indicates that the connection attempt to not block has been canceled
      /// This function alters the content of "state" variable. 
      /// state=CONNECTED. Connection has been made with a server.
      /// sate=LISTENING. The connection has not been made, probably because the server is not available.
      /// Try again in a little while.
      /// state=ERROR_DETECTED The requested IP or port is not in the valid format. O connect () has returned another error
      ///</returns>
public: BOOL Attemp_connect(wchar_t* IPString, int port) {
    lastWSAError = 0;
    if (bConnected)
    {
        closesocket(ClientSocket);
        if (!CreateClientSocket())return false;
    }
    IN_ADDR in_addr = { 0 };
    //Guarda el string IP u el Puerto recibidos
    //actualiza el estado de la clase
    wcscpy_s(this->IPString, this->IPString_Lenght, IPString);
    _itow_s(port, this->PortString, 10);
    if (InetPton(AF_INET, IPString, &in_addr) != 1) {
        //The InetPton function returns a value of 0 if the pAddrBuf parameter points to a string
        //that is not a valid IPv4 dotted - decimal string or a valid IPv6 address string.
        //Otherwise, a value of - 1 is returned, and a specific error code can be retrieved by 
        //calling the WSAGetLastError() for extended error information.
        if (iResult == 0) {
            //WSAEFAULT=The system detected an invalid pointer address.
            lastWSAError = WSAEFAULT;
            XTrace(L"InetPton failed: IPString is not a valid IP");
            state = STATE::ERROR_DETECTED;
            return FALSE;
        }
        lastWSAError = WSAGetLastError();
        XTrace(L"InetPton error %u\n", lastWSAError);
        state = STATE::ERROR_DETECTED;
        return FALSE;

    }
    ClientAdressLen = sizeof(ClientAdress);
    ClientAdress.sin_family = AF_INET;
    ClientAdress.sin_addr = in_addr;
    ClientAdress.sin_port = htons(port);
    iResult = connect(ClientSocket, (SOCKADDR*)&ClientAdress, ClientAdressLen);
    if (iResult == SOCKET_ERROR) {
        lastWSAError = WSAGetLastError();
        XTrace(L"connect failed with error %u : %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        switch (lastWSAError)
        {
        case WSAEWOULDBLOCK:
            bConnected = FALSE;
            state = STATE::REQUESTING;
            return TRUE;
        default:
            state = STATE::ERROR_DETECTED;
            return FALSE;
        }
    }
    bConnected = TRUE;
    state = STATE::CONNECTED;
    XTrace(L"Connected to server.\n");
    return TRUE;

}
      /// <summary>
      /// Evalua los Eventos registrados y reacciona apropiadamente.
      /// FD_CONNECT (conexion rechazada para no bloquear). coloca STATUS en REQUESTING
      /// FD_CONNECT (conexion aceptada por el servidor). coloca STATUS en CONNECTED y bConected=true,
      ///permitiendo la transmision de datos.
      /// FD_CLOSE Si la conexion se cierra. Destruye el socket cliente y crea uno nuevo para ponerlo
      /// nuevamente en modo "escucha". Actualiza el STATUS a NONE y bConnected a false;
      /// </summary>
      /// <returns>Devuelve cero si ha funconado, SOCKET_ERROR si ha fallado</returns>
public:int testForEvents() {

    lastWSAError = 0;
    WSANETWORKEVENTS NetworkEvents = { 0 };
    // Wait for one of the sockets to receive I/O notification and
    DWORD Event = WSAWaitForMultipleEvents(
        EventTotal,             //The number of event object handles in the array pointed to by lphEvents. 
        EventArray,             //A pointer to an array of event object handles.              
        FALSE,                  // If FALSE, the function returns when any of the event objects is signaled.
        TimeOutForEvents,       //The time-out interval, in milliseconds.
        FALSE                   //If FALSE, the thread is not placed in an alertable wait state and I/O completion routines are not executed.
    );
    switch (Event)
    {
    case WSA_WAIT_FAILED:
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAWaitForMultipleEvents() failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        return SOCKET_ERROR;
    }
    case WSA_WAIT_IO_COMPLETION:
        XTrace(L"WSAWaitForMultipleEvents() WSA_WAIT_IO_COMPLETION\n");
        return 0;
    case WSA_WAIT_TIMEOUT:
        XTrace(L"WSAWaitForMultipleEvents() WSA_WAIT_TIMEOUT\n");
        return 0;
    default:
        break;
    }
    XTrace(L"WSAWaitForMultipleEvents() is pretty damn OK!\n");
    iResult = WSAEnumNetworkEvents(
        ClientSocket,          //A descriptor identifying the socket.
        EventArray[Event - WSA_WAIT_EVENT_0],           //An optional handle identifying an associated event object to be reset.
        &NetworkEvents);                                //A structure that is filled with a record of network events that occurred and any associated error codes.
    if (iResult == SOCKET_ERROR)
    {
        lastWSAError = WSAGetLastError();
        XTrace(L"WSAEnumNetworkEvents() failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        return SOCKET_ERROR;
    }
    if (NetworkEvents.lNetworkEvents == 0) {
        XTrace(L"WSAEnumNetworkEvents() se ha disparado. Pero el evento no está definido.\n");
        return 0;
    }
    if (NetworkEvents.lNetworkEvents & FD_ACCEPT) {
        XTrace(L"FD_ACCEPT\n");
        return 0;
    }
    if (NetworkEvents.lNetworkEvents & FD_CLOSE) {
        XTrace(L"FD_CLOSE\n");
        closesocket(ClientSocket);
        WSACloseEvent(EventArray[0]);
        CreateClientSocket();
        bConnected = FALSE;
        state = STATE::NONE;
        return 0;
    }
    if (NetworkEvents.lNetworkEvents & FD_CONNECT) {
        if (NetworkEvents.iErrorCode[FD_CONNECT_BIT] != 0) {
            XTrace(L"FD_CONNECT conexion rechazada\n");
            bConnected = FALSE;
            state = STATE::NONE;
            return 0;
        }
        else
        {
            XTrace(L"FD_CONNECT\n");
            bConnected = TRUE;
            state = STATE::CONNECTED;
            return 0;
        }
    }
    if (NetworkEvents.lNetworkEvents & FD_READ) {
        if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0) {
            XTrace(L"FD_READ ha devuelto error %u:\n", NetworkEvents.iErrorCode[FD_READ_BIT]);
            return 0;
        }
        else {
            XTrace(L"FD_READ\n");
            FD_READ_response();
            return 0;
        }
    }
    if (NetworkEvents.lNetworkEvents & FD_WRITE) {
        if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0) {
            XTrace(L"FD_WRITE ha devuelto error %u:\n", NetworkEvents.iErrorCode[FD_WRITE_BIT]);
            return 0;
        }
        else {
            XTrace(L"FD_WRITE\n");
            return 0;
        }
    }
    return 0;
}

      /// <summary>
      /// FD_READ event response.
      /// Read the incoming data and put a zero at the end
      /// activates or deactivates the OverflowAlert if the incoming data is bigger or smaller than buffer
      /// </summary>
protected:int FD_READ_response() {
    ReceivedBytes = recv(ClientSocket, BufferRecieved, DATA_BUFSIZE, 0);
    if (ReceivedBytes == SOCKET_ERROR) {

        lastWSAError = WSAGetLastError();
        XTrace(L"recv() failed with error %u: %s\n", lastWSAError, WindowsErrorToString(lastWSAError));
        return SOCKET_ERROR;
    }
    if (ReceivedBytes >= DATA_BUFSIZE)
    {
        OverflowAlert = TRUE;
    }
    else {

        OverflowAlert = FALSE;
    }
    //El tamaño del buffer es DATA_BUFSIZE+1 para poder colocar un cero al final
    BufferRecieved[ReceivedBytes] = 0;
    return 0;
}

         /// <summary>
         /// Empieza haciendo una llamada a WSAStartup() lo que inicializa el sistema WinsockDLL de windows.
         /// Inmediatamente llama a GetAddrInfoW() para hacer recibir un listado de las IP disponibles
         /// Las IP's son guardadas en el arreglo privado ipstringbuffer[]
         /// </summary>
         /// <returns>WSAError code</returns>
public: int GetIPList(ADDRINFOW** resultReturned) {

    ADDRINFOW* resultReturnedI = *resultReturned;
    ADDRINFOW 	hints;
    // Initialize Winsock**************************************************************************************
    lastWSAError = 0;
    wchar_t ComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };	//Obnener el nombre de la computadora
    wchar_t ServiceName[MAX_SERVICENAME_LENGHT] = { 0 };
    DWORD bufCharCount = 0;
    wchar_t comodin[256], comodin2[256];
    int iResult = 0;
    const wchar_t* s;
    //Obtener el IP de la computadora
    LPSOCKADDR sockaddr_ip;
    ADDRINFOW* ptr = NULL;
    ADDRINFOW* result = NULL;

    INT iRetval;
    wchar_t ipstringbuffer[46];
    DWORD ipbufferlength = 46;


    // Obtiene el nombre de la computadora, necesario para la 
    //funcion GetAddrInfoW()
    ComputerName[0] = 0;
    bufCharCount = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(ComputerName, &bufCharCount))
    {
        lastWSAError = GetLastError();
        XTrace(L"GetComputerName failed: %s", WindowsErrorToString(lastWSAError));
    }

    if (!WSAIniciated)
    {
        //Inicializa el sistema de sockets de windows
        lastWSAError = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (lastWSAError != 0) {
            XTrace(L"WSAStartup failed: %s", WindowsErrorToString(lastWSAError));
            return lastWSAError;
        }
        WSAIniciated = true;
        XTrace(s = L"WSAStartup() success");
    }
    //Obtiene un listado de las direcciones IP**********************************************************************************

    ZeroMemory(&hints, sizeof(hints));
    ZeroMemory(&ServiceName, MAX_SERVICENAME_LENGHT);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;


    wcscpy_s(ComputerName, L"");
    lastWSAError = GetAddrInfoW(
        ComputerName,
        ServiceName,
        &hints,
        &result);
    if (lastWSAError != 0) {
        XTrace(L"getaddrinfo failed: %s", WindowsErrorToString(lastWSAError));
        WSACleanup();
        return lastWSAError;
    }
    XTrace(L"getaddrinfo() success");
    *resultReturned = result;
    // Retrieve each address and print out the hex bytes
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        switch (ptr->ai_family) {
        case AF_UNSPEC:
            break;
        case AF_INET:
        {
            sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;
            // The buffer length is changed by each call to WSAAddresstoString
            // So we need to set it for each iteration through the loop for safety
            ipbufferlength = 46;
            iRetval = WSAAddressToStringW(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL,
                ipstringbuffer, &ipbufferlength);
            if (iRetval)
                XTrace(L"WSAAddressToString failed with ", WSAGetLastError());
            else
            {
                SaveIpAddress(ipstringbuffer);
                break;
            }
        }
        }
    }
}/// <summary>
/// Guarda la IP en formato string en el arreglo interno IP[]. Permite un numero máximo de IP's= MAX_IP_ADRESSES
/// </summary>
/// <param name="newIpAddress">IP en formato String</param>
protected: void SaveIpAddress(wchar_t* newIpAddress)
{
    if (newIpAddress)
    {
        if (IP_Adresses_avaliables < MAX_IP_ADRESSES)
        {
            lstrcpyW(IP[IP_Adresses_avaliables], newIpAddress);

            IP_Adresses_avaliables++;
        }
        else
        {
            XTrace(L"Maximun number of allowed IP's reached.\n");
            XTrace(L"Discarting:\n", newIpAddress);
        }
    }
}
         /// <summary>
         /// Devuelve un puntero a una cadena con el Error de Windos traducido para ser leido por un humano
         /// </summary>
         /// <param name="ErrorCode">Codigo de error de windows</param>
         /// <returns>Cadena con el texto en humano</returns>
public: wchar_t* WindowsErrorToString(int ErrorCode)
{

    if (FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        ErrorCode,
        0,
        lpBufferWindowsError,
        lpBufferWindowsErrorLen,
        NULL) == 0)
    {
        XTrace(L"Error with FormatMessage\n");
    }
    return lpBufferWindowsError;
}

      /// <summary>
      /// Send a byte array to the connected Server 
      /// </summary>
      /// <param name="text">Array to send</param>
      /// <param name="len">number of bytes to send</param>
      /// <returns>True if succeed. FALSE if fails, lastWSAError saves the WSAGelLastError() value</returns>
public: BOOL SendText(char* text, size_t len) {
    lastWSAError = 0;
    int bytesSend = 0;
    if (bConnected) {
        bytesSend = send(ClientSocket, text, (int)len, 0);
        if (bytesSend == SOCKET_ERROR) {
            lastWSAError = WSAGetLastError();
            XTrace(L"Error sending Data. Code: %u = %s", lastWSAError, WindowsErrorToString(lastWSAError));
            return FALSE;
        }
    }
    return FALSE;
}
};