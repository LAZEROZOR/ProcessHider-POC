# ProcessHider-POC
This project demonstrates how to intercept the NtQuerySystemInformation function through an Import Address Table (IAT) hook in order to filter or hide specific processes from the list returned by Windows. It’s presented as a technical proof-of-concept to explore Windows internals and API hooking techniques.

This can be used to hide a process from Task Manager and other similar processes.

## Building

- Open the solution in Visual Studio.
- Build the project in **Release** mode for the correct architecture (x64 for 64-bit targets).

## Usage

This DLL is a **proof-of-concept**; to see its behaviour you have to load it into a target process yourself.

1. Choose a target process (e.g. Notepad) that matches the architecture of your build.
2. Use any standard DLL injector or your own loader **running with administrator privileges** to inject the compiled DLL into the target process.
3. After injection, calls to `NtQuerySystemInformation` from that process will return a filtered process list.
