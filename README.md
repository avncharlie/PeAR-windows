# PeAR

Add WinAFL instrumentation to x86 and x64 binaries.

## Run locally
1. Download `ddisasm` and `gtirb-pprinter` binaries here: https://download.grammatech.com/gtirb/files/windows-release/, and put them on your PATH.
2. Install python 3, max version python 3.10.
3. (Optional but recommended) Create a virtual environment to run PeAR in.
4. Install dependencies with `python -m pip install -r requirements.txt`.
3. Run `python -m pear -h` or `.\PeAR.bat -h` to get started.

## Run through Docker
Note: to generate Windows binaries you must run PeAR locally as it requires
access to MSVC build tools. Only instrumented assembly can be generated when
running in Docker.

1. Run `build.sh` to build the required Docker image.
2. Modify `PeAR.sh` as you require.
3. Run `PeAR.sh -h` to get started.

## Run tests

To start tests, run: `pytest .\pear\ -v -rA -s --vcvarsall-loc VCVARSALL_LOC --winafl32-afl-fuzz-loc AFL32_LOC --winafl64-afl-fuzz-loc AFL64_LOC`

Running tests requires:
1. The location of your `vcvarsall.bat`. This is used to run the MSVC
development environment, which is used to test PeAR with different
architectures. On my computer the location is:
`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat`.
2. The location of your 32-bit and 64-bit builds of WinAFL (the `afl-fuzz`
binary)

I recommend using the `-v -rA -s` arguments with pytest so you can see the tests
as they run live, including the WinAFL UI as the instrumented test binaries get
run. If you want to hide this UI to have usable log files, use `--hide-afl-ui`.

Windows Defender could prevent the tests from running correctly. To temporarily
disable it while running tests, open the Windows Security app -> Virus and
threat protection -> 'Manage settings' under Virus and threat protection
settings -> turn off 'Real-time protection'.